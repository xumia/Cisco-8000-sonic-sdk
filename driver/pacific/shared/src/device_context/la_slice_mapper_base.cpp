// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
//
// This file and all technical concepts, proprietary knowledge, algorithms and
// intellectual property rights it contains (collectively the "Confidential Information"),
// are the sole propriety information of Cisco and shall remain at Cisco's ownership.
// You shall not disclose the Confidential Information to any third party and you
// shall use it solely in connection with operating and/or maintaining of Cisco's
// products and pursuant to the terms and conditions of the license agreement you
// entered into with Cisco.
//
// THE SOURCE CODE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED.
// IN NO EVENT SHALL CISCO BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN
// AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH
// THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
//
// END_LEGAL

#include "la_slice_mapper_base.h"
#include "api/types/la_common_types.h"
#include "common/defines.h"
#include "common/gen_utils.h"

#include <algorithm>
#include <cstdlib>
#include <jansson.h>
#include <string>

namespace silicon_one
{

la_slice_mapper_base::la_slice_mapper_base(const la_slice_id_vec_t& active_slices,
                                           size_t num_slices_per_device,
                                           size_t num_ifgs_per_slice)
{
    m_num_mappable_ifgs = num_ifgs_per_slice;
    m_num_mappable_slices = num_slices_per_device;
    m_num_mappable_pairs = m_num_mappable_slices / 2;
    if (m_num_mappable_pairs * 2 < m_num_mappable_slices) {
        m_num_mappable_pairs++;
    }
    m_use_mapping = false;
    m_slice_pair_map.clear();
    m_slice_pair_map_back.clear();
    m_slice_mappings.clear();
    m_back_slice_mappings.clear();

    m_enabled_slices.clear();
    m_enabled_slices_logical.clear();
    for (la_slice_id_t sid : active_slices) {
        m_enabled_slices.push_back(sid);
        m_enabled_slices_logical.push_back(sid);
    }
}
la_slice_mapper_base::~la_slice_mapper_base()
{
}

la_status
la_slice_mapper_base::initialize(std::string map_file_path, bool use_mapping)
{
    m_slice_pair_map.clear();
    m_slice_pair_map_back.clear();
    m_slice_mappings.clear();
    m_back_slice_mappings.clear();
    m_use_mapping = use_mapping;

    if (m_use_mapping) {
        la_status status = read_mapping_from_file(map_file_path);
        return_on_error(status);

        m_enabled_slices_logical.clear();
        for (la_slice_id_t sid : m_enabled_slices) {
            m_enabled_slices_logical.push_back(map_back_slice(sid));
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_slice_mapper_base::read_slice_pairs_mapping(json_t* j_root)
{
    // initialize empty
    m_slice_pair_map.clear();
    m_slice_pair_map_back.clear();
    for (size_t sid = 0; sid < m_num_mappable_pairs; sid++) {
        single_idx_mapping empty_map = {._from = sid, ._to = sid};
        m_slice_pair_map.push_back(empty_map);
        m_slice_pair_map_back.push_back(empty_map);
    }
    json_t* j_mapping = json_object_get(j_root, "slice_pairs_mapping");
    if (!j_mapping) {
        // log_debug(HLD, "%s: ERROR - some of the REG fields are missing", __func__, to_string(pos));
        return LA_STATUS_EINVAL;
    }
    size_t index;
    json_t* j_sp_mapping;
    json_array_foreach(j_mapping, index, j_sp_mapping)
    {
        json_t* j_sid_from = json_object_get(j_sp_mapping, "from");
        json_t* j_sid_to = json_object_get(j_sp_mapping, "to");

        if (!j_sid_to || !j_sid_from) {
            // log_debug(HLD, "%s: ERROR - some of the REG fields are missing", __func__, to_string(pos));
            return LA_STATUS_EINVAL;
        }

        int from_sid_int = json_integer_value(j_sid_from);
        int to_sid_int = json_integer_value(j_sid_to);
        if ((from_sid_int < 0) || (from_sid_int > (int)m_num_mappable_pairs)) {
            return LA_STATUS_EOUTOFRANGE;
        }
        if ((to_sid_int < 0) || (to_sid_int > (int)m_num_mappable_pairs)) {
            return LA_STATUS_EOUTOFRANGE;
        }

        la_slice_id_t sid_from = static_cast<la_slice_id_t>(from_sid_int);
        la_slice_id_t sid_to = static_cast<la_slice_id_t>(to_sid_int);

        single_idx_mapping& s_map = m_slice_pair_map[sid_from];
        s_map._to = sid_to;
        single_idx_mapping& back_s_map = m_slice_pair_map_back[sid_to];
        back_s_map._to = sid_from;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_slice_mapper_base::read_ifg_mapping(json_t* j_root, slice_mapping& back_s_map, slice_mapping& s_map)
{
    json_t* j_ifg_from = json_object_get(j_root, "from_ifg");
    json_t* j_ifg_to = json_object_get(j_root, "to_ifg");

    if (!j_ifg_to || !j_ifg_from) {
        // log_debug(HLD, "%s: ERROR - some of the REG fields are missing", __func__, to_string(pos));
        return LA_STATUS_EINVAL;
    }

    int from_ifg_int = json_integer_value(j_ifg_from);
    int to_ifg_int = json_integer_value(j_ifg_to);
    if ((from_ifg_int < 0) || (from_ifg_int > (int)m_num_mappable_ifgs)) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if ((to_ifg_int < 0) || (to_ifg_int > (int)m_num_mappable_ifgs)) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_slice_id_t ifg_from = static_cast<la_slice_id_t>(from_ifg_int);
    la_slice_id_t ifg_to = static_cast<la_slice_id_t>(to_ifg_int);

    ifg_mapping& ifg_map = s_map[ifg_from];
    ifg_map.ifg._to = ifg_to;
    ifg_mapping& b_ifg_map = back_s_map[ifg_to];
    b_ifg_map.ifg._to = ifg_from;

    // initialize empty serdices mappings
    for (size_t ind = 0; ind < 24; ind++) {
        single_idx_mapping ser_des = {._from = ind, ._to = ind};
        ifg_map.serdes_map.push_back(ser_des);
        b_ifg_map.serdes_map.push_back(ser_des);
    }

    json_t* serdices_mapping = json_object_get(j_root, "serdices");
    if (!serdices_mapping) {
        // log_debug(HLD, "%s: ERROR - some of the REG fields are missing", __func__, to_string(pos));
        return LA_STATUS_EINVAL;
    }

    if (json_array_size(serdices_mapping) > 24) {
        // log_err(   )
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t serdes_from;
    json_t* j_ser_to;
    json_array_foreach(serdices_mapping, serdes_from, j_ser_to)
    {
        int serdes_to_int = json_integer_value(j_ser_to);
        if ((serdes_to_int < 0) || (serdes_to_int > 24)) {
            return LA_STATUS_EOUTOFRANGE;
        }
        size_t serdes_to = static_cast<size_t>(serdes_to_int);

        single_idx_mapping& ser_des = ifg_map[serdes_from];
        ser_des._to = serdes_to;

        single_idx_mapping& b_ser_des = b_ifg_map[serdes_to];
        b_ser_des._to = serdes_from;
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_slice_mapper_base::read_slice_mapping(json_t* j_root)
{
    json_t* j_sid_from = json_object_get(j_root, "from_slice");
    json_t* j_sid_to = json_object_get(j_root, "to_slice");

    if (!j_sid_to || !j_sid_from) {
        // log_debug(HLD, "%s: ERROR - some of the REG fields are missing", __func__, to_string(pos));
        return LA_STATUS_EINVAL;
    }

    int from_sid_int = json_integer_value(j_sid_from);
    int to_sid_int = json_integer_value(j_sid_to);
    if ((from_sid_int < 0) || (from_sid_int > (int)m_num_mappable_slices)) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if ((to_sid_int < 0) || (to_sid_int > (int)m_num_mappable_slices)) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_slice_id_t sid_from = static_cast<la_slice_id_t>(from_sid_int);
    la_slice_id_t sid_to = static_cast<la_slice_id_t>(to_sid_int);

    slice_mapping& s_map = m_slice_mappings[sid_from];
    s_map.slice._to = sid_to;
    slice_mapping& back_s_map = m_back_slice_mappings[sid_to];
    back_s_map.slice._to = sid_from;

    // map also the opposing slices: no need to that for ifgs and serdices
    if (m_slice_mappings[sid_to].slice._to == sid_to) {
        m_slice_mappings[sid_to].slice._to = sid_from;
        m_back_slice_mappings[sid_from].slice._to = sid_to;
    }

    json_t* j_ifgs_mapping = json_object_get(j_root, "IFGs");
    if (!j_ifgs_mapping) {
        // log_debug(HLD, "%s: ERROR - some of the REG fields are missing", __func__, to_string(pos));
        return LA_STATUS_EINVAL;
    }

    // initialize empty ifgs mappings
    for (size_t ifg_id = 0; ifg_id < m_num_mappable_ifgs; ifg_id++) {
        ifg_mapping ifg_map(ifg_id, ifg_id);
        s_map.ifg_map.push_back(ifg_map);
        back_s_map.ifg_map.push_back(ifg_map);
    }
    size_t index;
    json_t* j_ifg_mapping;
    json_array_foreach(j_ifgs_mapping, index, j_ifg_mapping)
    {
        la_status status = read_ifg_mapping(j_ifg_mapping, back_s_map, s_map);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_slice_mapper_base::read_mapping_from_file(std::string file_name)
{
    if (!m_use_mapping)
        return LA_STATUS_SUCCESS;

    json_error_t jerr;
    json_t* j_root = json_load_file(file_name.c_str(), 0, &jerr);
    if (!j_root) {
        // log_err(INTERRUPT, "Failed loading interrupt tree metadata, path %s, json_error %s", json_file, jerr.text);
        return LA_STATUS_EINVAL;
    }

    // json_decref(j_root);

    json_t* j_mapping = json_object_get(j_root, "slices_mapping");
    if (!j_mapping) {
        // log_debug(HLD, "%s: ERROR - some of the REG fields are missing", __func__, to_string(pos));
        return LA_STATUS_EINVAL;
    }

    m_slice_mappings.clear();
    m_back_slice_mappings.clear();
    // initialize empty slices mappings
    for (size_t sid = 0; sid < m_num_mappable_slices; sid++) {
        slice_mapping empty_map(sid, sid);
        m_slice_mappings.push_back(empty_map);
        m_back_slice_mappings.push_back(empty_map);
    }

    size_t index;
    json_t* j_s_mapping;
    json_array_foreach(j_mapping, index, j_s_mapping)
    {
        la_status status = read_slice_mapping(j_s_mapping);
        return_on_error(status);
    }

    // slice_pairs
    la_status status = read_slice_pairs_mapping(j_root);

    return status;
}

la_slice_serdices
la_slice_mapper_base::map_pif_to_serdes(const la_slice_pif& pif_dat) const
{
    la_slice_serdices map_this_in;
    map_this_in.is_logical = pif_dat.is_logical;
    map_this_in.slice = pif_dat.slice;
    map_this_in.ifg = pif_dat.ifg;
    map_this_in.first_serdes = pif_dat.first_pif;
    map_this_in.last_serdes = pif_dat.last_pif;
    return map_this_in;
}
la_slice_pif
la_slice_mapper_base::map_serdes_to_pif(const la_slice_serdices& serdes_dat) const
{
    la_slice_pif map_this_in;
    map_this_in.is_logical = serdes_dat.is_logical;
    map_this_in.slice = serdes_dat.slice;
    map_this_in.ifg = serdes_dat.ifg;
    map_this_in.first_pif = serdes_dat.first_serdes;
    map_this_in.last_pif = serdes_dat.last_serdes;
    return map_this_in;
}
la_status
la_slice_mapper_base::map_pif(la_slice_pif& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = false;
        return LA_STATUS_SUCCESS;
    }
    // this will only work for GB/pac were the mapping of serdices to pif is the identity function.
    la_slice_serdices map_this_in = map_pif_to_serdes(map_this);
    la_status status = map_serdices(map_this_in);
    map_this = map_serdes_to_pif(map_this_in);
    return status;
};

la_status
la_slice_mapper_base::map_back_pif(la_slice_pif& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = false;
        return LA_STATUS_SUCCESS;
    }
    // this will only work for GB/pac were the mapping of serdices to pif is the identity function.
    la_slice_serdices map_this_in = map_pif_to_serdes(map_this);
    la_status status = map_back_serdices(map_this_in);
    map_this = map_serdes_to_pif(map_this_in);
    return status;
};

la_status
la_slice_mapper_base::map_serdices(la_slice_serdices& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = false;
        return LA_STATUS_SUCCESS;
    }

    if (!map_this.is_logical) {
        return LA_STATUS_SUCCESS;
    }
    if (map_this.slice >= m_slice_mappings.size()) {
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }

    auto& slice_map = m_slice_mappings[map_this.slice];
    la_status status = slice_map.map_slice_serdices(map_this);
    return_on_error(status);

    map_this.is_logical = false;
    return LA_STATUS_SUCCESS;
}

la_status
la_slice_mapper_base::map_back_serdices(la_slice_serdices& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = true;
        return LA_STATUS_SUCCESS;
    }

    if (map_this.is_logical) {
        return LA_STATUS_SUCCESS;
    }
    if (map_this.slice >= m_back_slice_mappings.size()) {
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }

    auto& slice_map = m_back_slice_mappings[map_this.slice];
    la_status status = slice_map.map_slice_serdices(map_this);
    return_on_error(status);

    map_this.is_logical = true;
    return LA_STATUS_SUCCESS;
}

la_slice_pair_id_t
la_slice_mapper_base::map_slice_pair(la_slice_pair_id_t id) const
{
    if (!m_use_mapping)
        return id;
    if (id >= m_num_mappable_pairs) {
        // let somone else handle this problem
        return id;
    }
    return m_slice_pair_map[id]._to;
    // return id;
}
la_slice_pair_id_t
la_slice_mapper_base::map_back_slice_pair(la_slice_pair_id_t id) const
{
    if (!m_use_mapping)
        return id;
    if (id >= m_num_mappable_pairs) {
        // let somone else handle this problem
        return id;
    }
    return m_slice_pair_map_back[id]._to;
    // return id;
}

la_slice_id_t
la_slice_mapper_base::map_slice(la_slice_id_t id) const
{
    if (!m_use_mapping)
        return id;
    if (id >= m_num_mappable_slices) {
        // let somone else handle this problem
        return id;
    }
    la_slice_id_t res = m_slice_mappings[id].slice._to;
    return res;
}

la_slice_id_t
la_slice_mapper_base::map_back_slice(la_slice_id_t id) const
{
    if (!m_use_mapping)
        return id;
    if (id >= m_num_mappable_slices) {
        // let somone else handle this problem
        return id;
    }
    la_slice_id_t res = m_back_slice_mappings[id].slice._to;
    return res;
}

la_status
la_slice_mapper_base::map_slice_ifg(la_slice_ifg& ifg) const
{
    if (!m_use_mapping) {
        return LA_STATUS_SUCCESS;
    }
    if (ifg.slice >= m_slice_mappings.size()) {
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }
    auto& slice_map = m_slice_mappings[ifg.slice];
    la_status stat = slice_map.map_ifg_from_slice(ifg);
    return stat;
}
la_status
la_slice_mapper_base::map_back_slice_ifg(la_slice_ifg& ifg) const
{
    if (!m_use_mapping) {
        return LA_STATUS_SUCCESS;
    }
    if (ifg.slice >= m_back_slice_mappings.size()) {
        // let somone else handle this problem
        return LA_STATUS_SUCCESS;
    }

    auto& slice_map = m_back_slice_mappings[ifg.slice];
    la_status stat = slice_map.map_ifg_from_slice(ifg);
    return stat;
}

const la_slice_id_vec_t&
la_slice_mapper_base::get_used_slices_internal() const
{
    return m_enabled_slices;
}

const la_slice_id_vec_t&
la_slice_mapper_base::get_used_slices() const
{
    return m_enabled_slices_logical;
}

bool
la_slice_mapper_base::is_mapping_active() const
{
    return m_use_mapping;
}

size_t
la_slice_mapper_base::max_num_slices_per_device() const
{
    return m_num_mappable_slices;
}

} // namespace silicon_one
