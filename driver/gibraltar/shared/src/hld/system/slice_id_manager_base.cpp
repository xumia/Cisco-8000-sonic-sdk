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

#include "system/slice_id_manager_base.h"
#include "../device_context/la_slice_mapper_base.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "system/la_device_impl_base.h"
#include <algorithm>
#include <cstdlib>
#include <string>

namespace silicon_one
{

la_slice_id_vec_t
temp_helper_fill_the_slice_id()
{
    char def_val[5] = "6";
    char* NUM_SLICES_str = std::getenv("NUM_SLICES");
    if (NUM_SLICES_str == nullptr)
        NUM_SLICES_str = def_val;

    int NUM_SLICES = 6;
    try {
        NUM_SLICES = std::stoi(NUM_SLICES_str);
    } catch (...) {
        NUM_SLICES = 6;
    }
    switch (NUM_SLICES) {
    case 4:
        return {{0, 1, 2, 3}};
        break;
    case 3:
        return {{0, 1, 2}};
        break;
    case -4:
        return {{2, 3, 4, 5}};
        break;
    case -3:
        return {{3, 4, 5}};
        break;
    }
    return {{0, 1, 2, 3, 4, 5}};
}

slice_id_manager_base::slice_id_manager_base()
{
    m_FIRST_HW_FABRIC_SLICE = 4;
    m_first_possible_fabric_slice = 3;
    m_enabled_slices = temp_helper_fill_the_slice_id();
    // m_enabled_slices={{0, 1, 2, 3, 4, 5}};
    m_initialized = false;
}
slice_id_manager_base::~slice_id_manager_base()
{
}

void
slice_id_manager_base::initialize(const la_device_impl_base_wptr& dev)
{
    if (m_initialized)
        return;
    m_initialized = true;

    m_enabled_slice_pairs_logical.clear();
    m_enabled_slice_pairs.clear();
    m_enabled_slices_logical.clear();
    m_enabled_ifgs.clear();
    for (la_slice_id_t sid : m_enabled_slices) {
        m_enabled_slices_logical.push_back(sid);
        size_t pair_id = sid / 2;
        if (!contains(m_enabled_slice_pairs, pair_id)) {
            m_enabled_slice_pairs.push_back(pair_id);
            m_enabled_slice_pairs_logical.push_back(pair_id);
        }
        for (la_uint_t i = 0; i < NUM_IFGS_PER_SLICE; i++) {
            m_enabled_ifgs.push_back(la_slice_ifg({.slice = sid, .ifg = i}));
        }
    }

    m_is_gifg_enabled.clear();
    for (la_slice_id_t sid = 0; sid < num_slices_per_device(); sid++) {
        for (size_t i = 0; i < NUM_IFGS_PER_SLICE; i++) {
            m_is_gifg_enabled.push_back(is_slice_valid(sid) == LA_STATUS_SUCCESS);
        }
    }

    m_designated_fabric_slices = {};
    m_designated_nonfabric_slices = {};
    m_fabric_hw_slices = {};
    m_nonfabric_hw_slices = {};
    for (la_slice_id_t sid : m_enabled_slices) {
        if (sid >= first_possible_fabric_slice_in_lc()) {
            m_designated_fabric_slices.push_back(sid);
        } else {
            m_designated_nonfabric_slices.push_back(sid);
        }
        if (sid >= m_FIRST_HW_FABRIC_SLICE) { // 4
            m_fabric_hw_slices.push_back(sid);
        } else {
            m_nonfabric_hw_slices.push_back(sid);
        }
    }

    m_slice_mapper
        = std::make_shared<la_slice_mapper_base>(get_used_slices_internal(), num_slices_per_device(), NUM_IFGS_PER_SLICE);
}

la_slice_id_t
slice_id_manager_base::first_possible_fabric_slice_in_lc() const
{
    return m_first_possible_fabric_slice;
}
size_t
slice_id_manager_base::num_slices_per_device() const
{
    return ASIC_MAX_SLICES_PER_DEVICE_NUM;
}

size_t
slice_id_manager_base::num_slice_pairs_per_device() const
{
    return NUM_SLICE_PAIRS_PER_DEVICE;
}

size_t
slice_id_manager_base::maximal_num_ifg_per_slice() const
{
    return NUM_IFGS_PER_SLICE;
}

size_t
slice_id_manager_base::num_enabled_slices() const
{
    dassert_crit(m_initialized, "slice_id_manager_base::num_enabled_slices() been called befor initialization.");
    return m_enabled_slices.size();
}

const la_slice_id_vec_t&
slice_id_manager_base::get_used_slices_internal() const
{
    dassert_crit(m_initialized, "slice_id_manager_base::get_used_slices_internal() been called befor initialization.");
    return m_enabled_slices;
}

la_slice_id_vec_t
slice_id_manager_base::get_active_slices_in_pair(la_slice_pair_id_t pair) const
{
    la_slice_id_vec_t vect;
    for (size_t i = 0; i < 2; i++) {
        if (contains(m_enabled_slices, pair * 2 + i)) {
            vect.push_back(pair * 2 + i);
        }
    }
    return vect;
}

const la_slice_pair_id_vec_t&
slice_id_manager_base::get_used_slice_pairs_internal() const
{
    dassert_crit(m_initialized, "slice_id_manager_base::get_used_slice_pairs_internal() been called befor initialization.");
    return m_enabled_slice_pairs;
}

const la_slice_id_vec_t&
slice_id_manager_base::get_used_logical_slices() const
{
    dassert_crit(m_initialized, "slice_id_manager_base::get_used_logical_slices() been called befor initialization.");
    return m_enabled_slices_logical;
}

const la_slice_pair_id_vec_t&
slice_id_manager_base::get_used_logical_slice_pairs() const
{
    dassert_crit(m_initialized, "slice_id_manager_base::get_used_logical_slice_pairs() been called befor initialization.");
    return m_enabled_slice_pairs_logical;
}

const slice_ifg_vec_t&
slice_id_manager_base::get_used_ifgs() const
{
    dassert_crit(m_initialized, "slice_id_manager_base::get_used_ifgs() been called befor initialization.");
    return m_enabled_ifgs;
}

slice_ifg_vec_t
slice_id_manager_base::get_ifgs_by_mode(la_device_impl_base_wcptr device, la_slice_mode_e mode) const
{
    slice_ifg_vec_t enabled_ifgs;
    for (la_slice_ifg slice_ifg : get_used_ifgs()) {
        la_slice_mode_e slice_mode;
        la_status status = device->get_slice_mode(slice_ifg.slice, slice_mode);
        if (status != LA_STATUS_SUCCESS) {
            // log_err(HLD, "slice_id_manager_base::%s: get_slice_mode failed %s", __func__, la_status2str(status).c_str());
            return slice_ifg_vec_t();
        }

        if (slice_mode != mode) {
            continue;
        }
        enabled_ifgs.push_back(slice_ifg);
    }

    return enabled_ifgs;
}
ifg_index_vec_t
slice_id_manager_base::get_slice_used_ifgs(la_slice_id_t slice) const
{
    std::vector<size_t> vect;
    if (LA_STATUS_SUCCESS != is_slice_valid(slice)) {
        vect.clear();
        return vect;
    }

    for (size_t i = 0; i < NUM_IFGS_PER_SLICE; i++) {
        vect.push_back(i);
    }
    return vect;
}
ifg_index_vec_t
slice_id_manager_base::get_used_ifgs_gifg_id() const
{
    dassert_crit(m_initialized, "slice_id_manager_base::get_used_ifgs_gifg_id() been called befor initialization.");
    std::vector<size_t> vect;
    for (size_t i = 0; i < m_is_gifg_enabled.size(); i++) {
        if (m_is_gifg_enabled[i]) {
            vect.push_back(i);
        }
    }
    return vect;
}

size_t
slice_id_manager_base::slice_ifg_2_global_ifg(la_slice_id_t slice, la_ifg_id_t ifg) const
{
    return slice * NUM_IFGS_PER_SLICE + ifg;
}

size_t
slice_id_manager_base::slice_ifg_2_global_ifg(la_slice_ifg ifg) const
{
    return slice_ifg_2_global_ifg(ifg.slice, ifg.ifg);
}
la_slice_ifg
slice_id_manager_base::global_ifg_2_slice_ifg(size_t gifg) const
{
    la_slice_ifg ifg = {.slice = (la_slice_id_t)gifg / NUM_IFGS_PER_SLICE, .ifg = (la_ifg_id_t)gifg % NUM_IFGS_PER_SLICE};
    return ifg;
}

la_status
slice_id_manager_base::is_slice_valid(la_slice_id_t sid) const
{
    if (!m_initialized)
        return LA_STATUS_ENOTINITIALIZED;
    if (sid >= num_slices_per_device()) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (!contains(m_enabled_slices, sid)) {
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
slice_id_manager_base::is_slice_pair_valid(la_slice_pair_id_t sid) const
{
    if (!m_initialized)
        return LA_STATUS_ENOTINITIALIZED;
    if (sid >= num_slice_pairs_per_device()) {
        return LA_STATUS_EOUTOFRANGE;
    }
    if (!contains(m_enabled_slice_pairs, sid)) {
        return LA_STATUS_EINVAL;
    }
    return LA_STATUS_SUCCESS;
}

la_status
slice_id_manager_base::is_slice_ifg_valid(la_slice_id_t slice, size_t ifg_id) const
{
    if (!m_initialized)
        return LA_STATUS_ENOTINITIALIZED;
    la_status status = is_slice_valid(slice);
    return_on_error(status);
    if (ifg_id >= NUM_IFGS_PER_SLICE) {
        return LA_STATUS_EOUTOFRANGE;
    }
    return LA_STATUS_SUCCESS;
}

la_status
slice_id_manager_base::is_slice_ifg_valid(la_slice_ifg ifg) const
{
    return is_slice_ifg_valid(ifg.slice, ifg.ifg);
}

slice_ifg_vec_t
slice_id_manager_base::get_all_valid_ifgs(const slice_ifg_vec_t& ifg_vect) const
{
    slice_ifg_vec_t out_vect = {};
    for (la_slice_ifg ifg : ifg_vect) {
        if (is_slice_ifg_valid(ifg)) {
            out_vect.push_back(ifg);
        }
    }
    return out_vect;
}

const la_slice_id_vec_t&
slice_id_manager_base::get_slices_by_fabric_type(fabric_slices_type_e type) const
{
    switch (type) {
    case fabric_slices_type_e::LINECARD_FABRIC:
        return m_designated_fabric_slices;
    case fabric_slices_type_e::LINECARD_NON_FABRIC:
        return m_designated_nonfabric_slices;
    case fabric_slices_type_e::HW_FABRIC:
        return m_fabric_hw_slices;
    case fabric_slices_type_e::HW_NON_FABRIC:
        return m_nonfabric_hw_slices;
    }
    dassert_crit(false, "slice_id_manager_base::get_slices_by_fabric_type() called with illegall fabric type.");
    return m_designated_fabric_slices;
}

bool
slice_id_manager_base::is_fabric_type_slice(la_slice_id_t sid, fabric_slices_type_e type) const
{
    return contains(get_slices_by_fabric_type(type), sid);
}

la_slice_id_vec_t
slice_id_manager_base::get_all_possible_slices() const
{
    la_slice_id_vec_t slices;
    for (la_slice_id_t sid = 0; sid < num_slices_per_device(); sid++) {
        slices.push_back(sid);
    }
    return slices;
}

la_slice_pair_id_vec_t
slice_id_manager_base::get_all_possible_slice_pairs() const
{
    la_slice_pair_id_vec_t slice_pairs;
    for (la_slice_pair_id_t sid = 0; sid < num_slice_pairs_per_device(); sid++) {
        slice_pairs.push_back(sid);
    }
    return slice_pairs;
}

slice_ifg_vec_t
slice_id_manager_base::get_all_possible_ifgs() const
{
    slice_ifg_vec_t ifgs;
    for (la_slice_id_t sid = 0; sid < num_slices_per_device(); sid++) {
        for (la_uint_t i = 0; i < maximal_num_ifg_per_slice(); i++) {
            ifgs.push_back(la_slice_ifg({.slice = sid, .ifg = i}));
        }
    }
    return ifgs;
}

la_slice_id_t
slice_id_manager_base::get_an_active_slice_id(la_slice_id_t def_sid) const
{
    if (contains(m_enabled_slices, def_sid)) {
        return def_sid;
    }
    return m_enabled_slices[0];
}

la_status
slice_id_manager_base::map_serdices(la_slice_serdices& map_this) const
{
    map_this.is_logical = false;
    return LA_STATUS_SUCCESS;
}

la_status
slice_id_manager_base::map_back_serdices(la_slice_serdices& map_this) const
{
    map_this.is_logical = true;
    return LA_STATUS_SUCCESS;
}

// la_status
// slice_id_manager_base::read_mapping_file(std::string file_name)
// {
//     return LA_STATUS_SUCCESS;

//     m_slice_mappings.clear();
//     m_back_slice_mappings.clear();
//     // stub -- only for matilda 3.2B
//     for (size_t sid = 0; sid < NUM_SLICES_PER_DEVICE; sid++) {
//         slice_mapping empty_map(sid, sid);
//         m_slice_mappings.push_back(empty_map);
//         m_back_slice_mappings.push_back(empty_map);
//     }

//     for (la_slice_id_t sid : m_enabled_slices) {
//         // dassert_crit(sid >= 3);
//         slice_mapping& back_map = m_back_slice_mappings[sid];
//         back_map.slice._to = 5 - sid;
//         // back_map.slice._to = sid;
//         // back_map.slice._to = sid ^ 1;

//         slice_mapping& s_map = m_slice_mappings[back_map.slice._to];
//         s_map.slice._to = back_map.slice._from;

//         for (size_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
//             ifg_mapping ifg_map(ifg_id, ifg_id);
//             s_map.ifg_map.push_back(ifg_map);
//         }

//         for (size_t ifg_id = 0; ifg_id < NUM_IFGS_PER_SLICE; ifg_id++) {
//             // size_t ifg_to = ifg_id^1;
//             size_t ifg_to = ifg_id;
//             // if (sid == 5 || sid == 4) {
//             //     ifg_to = ifg_id ^ 1;
//             // }
//             ifg_mapping b_ifg_map(ifg_id, ifg_to);
//             ifg_mapping& ifg_map = s_map[ifg_to];
//             ifg_map.ifg._to = b_ifg_map.ifg._from;

//             for (size_t ind = 0; ind < 24; ind++) {
//                 single_idx_mapping ser_des = {._from = ind, ._to = ind};
//                 ifg_map.serdes_map.push_back(ser_des);
//             }

//             for (size_t ind = 0; ind < 24; ind++) {
//                 single_idx_mapping b_ser_des = {._from = ind, ._to = ind};
//                 b_ifg_map.serdes_map.push_back(b_ser_des);

//                 single_idx_mapping& ser_des = b_ifg_map[b_ser_des._to];
//                 ser_des._to = b_ser_des._from;
//                 ser_des._from = b_ser_des._to;
//             }
//             back_map.ifg_map.push_back(b_ifg_map);
//         }
//     }

//     return LA_STATUS_SUCCESS;
// }

la_slice_pair_id_t
slice_id_manager_base::map_slice_pair(la_slice_pair_id_t id) const
{
    return id;
}
la_slice_pair_id_t
slice_id_manager_base::map_back_slice_pair(la_slice_pair_id_t id) const
{
    return id;
}

la_slice_id_t
slice_id_manager_base::map_slice(la_slice_id_t id) const
{
    return id;
}

la_slice_id_t
slice_id_manager_base::map_back_slice(la_slice_id_t id) const
{
    return id;
}

la_status
slice_id_manager_base::map_slice_ifg(la_slice_ifg& ifg) const
{
    return LA_STATUS_SUCCESS;
}
la_status
slice_id_manager_base::map_back_slice_ifg(la_slice_ifg& ifg) const
{
    return LA_STATUS_SUCCESS;
}

const std::shared_ptr<la_slice_mapper_base>&
slice_id_manager_base::get_slice_mapper() const
{
    return m_slice_mapper;
}

la_status
slice_id_manager_base::map_pif(la_slice_pif& map_this) const
{
    return LA_STATUS_SUCCESS;
}

la_status
slice_id_manager_base::map_back_pif(la_slice_pif& map_this) const
{
    return LA_STATUS_SUCCESS;
}

la_slice_ifg
slice_id_manager_base::get_npu_host_port_ifg() const
{
    la_slice_ifg s_ifg = {.slice = 0, .ifg = 1};
    la_status stauts = map_slice_ifg(s_ifg);
    dassert_crit(stauts == LA_STATUS_SUCCESS);
    // if (s_ifg.slice == 5) {
    //     s_ifg.slice = 3;
    //     s_ifg.ifg = 1;
    // }
    return s_ifg;
}

} // namespace silicon_one
