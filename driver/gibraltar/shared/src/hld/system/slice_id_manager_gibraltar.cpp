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

#include "system/slice_id_manager_gibraltar.h"
#include "api/system/la_device.h"
#include "api/types/la_common_types.h"
#include "common/defines.h"
#include "common/gen_utils.h"
#include "system/device_model_types.h"
#include "system/la_device_impl_base.h"

#include <algorithm>
#include <cstdlib>
#include <jansson.h>
#include <string>

namespace silicon_one
{

slice_id_manager_gibraltar::slice_id_manager_gibraltar()
{
    m_use_mapping = false;
}
slice_id_manager_gibraltar::~slice_id_manager_gibraltar()
{
}

void
slice_id_manager_gibraltar::initialize(const la_device_impl_base_wptr& dev)
{
    m_use_mapping = false;

    int property_value;
    la_status status = dev->get_int_property(la_device_property_e::MATILDA_MODEL_TYPE, property_value);
    if (status == LA_STATUS_SUCCESS) {
        switch (property_value) {
        case matilda_model_e::MATILDA_32A:
            m_enabled_slices = {{0, 1, 2}};
            break;
        case matilda_model_e::MATILDA_32B:
            m_use_mapping = true;
            m_enabled_slices = {{3, 4, 5}};
            break;
        case matilda_model_e::MATILDA_8T_A:
            m_enabled_slices = {{0, 1, 2, 3, 4}};
            break;
        case matilda_model_e::MATILDA_8T_B:
            m_enabled_slices = {{0, 1, 2, 3, 5}};
            break;
        default: // 0 for GB, 1 for Matilda 6.4
            m_enabled_slices = {{0, 1, 2, 3, 4, 5}};
            break;
        }
    }

    slice_id_manager_base::initialize(dev);
    std::string map_file_path = "manufacturing/matilda_32B_slices_mappings.json";
    if (m_use_mapping) {
        if (const char* env_p = std::getenv("MATILDA_MAP_F"))
            map_file_path = std::string(env_p);
    }
    status = m_slice_mapper->initialize(map_file_path, m_use_mapping);
    dassert_crit(status == LA_STATUS_SUCCESS, "failed to read slice mapping file");

    m_enabled_slices_logical.clear();
    m_enabled_slice_pairs_logical.clear();
    for (la_slice_id_t sid : m_enabled_slices) {
        m_enabled_slices_logical.push_back(map_back_slice(sid));
    }
    for (la_slice_id_t sid : m_enabled_slice_pairs) {
        m_enabled_slice_pairs_logical.push_back(map_back_slice_pair(sid));
    }
    // some testing for 3.2B
    //     m_designated_fabric_slices.clear();
    //     m_designated_nonfabric_slices.clear();
    //     for (la_slice_id_t sid : m_enabled_slices) {
    //         m_designated_nonfabric_slices.push_back(sid);
    //     }
}

la_status
slice_id_manager_gibraltar::map_serdices(la_slice_serdices& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = false;
        return LA_STATUS_SUCCESS;
    }
    return m_slice_mapper->map_serdices(map_this);
}

la_status
slice_id_manager_gibraltar::map_back_serdices(la_slice_serdices& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = true;
        return LA_STATUS_SUCCESS;
    }
    return m_slice_mapper->map_back_serdices(map_this);
}

la_slice_pair_id_t
slice_id_manager_gibraltar::map_slice_pair(la_slice_pair_id_t id) const
{
    if (!m_use_mapping)
        return id;
    return m_slice_mapper->map_slice_pair(id);
    // return id;
}
la_slice_pair_id_t
slice_id_manager_gibraltar::map_back_slice_pair(la_slice_pair_id_t id) const
{
    if (!m_use_mapping)
        return id;
    return m_slice_mapper->map_back_slice_pair(id);
    // return id;
}

la_slice_id_t
slice_id_manager_gibraltar::map_slice(la_slice_id_t id) const
{
    if (!m_use_mapping)
        return id;
    return m_slice_mapper->map_slice(id);
}

la_slice_id_t
slice_id_manager_gibraltar::map_back_slice(la_slice_id_t id) const
{
    if (!m_use_mapping)
        return id;
    return m_slice_mapper->map_back_slice(id);
}

la_status
slice_id_manager_gibraltar::map_slice_ifg(la_slice_ifg& ifg) const
{
    if (!m_use_mapping) {
        return LA_STATUS_SUCCESS;
    }
    return m_slice_mapper->map_slice_ifg(ifg);
}
la_status
slice_id_manager_gibraltar::map_back_slice_ifg(la_slice_ifg& ifg) const
{
    if (!m_use_mapping) {
        return LA_STATUS_SUCCESS;
    }
    return m_slice_mapper->map_back_slice_ifg(ifg);
}

la_status
slice_id_manager_gibraltar::map_pif(la_slice_pif& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = false;
        return LA_STATUS_SUCCESS;
    }
    return m_slice_mapper->map_pif(map_this);
}

la_status
slice_id_manager_gibraltar::map_back_pif(la_slice_pif& map_this) const
{
    if (!m_use_mapping) {
        map_this.is_logical = true;
        return LA_STATUS_SUCCESS;
    }
    return m_slice_mapper->map_back_pif(map_this);
}

} // namespace silicon_one
