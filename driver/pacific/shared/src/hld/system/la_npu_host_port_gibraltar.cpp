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

#include "la_npu_host_port_gibraltar.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "system/la_device_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/la_system_port_gibraltar.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/tm_utils.h"

#include "device_utils_base.h"

#include <sstream>

namespace silicon_one
{

la_npu_host_port_gibraltar::la_npu_host_port_gibraltar(const la_device_impl_wptr& device) : la_npu_host_port_base(device)
{
}

la_npu_host_port_gibraltar::~la_npu_host_port_gibraltar()
{
}

la_status
la_npu_host_port_gibraltar::initialize_remote(la_remote_device* remote_device,
                                              la_system_port_gid_t system_port_gid,
                                              la_voq_set* voq_set,
                                              const la_tc_profile* tc_profile)
{
    la_slice_ifg s_ifg = m_device->get_slice_id_manager()->get_npu_host_port_ifg();
    la_remote_port* remote_port;
    size_t host_pif_id = HOST_PIF_ID;
    if (remote_device) {
        // NPU host is always on the last serdes on ifg 1
        host_pif_id = device_utils::get_num_of_pif_per_ifg(remote_device->get_remote_device_revision());
    }
    auto status
        = m_device->create_remote_port(remote_device, s_ifg.slice, s_ifg.ifg, host_pif_id, host_pif_id + 1, m_speed, remote_port);
    return_on_error(status);
    m_remote_port = m_device->get_sptr<la_remote_port_impl>(remote_port);

    la_system_port* system_port;
    status = m_device->create_system_port(system_port_gid, remote_port, voq_set, tc_profile, system_port);
    return_on_error(status);
    m_system_port = m_device->get_sptr<la_system_port_base>(system_port);

    m_device->add_object_dependency(m_remote_port, this);

    return LA_STATUS_SUCCESS;
}

la_status
la_npu_host_port_gibraltar::set_slice_source_pif_entry()
{
    // Update the system port with the NPP attributes index
    npl_source_pif_hw_table_t::value_type v;
    npl_source_pif_hw_table_t::key_type k;
    npl_source_pif_hw_table_t::entry_pointer_type e = nullptr;

    k.rxpp_npu_input_ifg_rx_fd_source_pif = HOST_PIF_ID;

    v.action = NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA;

    // FI and NP macro are special inject macros. No tag swapping for now.
    v.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_ETH;
    // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
    v.payloads.init_rx_data.np_macro_id = (NPL_RX_INJECT_MACRO & 0x3F);
    v.payloads.init_rx_data.tag_swap_cmd = NPL_NO_TAG_SWAP;

    la_slice_ifg s_ifg = m_device->get_slice_id_manager()->get_npu_host_port_ifg();
    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = 0; // Not used
    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id = s_ifg.slice;   // Not used
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mapping_type = NPL_L2_VLAN_MAPPING;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_vlan_profile = 0;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.initial_lp_id.id = 0;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.mpls_label_placeholder = 0;
    v.payloads.init_rx_data.first_header_is_layer = 1;
    v.payloads.init_rx_data.first_header_type = NPL_PROTOCOL_TYPE_ETHERNET;
    la_status status = LA_STATUS_SUCCESS;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        // Pkts from NPU host are injected on either IFG. Program entry for both IFG.
        for (uint64_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            k.rxpp_npu_input_ifg = ifg;
            status = m_device->m_tables.source_pif_hw_table[slice]->set(k, v, e);
            return_on_error(status);
        }
    }

    return status;
}

la_status
la_npu_host_port_gibraltar::erase_slice_source_pif_entry()
{
    npl_source_pif_hw_table_t::key_type key;
    key.rxpp_npu_input_ifg_rx_fd_source_pif = HOST_PIF_ID;

    la_status status = LA_STATUS_SUCCESS;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        for (uint64_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            key.rxpp_npu_input_ifg = ifg;
            status = m_device->m_tables.source_pif_hw_table[slice]->erase(key);
        }
    }

    return status;
}

la_status
la_npu_host_port_gibraltar::initialize(la_object_id_t oid,
                                       la_remote_device* remote_device,
                                       la_system_port_gid_t system_port_gid,
                                       la_voq_set* voq_set,
                                       const la_tc_profile* tc_profile)
{
    m_oid = oid;

    la_status status = (remote_device == nullptr) ? initialize_local(system_port_gid, voq_set, tc_profile)
                                                  : initialize_remote(remote_device, system_port_gid, voq_set, tc_profile);
    return_on_error(status);

    m_device->add_object_dependency(m_system_port, this);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
