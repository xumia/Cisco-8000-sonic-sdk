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

#include "la_npu_host_port_plgr.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "system/la_device_impl.h"
#include "system/la_remote_port_impl.h"
#include "system/la_system_port_plgr.h"
#include "system/slice_id_manager_base.h"
#include "tm/la_ifg_scheduler_impl.h"
#include "tm/la_interface_scheduler_impl.h"
#include "tm/tm_utils.h"

#include <sstream>

namespace silicon_one
{

la_npu_host_port_plgr::la_npu_host_port_plgr(la_device_impl_wptr device) : la_npu_host_port_akpg(device)
{
}

la_npu_host_port_plgr::~la_npu_host_port_plgr()
{
}

la_status
la_npu_host_port_plgr::set_slice_source_pif_entry()
{
    la_status status = LA_STATUS_SUCCESS;

    // Update the system port with the NPP attributes index
    npl_ifg0_ssp_mapping_table_key_t k;
    npl_ifg0_ssp_mapping_table_value_t v;
    npl_ifg0_ssp_mapping_table_entry_t* e = nullptr;

    npl_ifg1_ssp_mapping_table_value_t ifg1_v;
    npl_ifg1_ssp_mapping_table_entry_t* ifg1_e = nullptr;
    npl_ifg1_ssp_mapping_table_key_t ifg1_k;

    k.rxpp_npu_input_ifg_rx_fd_source_pif = HOST_PIF_ID;
    ifg1_k.rxpp_npu_input_ifg_rx_fd_source_pif = HOST_PIF_ID;

    v.action = NPL_IFG0_SSP_MAPPING_TABLE_ACTION_INIT_RX_DATA;

    // FI and NP macro are special inject macros. No tag swapping for now.
    v.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_ETH | FI_MACRO_RTC_STAGE;

    // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
    v.payloads.init_rx_data.np_macro_id = (NPL_RX_INJECT_MACRO & 0x3F);
    // v.payloads.init_rx_data.tag_swap_cmd = NPL_NO_TAG_SWAP;

    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = 0; // Not used
    v.payloads.init_rx_data.initial_rx_data.init_fields.init_data.initial_slice_id = 0;             // Not used
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mapping_type = NPL_L2_VLAN_MAPPING;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    v.payloads.init_rx_data.initial_rx_data.init_fields.initial_vlan_profile = 0;
    // v.payloads.init_rx_Data.initial_rx_data.init_fields.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.initial_lp_id.id = 0;
    v.payloads.init_rx_data.initial_rx_data.init_fields.mapping_key.mpls_label_placeholder = 0;
    v.payloads.init_rx_data.first_header_is_layer = 1;
    v.payloads.init_rx_data.first_header_type = NPL_PROTOCOL_TYPE_ETHERNET;

    for (la_slice_id_t slice : m_device->get_used_slices()) {
        // Pkts from NPU host are injected on either IFG. Program entry for both IFG.
        for (uint64_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            v.payloads.init_rx_data.slice_source_system_port.value = (ifg << 7 | HOST_PIF_ID);
            for (int i = 0; i < NUM_PCH_SUB_PORT_PER_PIF; i++) {
                if (!get_physical_ifg(slice, ifg)) {
                    k.rx_pd_init_local_vars_sub_port_index = i;
                    status = m_device->m_tables.ifg0_ssp_mapping_table[slice]->set(k, v, e);
                    return_on_error(status);
                } else {
                    ifg1_v.unpack(v.pack()); // Ugly but effective
                    ifg1_k.rx_pd_init_local_vars_sub_port_index = i;
                    status = m_device->m_tables.ifg1_ssp_mapping_table[slice]->set(ifg1_k, ifg1_v, ifg1_e);
                    return_on_error(status);
                }
            }
        }
    }

    return status;
}

la_status
la_npu_host_port_plgr::erase_slice_source_pif_entry()
{
    la_status status = LA_STATUS_SUCCESS;
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        for (uint64_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            for (int i = 0; i < NUM_PCH_SUB_PORT_PER_PIF; i++) {
                if (!get_physical_ifg(slice, ifg)) {
                    npl_ifg0_ssp_mapping_table_key_t key;
                    key.rxpp_npu_input_ifg_rx_fd_source_pif = HOST_PIF_ID;
                    key.rx_pd_init_local_vars_sub_port_index = i;
                    status = m_device->m_tables.ifg0_ssp_mapping_table[slice]->erase(key);
                    return_on_error(status);
                } else {
                    npl_ifg1_ssp_mapping_table_key_t key;
                    key.rxpp_npu_input_ifg_rx_fd_source_pif = HOST_PIF_ID;
                    key.rx_pd_init_local_vars_sub_port_index = i;
                    status = m_device->m_tables.ifg1_ssp_mapping_table[slice]->erase(key);
                    return_on_error(status);
                }
            }
        }
    }

    return status;
}

} // namespace silicon_one
