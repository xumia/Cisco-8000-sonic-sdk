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

#include "la_punt_inject_port_pacific.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_pacific.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_punt_inject_port_pacific::la_punt_inject_port_pacific(const la_device_impl_wptr& device) : la_punt_inject_port_pacgb(device)
{
}

la_punt_inject_port_pacific::~la_punt_inject_port_pacific()
{
}

la_status
la_punt_inject_port_pacific::set_slice_source_pif_entry(la_slice_id_t slice)
{
    // Update the system port with the NPP attributes index
    npl_source_pif_hw_table_value_t source_pif_value;
    npl_source_pif_hw_table_init_rx_data_payload_t& payload(source_pif_value.payloads.init_rx_data);

    source_pif_value.action = NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA;

    // FI and NP macro are special inject macros. No tag swapping for now.
    payload.fi_macro_id = NPL_FI_MACRO_ID_ETH;
    // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
    payload.np_macro_id = (NPL_RX_INJECT_MACRO & 0x3F);
    payload.tag_swap_cmd = NPL_NO_TAG_SWAP;

    payload.initial_rx_data.init_fields.init_data.initial_npp_attributes_index = 0; // Not used
    payload.initial_rx_data.init_fields.init_data.initial_slice_id = 0;             // Not used
    payload.initial_rx_data.init_fields.initial_mapping_type = NPL_L2_VLAN_MAPPING;
    payload.initial_rx_data.init_fields.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    payload.initial_rx_data.init_fields.initial_vlan_profile = 0;
    payload.initial_rx_data.init_fields.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    payload.initial_rx_data.init_fields.mapping_key.initial_lp_id.id = 0;
    payload.initial_rx_data.init_fields.mapping_key.mpls_label_placeholder = 0;

    if (m_system_port != nullptr) {
        auto system_port_pacific = m_system_port.weak_ptr_static_cast<la_system_port_pacific>();
        la_status status = system_port_pacific->set_source_pif_table(source_pif_value);
        return status;
    }

    return LA_STATUS_EUNKNOWN;
}

} // namespace silicon_one
