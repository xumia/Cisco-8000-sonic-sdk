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

#include "la_punt_inject_port_gibraltar.h"
#include "nplapi/npl_constants.h"
#include "system/la_device_impl.h"
#include "system/la_system_port_gibraltar.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_punt_inject_port_gibraltar::la_punt_inject_port_gibraltar(const la_device_impl_wptr& device) : la_punt_inject_port_pacgb(device)
{
}

la_punt_inject_port_gibraltar::~la_punt_inject_port_gibraltar()
{
}

la_status
la_punt_inject_port_gibraltar::set_slice_source_pif_entry(la_slice_id_t slice)
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
    payload.initial_layer_index = 0;

    // TODO - first_header_is_layer and first_header_type should be configured in all places that prepare value for
    // source_pif_value.
    payload.first_header_is_layer = 1;
    payload.first_header_type = NPL_PROTOCOL_TYPE_ETHERNET;

    payload.initial_rx_data.init_fields.init_data.initial_npp_attributes_index
        = 0; // Not used - it is beeing overide by m_system_port->set_source_pif_table
    payload.initial_rx_data.init_fields.init_data.initial_slice_id
        = 0; // Not used  - it is beeing overide by m_system_port->set_source_pif_table
    payload.initial_rx_data.init_fields.initial_mapping_type = NPL_L2_VLAN_MAPPING;
    payload.initial_rx_data.init_fields.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    payload.initial_rx_data.init_fields.initial_vlan_profile = 0;
    payload.initial_rx_data.init_fields.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    payload.initial_rx_data.init_fields.mapping_key.initial_lp_id.id = 0;
    payload.initial_rx_data.init_fields.mapping_key.mpls_label_placeholder = 0;

    if (m_system_port != nullptr) {
        auto system_port_gibraltar = m_system_port.weak_ptr_static_cast<la_system_port_gibraltar>();
        la_status status = system_port_gibraltar->set_source_pif_table(source_pif_value);
        return status;
    }

    return LA_STATUS_EUNKNOWN;
}

} // namespace silicon_one
