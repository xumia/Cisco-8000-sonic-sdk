// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_stack_port_pacific.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_pacific.h"
#include "system/la_system_port_pacific.h"

using namespace std;
namespace silicon_one
{

la_stack_port_pacific::la_stack_port_pacific(const la_device_impl_wptr& device) : la_stack_port_base(device)
{
}

la_stack_port_pacific::~la_stack_port_pacific()
{
}

npl_initial_pd_nw_rx_data_t
la_stack_port_pacific::populate_initial_pd_nw_rx_data() const
{
    npl_initial_pd_nw_rx_data_t init_data;
    init_data.initial_mapping_type = NPL_L2_VLAN_MAPPING;
    init_data.initial_mac_lp_type = NPL_LP_TYPE_LAYER_2;
    init_data.initial_vlan_profile = 0;
    init_data.initial_lp_type = NPL_L2_LP_TYPE_NPP;
    init_data.mapping_key.initial_lp_id.id = 0;
    init_data.mapping_key.mpls_label_placeholder = 0;
    init_data.initial_is_rcy_if = 0;
    init_data.init_data.initial_npp_attributes_index = 0;
    init_data.init_data.initial_slice_id = 0;
    return init_data;
}

la_status
la_stack_port_pacific::set_source_pif_entry()
{
    la_status status = LA_STATUS_SUCCESS;
    npl_source_pif_hw_table_value_t source_pif_value;
    source_pif_value.payloads.init_rx_data.initial_rx_data.init_fields = populate_initial_pd_nw_rx_data();

    source_pif_value.action = NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA;
    source_pif_value.payloads.init_rx_data.tag_swap_cmd = NPL_NO_TAG_SWAP;
    source_pif_value.payloads.init_rx_data.initial_layer_index = 0;

    source_pif_value.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_ETH;
    source_pif_value.payloads.init_rx_data.np_macro_id = (NPL_NETWORK_RX_SVL_MACRO & 0x3F);

    if (m_spa_port != nullptr) {
        const auto& spa_port_pacific = m_spa_port.weak_ptr_static_cast<la_spa_port_pacific>();
        status = spa_port_pacific->set_source_pif_table(source_pif_value);
    } else if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            const auto& system_port_pacific = m_system_port.weak_ptr_static_cast<la_system_port_pacific>();
            status = system_port_pacific->set_source_pif_table(source_pif_value);
        }
    }

    return status;
}

la_status
la_stack_port_pacific::set_peer_device_reachable_stack_port_destination()
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
