// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "la_ethernet_port_gibraltar.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_l3_ac_port_impl.h"
#include "npu/la_switch_impl.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_gibraltar.h"
#include "system/la_system_port_gibraltar.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

#include <sstream>

using namespace std;
namespace silicon_one
{

la_ethernet_port_gibraltar::la_ethernet_port_gibraltar(const la_device_impl_wptr& device) : la_ethernet_port_base(device)
{
}

la_ethernet_port_gibraltar::~la_ethernet_port_gibraltar()
{
}

la_status
la_ethernet_port_gibraltar::set_service_mapping_type(service_mapping_type_e type)
{
    if (m_service_mapping_type == type) {
        return LA_STATUS_SUCCESS;
    }

    if ((type != service_mapping_type_e::LARGE) && (type != service_mapping_type_e::SMALL)) {
        return LA_STATUS_EINVAL;
    }

    // get all ac ports created on this ethernet port
    std::vector<la_object*> deps = m_device->get_dependent_objects(this);

    // iterate through all ac port create on the ethernet port
    for (auto objp : deps) {
        if (objp->type() != object_type_e::L3_AC_PORT) {
            log_err(HLD, "the ethernet port has %s attached to it.", objp->to_string().c_str());
            return LA_STATUS_EINVAL;
        }
    }

    service_mapping_type_e old_type = m_service_mapping_type;
    m_service_mapping_type = type;

    attribute_management_details amd;
    amd.op = attribute_management_op::SERVICE_MAPPING_TYPE_CHANGED;
    la_amd_undo_callback_funct_t undo = [this, old_type](attribute_management_details amd) {
        m_service_mapping_type = old_type;
        return amd;
    };
    la_status status = m_device->notify_attribute_changed(this, amd, undo);
    return_on_error(status);

    status = update_npp_attributes();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_gibraltar::set_source_pif_entry(const la_ac_profile_impl* ac_profile)
{
    la_status status = LA_STATUS_SUCCESS;
    if (get_underlying_port_type() == object_type_e::RECYCLE_PORT) {
        return LA_STATUS_SUCCESS;
    }

    npl_source_pif_hw_table_value_t source_pif_value;
    source_pif_value.payloads.init_rx_data.initial_rx_data.init_fields = populate_initial_pd_nw_rx_data(ac_profile);

    source_pif_value.action = NPL_SOURCE_PIF_HW_TABLE_ACTION_INIT_RX_DATA;
    source_pif_value.payloads.init_rx_data.tag_swap_cmd = NPL_NO_TAG_SWAP;
    source_pif_value.payloads.init_rx_data.initial_layer_index = 0;

    // Convention is always start from FI, NP macro 0. No tag swapping for now.
    // Will change when this code gets more complex.
    source_pif_value.payloads.init_rx_data.fi_macro_id = NPL_FI_MACRO_ID_ETH;
    // np_macro_id is the in-engine, 6-bit ID and not the full 8-bit ID; truncate the MSB-s
    source_pif_value.payloads.init_rx_data.np_macro_id = (NPL_NETWORK_RX_MAC_AF_AND_TERMINATION_MACRO & 0x3F);

    // TODO - first_header_is_layer and first_header_type should be configured in all places that prepare value for
    // source_pif_value.
    source_pif_value.payloads.init_rx_data.first_header_is_layer = 1;
    source_pif_value.payloads.init_rx_data.first_header_type = NPL_PROTOCOL_TYPE_ETHERNET;

    // TODO-GB - the below WA was relevant to Pacific. Need to verify relevancy to GB.
    // PACKET-DMA-WA : all packets that go to PIF 18 will be wrapped with an inject-up header
    // as a consequence - SPA cannot have a member on PIF 18
    if ((m_system_port != nullptr) && (m_system_port->get_port_type() == la_system_port_base::port_type_e::PCI)) {
        source_pif_value.payloads.init_rx_data.np_macro_id = (NPL_RX_INJECT_MACRO & 0x3F);
    }

    if (m_spa_port != nullptr) {
        auto spa_port_gibraltar = m_spa_port.weak_ptr_static_cast<la_spa_port_gibraltar>();
        status = spa_port_gibraltar->set_source_pif_table(source_pif_value);
    } else if (m_system_port != nullptr) {
        la_system_port_base::port_type_e sys_port_type = m_system_port->get_port_type();
        if (sys_port_type != la_system_port_base::port_type_e::REMOTE) {
            auto system_port_gibraltar = m_system_port.weak_ptr_static_cast<la_system_port_gibraltar>();
            status = system_port_gibraltar->set_source_pif_table(source_pif_value);
        }
    }

    return status;
}

npl_mac_af_npp_attributes_table_t::value_type
la_ethernet_port_gibraltar::populate_mac_af_npp_attributes() const
{
    npl_mac_af_npp_attributes_table_t::value_type value;
    value.action = NPL_MAC_AF_NPP_ATTRIBUTES_TABLE_ACTION_WRITE;

    value.payloads.mac_af_npp_attributes.npp_attributes = (uint64_t)(m_copc_profile);
    value.payloads.mac_af_npp_attributes.enable_vlan_membership = 0;
    value.payloads.mac_af_npp_attributes.enable_transparent_ptp = m_transparent_ptp_enabled;
    value.payloads.mac_af_npp_attributes.enable_sr_dm_accounting = (m_traffic_matrix_type == traffic_matrix_type_e::EXTERNAL);

    value.payloads.mac_af_npp_attributes.mac_relay_id = 0;
    value.payloads.mac_af_npp_attributes.mapping_type
        = (m_port_type == port_type_e::SIMPLE) ? NPL_L2_VLAN_MAPPING : NPL_L2_SERVICE_MAPPING;
    if (m_service_mapping_type == service_mapping_type_e::LARGE) {
        value.payloads.mac_af_npp_attributes.mapping_type = NPL_L2_SERVICE_MAPPING;
    } else {
        value.payloads.mac_af_npp_attributes.mapping_type = NPL_L2_TCAM_MAPPING;
    }
    value.payloads.mac_af_npp_attributes.port_vlan_tag.pcp_dei.pcp = m_default_pcpdei.fields.pcp;
    value.payloads.mac_af_npp_attributes.port_vlan_tag.pcp_dei.dei = m_default_pcpdei.fields.dei;
    value.payloads.mac_af_npp_attributes.port_vlan_tag.vid.id = m_port_vid;
    value.payloads.mac_af_npp_attributes.vlan_membership_index = 0;
    return value;
}

la_status
la_ethernet_port_gibraltar::update_npp_sgt_attributes()
{
    la_status status = LA_STATUS_SUCCESS;

    if (m_spa_port != nullptr) {
        auto spa_port_gibraltar = m_spa_port.weak_ptr_static_cast<la_spa_port_gibraltar>();
        status = spa_port_gibraltar->update_npp_sgt_attributes(m_security_group_tag);
        return_on_error(status);
    } else if (m_system_port != nullptr) {
        auto system_port_gibraltar = m_system_port.weak_ptr_static_cast<la_system_port_gibraltar>();
        status = system_port_gibraltar->update_npp_sgt_attributes(m_security_group_tag);
        return_on_error(status);
    }

    return status;
}

la_status
la_ethernet_port_gibraltar::set_security_group_tag(la_sgt_t sgt)
{
    start_api_call("sgt=", sgt);

    transaction txn;
    la_sgt_t old_sgt = m_security_group_tag;

    m_security_group_tag = sgt;
    txn.on_fail([&]() { m_security_group_tag = old_sgt; });

    txn.status = update_npp_sgt_attributes();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_gibraltar::get_security_group_tag(la_sgt_t& out_sgt) const
{
    start_api_getter_call();

    out_sgt = m_security_group_tag;

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_gibraltar::update_dsp_sgt_attributes()
{
    la_status status = LA_STATUS_SUCCESS;

    if (m_spa_port != nullptr) {
        auto spa_port = m_spa_port.weak_ptr_static_cast<la_spa_port_gibraltar>();
        status = spa_port->update_dsp_sgt_attributes(m_security_group_policy_enforcement);
        return_on_error(status);
    } else if (m_system_port != nullptr) {
        auto system_port_gibraltar = m_system_port.weak_ptr_static_cast<la_system_port_gibraltar>();
        status = system_port_gibraltar->update_dsp_sgt_attributes(m_security_group_policy_enforcement);
        return_on_error(status);
    }

    return status;
}

la_status
la_ethernet_port_gibraltar::set_security_group_policy_enforcement(bool enforcement)
{
    start_api_call("enforcement=", enforcement);

    if (m_security_group_policy_enforcement == enforcement) {
        return LA_STATUS_SUCCESS;
    }

    transaction txn;
    bool old_enforcement = m_security_group_policy_enforcement;

    m_security_group_policy_enforcement = enforcement;
    txn.on_fail([&]() { m_security_group_policy_enforcement = old_enforcement; });

    txn.status = update_dsp_sgt_attributes();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_gibraltar::get_security_group_policy_enforcement(bool& out_enforcement) const
{
    start_api_getter_call();

    out_enforcement = m_security_group_policy_enforcement;
    return LA_STATUS_SUCCESS;
}

la_status
la_ethernet_port_gibraltar::configure_security_group_policy_attributes()
{
    transaction txn;

    txn.status = update_npp_sgt_attributes();
    return_on_error(txn.status);

    txn.status = update_dsp_sgt_attributes();
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
