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

#include "api/npu/la_switch.h"

#include "common/defines.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "npu/counter_utils.h"
#include "npu/la_ac_profile_impl.h"
#include "npu/la_acl_delegate.h"

#include "api/npu/la_vrf.h"
#include "la_l2_service_port_pacgb.h"
#include "nplapi/npl_constants.h"
#include "npu/ipv4_sip_index_manager.h"
#include "npu/la_ac_port_common.h"
#include "npu/la_acl_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_switch_impl.h"
#include "npu/resolution_utils.h"
#include "qos/la_egress_qos_profile_impl.h"
#include "qos/la_ingress_qos_profile_impl.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"
#include "system/la_spa_port_base.h"
#include "system/la_system_port_base.h"
#include "system/slice_id_manager_base.h"

#include "api_tracer.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>
#include <tuple>

namespace silicon_one
{

la_l2_service_port_pacgb::la_l2_service_port_pacgb(const la_device_impl_wptr& device) : la_l2_service_port_base(device)
{
}

la_l2_service_port_pacgb::~la_l2_service_port_pacgb()
{
}

lpm_destination_id
la_l2_service_port_pacgb::get_lpm_destination_id(resolution_step_e prev_step) const
{
    return lpm_destination_id(NPL_LPM_COMPRESSED_DESTINATION_FEC_MASK | m_port_gid);
}

la_status
la_l2_service_port_pacgb::populate_inject_up_port_parameters()
{
    if (m_port_type != port_type_e::AC) {
        return LA_STATUS_EINVAL;
    }

    if (m_ac_ethernet_port->is_aggregate()) {
        return LA_STATUS_EINVAL;
    }

    auto sp = la_system_port_base::upcast_from_api(m_device, m_ac_ethernet_port->get_system_port());
    const la_object* underlying_port = sp->get_underlying_port();
    if (underlying_port == nullptr) {
        return LA_STATUS_EINVAL;
    }

    // update l2_dlp_table with inject-up port parameters
    la_slice_id_t slice = sp->get_slice();
    la_slice_pair_id_t pair_idx = slice / 2;

    const auto& l2_dlp_entry = m_slice_pair_data_b[pair_idx].l2_dlp_entry;
    npl_l2_dlp_table_key_t k;
    npl_l2_dlp_table_value_t v;
    k.l2_dlp_id_key_id = m_port_gid;

    bool is_recycle_ac = silicon_one::is_recycle_ac(m_device->get_sptr(this));
    if (is_recycle_ac) {
        v.payloads.l2_dlp_attributes.tx_to_rx_rcy_data.unscheduled_recycle_data = NPL_TX2RX_SCHED_RCY_DATA_OBM_TO_INJECT_UP & 0x3f;
        v.payloads.l2_dlp_attributes.tx_to_rx_rcy_data.unscheduled_recycle_code.unscheduled_recycle_code_lsb
            = bit_utils::get_bit(NPL_TX2RX_SCHED_RCY_DATA_OBM_TO_INJECT_UP, 6);
        v.payloads.l2_dlp_attributes.tx_to_rx_rcy_data.unscheduled_recycle_code.recycle_pkt
            = bit_utils::get_bit(NPL_TX2RX_SCHED_RCY_DATA_OBM_TO_INJECT_UP, 7);
        v.payloads.l2_dlp_attributes.l2_dlp_specific.ac.eve_types.eve.main_type = NPL_VLAN_EDIT_COMMAND_MAIN_PUSH_2;
        v.payloads.l2_dlp_attributes.l2_dlp_specific.ac.eve_types.eve.prf = 2;

    } else {
        v.payloads.l2_dlp_attributes.tx_to_rx_rcy_data.unscheduled_recycle_data = NPL_TX2RX_RCY_DATA_OBM_TO_INJECT_UP & 0x3f;
        v.payloads.l2_dlp_attributes.tx_to_rx_rcy_data.unscheduled_recycle_code.unscheduled_recycle_code_lsb = 0x0;
        v.payloads.l2_dlp_attributes.tx_to_rx_rcy_data.unscheduled_recycle_code.recycle_pkt = 0x1;
    }

    v.payloads.l2_dlp_attributes.dlp_attributes.port_mirror_type = NPL_PORT_MIRROR_TYPE_UN_CONDITIONED;

    la_status status = l2_dlp_entry->update(v);
    return_on_error(status, HLD, ERROR, "inject-up port config failed: l2_dlp_table[%d].update", pair_idx);

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_pacgb::configure_service_lp_attributes_table(la_slice_id_t slice_idx,
                                                                npl_service_lp_attributes_table_entry_wptr_t& lp_attributes_entry)
{
    la_slice_pair_id_t pair_idx = slice_idx / 2;
    // Configure key and value
    const auto& table(m_device->m_tables.service_lp_attributes_table[pair_idx]);
    npl_service_lp_attributes_table_key_t k;
    npl_service_lp_attributes_table_value_t v;
    npl_mac_lp_attributes_payload_t& payload(v.payloads.write.mac_lp_attributes_payload.lp_attr);

    k.service_lp_attributes_table_key.id = get_local_slp_id(slice_idx);
    v.action = NPL_SERVICE_LP_ATTRIBUTES_TABLE_ACTION_WRITE;
    populate_lp_attributes_payload(payload);

    // vxlan does not support feature yet
    if (m_port_type != port_type_e::VXLAN) {
        payload.layer.two.shared.qos_id = m_ingress_qos_profile->get_id(pair_idx);
        populate_payload_counters(payload, slice_idx);
    }

    // Update table
    la_status status = table->insert(k, v, lp_attributes_entry);
    if (status != LA_STATUS_SUCCESS) {
        log_err(
            HLD,
            "la_l2_service_port_base::configure_service_lp_attributes_table: lp_attributes_table[%d].insert failed, status = %s",
            pair_idx,
            la_status2str(status).c_str());
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_l2_service_port_pacgb::set_group_policy_encap(bool enabled)
{
    start_api_call("enabled=", enabled);

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_l2_service_port_pacgb::get_group_policy_encap(bool& out_enabled) const
{
    start_api_getter_call("");

    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
