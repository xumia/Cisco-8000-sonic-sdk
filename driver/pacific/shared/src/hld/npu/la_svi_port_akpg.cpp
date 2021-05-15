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

#include "la_svi_port_akpg.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_switch_impl.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_strings.h"

namespace silicon_one
{

la_svi_port_akpg::la_svi_port_akpg(const la_device_impl_wptr& device) : la_svi_port_base(device)
{
}

la_svi_port_akpg::~la_svi_port_akpg()
{
}

la_status
la_svi_port_akpg::add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);

    return la_svi_port_base::add_ipv4_host_with_class_id(ip_addr, mac_addr, class_id);
}

la_status
la_svi_port_akpg::modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);

    return la_svi_port_base::modify_ipv4_host_with_class_id(ip_addr, mac_addr, class_id);
}

la_status
la_svi_port_akpg::add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);

    return la_svi_port_base::add_ipv6_host_with_class_id(ip_addr, mac_addr, class_id);
}

la_status
la_svi_port_akpg::modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id)
{
    start_api_call("ip_addr=", ip_addr, "mac_addr=", mac_addr, "class_id=", class_id);

    return la_svi_port_base::modify_ipv6_host_with_class_id(ip_addr, mac_addr, class_id);
}

la_status
la_svi_port_akpg::populate_recycled_inject_up_info_table(const la_l2_service_port_base_wptr& inject_up_port)
{
    npl_recycled_inject_up_info_table_key_t key;
    npl_recycled_inject_up_info_table_value_t value;
    npl_recycled_inject_up_info_table_entry_t* entry = nullptr;

    la_system_port_gid_t ssp = inject_up_port->get_ethernet_port()->get_system_port()->get_gid();

    bool is_recycle_ac = silicon_one::is_recycle_ac(inject_up_port.weak_ptr_static_cast<const la_l2_service_port_base>());
    if (is_recycle_ac) {
        key.tx_to_rx_rcy_data = NPL_TX2RX_SCHED_RCY_DATA_OBM_2_TO_INJECT_UP & 0x3f;
    } else {
        key.tx_to_rx_rcy_data = NPL_TX2RX_RCY_DATA_OBM_TO_INJECT_UP & 0x3f;
    }

    la_status status = m_device->m_tables.recycled_inject_up_info_table[0]->lookup(key, entry);
    if (status == LA_STATUS_SUCCESS) {
        value = entry->value();
        if (value.payloads.update_data.ssp == ssp) {
            // single entry per device
            return LA_STATUS_SUCCESS;
        } else {
            log_err(HLD, "inject-up already configured on system port 0x%lx", value.payloads.update_data.ssp);
            return LA_STATUS_EINVAL;
        }
    } else {
        value.action = NPL_RECYCLED_INJECT_UP_INFO_TABLE_ACTION_UPDATE_DATA;
        value.payloads.update_data.ssp = ssp;
        for (la_slice_id_t slice : m_device->get_used_slices()) {
            la_status status = m_device->m_tables.recycled_inject_up_info_table[slice]->set(key, value, entry);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_akpg::clear_recycled_inject_up_info_table()
{
    npl_recycled_inject_up_info_table_key_t key;
    key.tx_to_rx_rcy_data = NPL_TX2RX_RCY_DATA_OBM_TO_INJECT_UP & 0x3f;
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        la_status status = m_device->m_tables.recycled_inject_up_info_table[slice]->erase(key);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_svi_port_akpg::update_additional_l3_lp_attributes(const npl_l3_lp_additional_attributes_t& additional_attribs)
{
    const auto& table(m_device->m_tables.service_relay_attributes_table);
    npl_service_relay_attributes_table_key_t key;
    npl_service_relay_attributes_table_entry_t* entry = nullptr;

    key.relay_id.id = m_sw->get_gid();

    la_status status = table->lookup(key, entry);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "la_svi_port_base::update_additional_l3_lp_attributes: lookup failed %s", la_status2str(status).c_str());
        return status;
    }

    npl_service_relay_attributes_table_value_t value(entry->value());
    npl_l3_lp_additional_attributes_t& current_additional_attribs(
        value.payloads.relay.payload.relay_table_payload.l3_lp_additional_attributes);
    current_additional_attribs = additional_attribs;

    status = entry->update(value);

    return status;
}

void
la_svi_port_akpg::fill_npl_mac_termination_em_table_key(la_switch_gid_t sw_gid,
                                                        const la_mac_addr_t& mac_addr,
                                                        uint64_t prefix,
                                                        npl_mac_termination_em_table_key_t& out_key)
{
    out_key.relay_id.id = sw_gid;
    out_key.ethernet_header_da_17_0_ = mac_addr.flat & ((1ULL << 18) - 1);
    out_key.da_prefix = prefix;
}

} // namespace silicon_one
