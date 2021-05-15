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

#include "la_copc_base.h"
#include "common/transaction.h"
#include "system/la_device_impl.h"

namespace silicon_one
{
la_copc_base::la_copc_base(la_device_impl_wptr device) : m_device(device)
{
}

la_copc_base::~la_copc_base()
{
}

la_status
la_copc_base::initialize(la_object_id_t oid, la_control_plane_classifier::type_e type)
{
    m_oid = oid;
    m_type = type;

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_copc_base::type() const
{
    return object_type_e::COPC;
}

std::string
la_copc_base::to_string() const
{
    std::stringstream log_message;
    log_message << "la_copc_base(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_copc_base::oid() const
{
    return m_oid;
}

const la_device*
la_copc_base::get_device() const
{
    return m_device.get();
}

la_status
la_copc_base::get_copc_type(la_control_plane_classifier::type_e& out_type) const
{
    // start_api_getter_call();

    out_type = m_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::get_count(size_t& out_count) const
{
    // start_api_getter_call();

    out_count = m_entries.size();

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::push(size_t position,
                   const la_control_plane_classifier::key& key_val,
                   const la_control_plane_classifier::result& result)
{
    // start_api_call("position=", position, "key_val=", key_val, "result=", result);

    transaction txn;
    copc_key_t sdk_key_val;
    copc_result_t sdk_result;
    sdk_result.event = result.event;

    txn.status = convert_la_key_to_sdk_key(key_val, sdk_key_val);
    return_on_error(txn.status);

    // Check TCAM availability
    txn.status = is_tcam_available();
    return_on_error(txn.status);

    // Program TCAM entry
    txn.status = set_tcam_line(position, sdk_key_val, sdk_result);
    return_on_error(txn.status);

    // Update shadow
    auto shadow_copc_entry = la_control_plane_classifier::entry_desc{key_val, result};
    m_entries.insert(m_entries.begin() + position, shadow_copc_entry);

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::set(size_t position,
                  const la_control_plane_classifier::key& key_val,
                  const la_control_plane_classifier::result& result)
{
    // start_api_call("position=", position, "key_val=", key_val, "result=", result);

    // Check arguments
    if (position >= m_entries.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = pop(position);
    return_on_error(status);

    return push(position, key_val, result);
}

la_status
la_copc_base::append(const la_control_plane_classifier::key& key_val, const la_control_plane_classifier::result& result)
{
    // start_api_call("key_val=", key_val, "result=", result);

    return push(m_entries.size(), key_val, result);
}

la_status
la_copc_base::pop(size_t position)
{
    // start_api_call("position=", position);
    la_status status;

    if (position >= m_entries.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        // locate the entry
        size_t index = 0;

        status = get_tcam_line_index(slice, position, index);
        return_on_error(status);

        status = pop_tcam_table_entry(slice, index);
        return_on_error(status);
    }

    m_entries.erase(m_entries.begin() + position);

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::get(size_t position, la_control_plane_classifier::entry_desc& out_copc_entry_desc) const
{
    // start_api_call("position=", position);

    if (position >= m_entries.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_copc_entry_desc = m_entries[position];

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::clear()
{
    // start_api_getter_call();

    // Pop entries from last to first for best performance.
    while (!m_entries.empty()) {
        la_status status = pop(m_entries.size() - 1);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

slice_ifg_vec_t
la_copc_base::get_ifgs() const
{
    return get_all_network_ifgs(m_device);
}

la_status
la_copc_base::get_tcam_size(la_slice_id_t slice, size_t& size) const
{
    la_status status = LA_STATUS_SUCCESS;
    size = 0;

    if (m_type == la_control_plane_classifier::type_e::IPV4) {
        size = m_device->m_tables.l2_lpts_ipv4_table[slice]->max_size();
    } else if (m_type == la_control_plane_classifier::type_e::IPV6) {
        size = m_device->m_tables.l2_lpts_ipv6_table[slice]->max_size();
    } else if (m_type == la_control_plane_classifier::type_e::MAC) {
        size = m_device->m_tables.l2_lpts_mac_table[slice]->max_size();
    } else {
        status = LA_STATUS_EINVAL;
    }

    return status;
}

la_status
la_copc_base::get_tcam_fullness(la_slice_id_t slice, size_t& size) const
{
    la_status status = LA_STATUS_SUCCESS;
    size = 0;

    if (m_type == la_control_plane_classifier::type_e::IPV4) {
        size = m_device->m_tables.l2_lpts_ipv4_table[slice]->size();
    } else if (m_type == la_control_plane_classifier::type_e::IPV6) {
        size = m_device->m_tables.l2_lpts_ipv6_table[slice]->size();
    } else if (m_type == la_control_plane_classifier::type_e::MAC) {
        size = m_device->m_tables.l2_lpts_mac_table[slice]->size();
    } else {
        status = LA_STATUS_EINVAL;
    }

    return status;
}

la_status
la_copc_base::get_tcam_line_index(la_slice_id_t slice, size_t position, size_t& tcam_line_index) const
{
    size_t tcam_size = 0;
    la_status status = get_tcam_size(slice, tcam_size);
    return_on_error(status);

    size_t entry_found = 0;

    for (size_t index = 0; (index < tcam_size) && (entry_found <= position); index++) {
        bool contains;
        status = is_tcam_line_contains_entry(slice, index, contains);
        return_on_error(status);

        if (!contains) {
            continue;
        }

        entry_found++;

        if (entry_found > position) {
            tcam_line_index = index;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_copc_base::is_tcam_line_contains_entry(la_slice_id_t slice, size_t tcam_line, bool& contains) const
{
    la_status status;

    if (m_type == la_control_plane_classifier::type_e::IPV4) {
        npl_l2_lpts_ipv4_table_t::entry_pointer_type e1 = nullptr;
        status = m_device->m_tables.l2_lpts_ipv4_table[slice]->get_entry(tcam_line, e1);
        contains = (e1 != nullptr);
    } else if (m_type == la_control_plane_classifier::type_e::IPV6) {
        npl_l2_lpts_ipv6_table_t::entry_pointer_type e1 = nullptr;
        status = m_device->m_tables.l2_lpts_ipv6_table[slice]->get_entry(tcam_line, e1);
        contains = (e1 != nullptr);
    } else if (m_type == la_control_plane_classifier::type_e::MAC) {
        npl_l2_lpts_mac_table_t::entry_pointer_type e1 = nullptr;
        status = m_device->m_tables.l2_lpts_mac_table[slice]->get_entry(tcam_line, e1);
        contains = (e1 != nullptr);
    } else {
        return LA_STATUS_EINVAL;
    }

    if (status == LA_STATUS_ENOTFOUND) {
        // Empty
        contains = false;
        return LA_STATUS_SUCCESS;
    }

    if (status != LA_STATUS_SUCCESS) {
        contains = false;
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::is_tcam_available()
{
    la_status status;
    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        size_t tcam_fullness = 0;
        status = get_tcam_fullness(slice, tcam_fullness);
        return_on_error(status);

        size_t tcam_size = 0;
        status = get_tcam_size(slice, tcam_size);
        return_on_error(status);

        if (tcam_fullness >= tcam_size) {
            log_err(HLD, "Insufficient TCAM space to push COPC entry. Fullness: %ld/%ld", tcam_fullness, tcam_size);
            return LA_STATUS_ERESOURCE;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::populate_tcam_key_value_result(npl_l2_lpts_ipv4_table_t::key_type& out_key,
                                             npl_l2_lpts_ipv4_table_t::key_type& out_mask,
                                             npl_l2_lpts_ipv4_table_t::value_type& out_value,
                                             const copc_key_t& key_val,
                                             const copc_result_t& result)
{
    la_status status;

    status = copy_key_mask_to_npl(key_val.val.ipv4, out_key, false /* is_mask */);
    return_on_error(status);

    status = copy_key_mask_to_npl(key_val.mask.ipv4, out_mask, true /* is_mask */);
    return_on_error(status);

    status = copy_result_to_npl(result, out_value.payloads.l2_lpts_result);
    return_on_error(status);

    return status;
}

la_status
la_copc_base::populate_tcam_key_value_result(npl_l2_lpts_ipv6_table_t::key_type& out_key,
                                             npl_l2_lpts_ipv6_table_t::key_type& out_mask,
                                             npl_l2_lpts_ipv6_table_t::value_type& out_value,
                                             const copc_key_t& key_val,
                                             const copc_result_t& result)
{
    la_status status;

    status = copy_key_mask_to_npl(key_val.val.ipv6, out_key, false /* is_mask */);
    return_on_error(status);

    status = copy_key_mask_to_npl(key_val.mask.ipv6, out_mask, true /* is_mask */);
    return_on_error(status);

    status = copy_result_to_npl(result, out_value.payloads.l2_lpts_result);
    return_on_error(status);

    return status;
}

la_status
la_copc_base::populate_tcam_key_value_result(npl_l2_lpts_mac_table_t::key_type& out_key,
                                             npl_l2_lpts_mac_table_t::key_type& out_mask,
                                             npl_l2_lpts_mac_table_t::value_type& out_value,
                                             const copc_key_t& key_val,
                                             const copc_result_t& result)
{
    la_status status;

    status = copy_key_mask_to_npl(key_val.val.mac, out_key, false /* is_mask */);
    return_on_error(status);

    status = copy_key_mask_to_npl(key_val.mask.mac, out_mask, true /* is_mask */);
    return_on_error(status);

    status = copy_result_to_npl(result, out_value.payloads.l2_lpts_result);
    return_on_error(status);

    return status;
}

template <class _TableType>
la_status
la_copc_base::push_entry(const std::shared_ptr<_TableType>& table,
                         size_t index,
                         bool is_push,
                         const copc_key_t& key_val,
                         const copc_result_t& result)
{
    typename _TableType::key_type key;
    typename _TableType::key_type mask;
    typename _TableType::value_type value;
    typename _TableType::entry_pointer_type entry = nullptr;

    transaction txn;

    txn.status = populate_tcam_key_value_result(key, mask, value, key_val, result);
    return_on_error(txn.status);

    if (is_push) {
        txn.status = table->push(index, key, mask, value, entry);
    } else {
        txn.status = table->insert(index, key, mask, value, entry);
    }
    return_on_error(txn.status);

    return txn.status;
}

la_status
la_copc_base::set_tcam_line(size_t position, const copc_key_t& key_val, const copc_result_t& result)
{
    transaction txn;

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        // locate empty tcam line
        size_t index = 0;

        if (position > 0) {
            // Locate the last lpts entry before the required position
            txn.status = get_tcam_line_index(slice, position - 1, index);
            return_on_error(txn.status);

            index += 1;
        }

        if (m_type == la_control_plane_classifier::type_e::IPV4) {
            txn.status = push_entry(m_device->m_tables.l2_lpts_ipv4_table[slice], index, true, key_val, result);
        } else if (m_type == la_control_plane_classifier::type_e::IPV6) {
            txn.status = push_entry(m_device->m_tables.l2_lpts_ipv6_table[slice], index, true, key_val, result);
        } else if (m_type == la_control_plane_classifier::type_e::MAC) {
            txn.status = push_entry(m_device->m_tables.l2_lpts_mac_table[slice], index, true, key_val, result);
        }
        return_on_error(txn.status);
    }

    return txn.status;
}

la_status
la_copc_base::convert_trap_to_npl_result(const la_event_e& event, npl_l2_lpts_payload_t& result_event)
{
    switch (event) {
    case LA_EVENT_ETHERNET_LACP:
        result_event.lacp = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP0:
        result_event.l2cp0 = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP1:
        result_event.l2cp1 = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP2:
        result_event.l2cp2 = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP3:
        result_event.l2cp3 = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP4:
        result_event.l2cp4 = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP5:
        result_event.l2cp5 = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP6:
        result_event.l2cp6 = 1;
        break;
    case LA_EVENT_ETHERNET_L2CP7:
        result_event.l2cp7 = 1;
        break;
    case LA_EVENT_ETHERNET_CISCO_PROTOCOLS:
        result_event.cisco_protocols = 1;
        break;
    case LA_EVENT_ETHERNET_ISIS_OVER_L2:
        result_event.isis_over_l2 = 1;
        break;
    case LA_EVENT_L3_ISIS_DRAIN:
        result_event.isis_drain = 1;
        break;
    case LA_EVENT_L3_ISIS_OVER_L3:
        result_event.isis_over_l3 = 1;
        break;
    case LA_EVENT_ETHERNET_ARP:
        result_event.arp = 1;
        break;
    case LA_EVENT_ETHERNET_PTP_OVER_ETH:
        result_event.ptp_over_eth = 1;
        break;
    case LA_EVENT_ETHERNET_MACSEC:
        result_event.macsec = 1;
        break;
    case LA_EVENT_ETHERNET_DHCPV4_SERVER:
        result_event.dhcpv4_server = 1;
        break;
    case LA_EVENT_ETHERNET_DHCPV4_CLIENT:
        result_event.dhcpv4_client = 1;
        break;
    case LA_EVENT_ETHERNET_DHCPV6_SERVER:
        result_event.dhcpv6_server = 1;
        break;
    case LA_EVENT_ETHERNET_DHCPV6_CLIENT:
        result_event.dhcpv6_client = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP0:
        result_event.rsvd.trap0 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP1:
        result_event.rsvd.trap1 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP2:
        result_event.rsvd.trap2 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP3:
        result_event.rsvd.trap3 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP4:
        result_event.rsvd.trap4 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP5:
        result_event.rsvd.trap5 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP6:
        result_event.rsvd.trap6 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP7:
        result_event.rsvd.trap7 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP8:
        result_event.rsvd.trap8 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP9:
        result_event.rsvd.trap9 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP10:
        result_event.rsvd.trap10 = 1;
        break;
    case LA_EVENT_L2_LPTS_TRAP11:
        result_event.rsvd.trap11 = 1;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::copy_key_mask_to_npl(const copc_key_ipv4_t& key_mask,
                                   npl_l2_lpts_ipv4_table_t::key_type& npl_key_mask,
                                   bool is_mask) const
{
    npl_key_mask.dip = key_mask.dip.s_addr;
    npl_key_mask.l4_ports.src_port = (key_mask.l4_ports.src_port & 0xffff);
    npl_key_mask.l4_ports.dst_port = (key_mask.l4_ports.dst_port & 0xffff);
    npl_key_mask.ttl = (key_mask.ttl & 0xff);
    npl_key_mask.protocol = (key_mask.protocol & 0xff);
    npl_key_mask.npp_attributes = (key_mask.npp_attributes & la_device_impl::MAX_COPC_ETHERNET_PROFILES);
    npl_key_mask.bd_attributes = (key_mask.bd_attributes & la_device_impl::MAX_COPC_SWITCH_PROFILES);
    npl_key_mask.l2_slp_attributes = (key_mask.l2_service_port_attributes & la_device_impl::MAX_COPC_L2_SERVICE_PORT_PROFILES);
    npl_key_mask.mac_lp_type = (npl_mac_lp_type_e)key_mask.mac_lp_type;
    npl_key_mask.mac_terminated = key_mask.my_mac;
    npl_key_mask.is_svi = key_mask.is_svi;
    npl_key_mask.is_tagged = key_mask.has_vlan_tag;
    npl_key_mask.ip_not_first_fragment.v4_not_first_fragment = key_mask.ip_not_first_fragment;
    npl_key_mask.ip_not_first_fragment.v6_not_first_fragment = 0;

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::copy_result_to_npl(const copc_result_t& result, npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t& npl_result)
{
    la_status status = LA_STATUS_SUCCESS;

    status = convert_trap_to_npl_result(result.event, npl_result.l2_lpts_trap_vector);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "ipv4_copy_result_to_npl: invalid trap id = %u", result.event);
    }

    return status;
}

la_status
la_copc_base::copy_key_mask_to_npl(const copc_key_ipv6_t& key_mask,
                                   npl_l2_lpts_ipv6_table_t::key_type& npl_key_mask,
                                   bool is_mask) const
{
    npl_key_mask.dip_32_lsb = (key_mask.dip.d_addr[0] & 0xffffffff);
    npl_key_mask.dip_32_msb = (key_mask.dip.d_addr[3] & 0xffffffff);
    npl_key_mask.l4_ports.src_port = (key_mask.l4_ports.src_port & 0xffff);
    npl_key_mask.l4_ports.dst_port = (key_mask.l4_ports.dst_port & 0xffff);
    npl_key_mask.next_header = (key_mask.next_header & 0xff);
    npl_key_mask.hop_limit = (key_mask.hop_limit & 0xff);
    npl_key_mask.npp_attributes = (key_mask.npp_attributes & la_device_impl::MAX_COPC_ETHERNET_PROFILES);
    npl_key_mask.bd_attributes = (key_mask.bd_attributes & la_device_impl::MAX_COPC_SWITCH_PROFILES);
    npl_key_mask.l2_slp_attributes = (key_mask.l2_service_port_attributes & la_device_impl::MAX_COPC_L2_SERVICE_PORT_PROFILES);
    npl_key_mask.mac_lp_type = (npl_mac_lp_type_e)key_mask.mac_lp_type;
    npl_key_mask.mac_terminated = key_mask.my_mac;
    npl_key_mask.is_svi = key_mask.is_svi;
    npl_key_mask.is_tagged = key_mask.has_vlan_tag;
    npl_key_mask.ip_not_first_fragment.v4_not_first_fragment = 0;
    npl_key_mask.ip_not_first_fragment.v6_not_first_fragment = (key_mask.ip_not_first_fragment ? (0x1 << 1) : 0);

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::copy_result_to_npl(const copc_result_t& result, npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t& npl_result)
{
    la_status status = LA_STATUS_SUCCESS;

    status = convert_trap_to_npl_result(result.event, npl_result.l2_lpts_trap_vector);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "ipv6_copy_result_to_npl: invalid trap id = %u", result.event);
    }

    return status;
}

la_status
la_copc_base::copy_key_mask_to_npl(const copc_key_mac_t& key_mask,
                                   npl_l2_lpts_mac_table_t::key_type& npl_key_mask,
                                   bool is_mask) const
{
    npl_key_mask.ether_type = key_mask.ether_type;
    npl_key_mask.mac_da.mac_address = key_mask.mac_da.flat;
    npl_key_mask.npp_attributes = (key_mask.npp_attributes & la_device_impl::MAX_COPC_ETHERNET_PROFILES);
    npl_key_mask.bd_attributes = (key_mask.bd_attributes & la_device_impl::MAX_COPC_SWITCH_PROFILES);
    npl_key_mask.l2_slp_attributes = (key_mask.l2_service_port_attributes & la_device_impl::MAX_COPC_L2_SERVICE_PORT_PROFILES);
    npl_key_mask.mac_lp_type = (npl_mac_lp_type_e)key_mask.mac_lp_type;
    npl_key_mask.mac_terminated = key_mask.my_mac;
    npl_key_mask.is_svi = key_mask.is_svi;
    npl_key_mask.is_tagged = key_mask.has_vlan_tag;

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::copy_result_to_npl(const copc_result_t& result, npl_l2_lpts_mac_table_l2_lpts_result_payload_t& npl_result)
{
    la_status status = LA_STATUS_SUCCESS;

    status = convert_trap_to_npl_result(result.event, npl_result.l2_lpts_trap_vector);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "mac_copy_result_to_npl: invalid trap id = %u", result.event);
    }

    return status;
}

la_status
la_copc_base::pop_tcam_table_entry(la_slice_id_t slice, size_t tcam_line)
{
    la_status status;

    if (m_type == la_control_plane_classifier::type_e::IPV4) {
        status = m_device->m_tables.l2_lpts_ipv4_table[slice]->pop(tcam_line);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to pop copc_ipv4_table entry, status = %s", la_status2str(status).c_str());
            return status;
        }
    } else if (m_type == la_control_plane_classifier::type_e::IPV6) {
        status = m_device->m_tables.l2_lpts_ipv6_table[slice]->pop(tcam_line);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to pop copc_ipv6_table entry, status = %s", la_status2str(status).c_str());
            return status;
        }
    } else if (m_type == la_control_plane_classifier::type_e::MAC) {
        status = m_device->m_tables.l2_lpts_mac_table[slice]->pop(tcam_line);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to pop copc_mac_table entry, status = %s", la_status2str(status).c_str());
            return status;
        }
    } else {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::convert_la_ipv4_key_to_sdk_ipv4_key(const la_control_plane_classifier::key& la_key_val, copc_key_t& sdk_key_val)
{
    la_copc_base::copc_key_t ipv4_key_val = {.type = la_control_plane_classifier::type_e::IPV4,
                                             .val = {.ipv4 = {.dip = {.s_addr = 0},
                                                              .protocol = 0,
                                                              .l4_ports = {.src_port = 0, .dst_port = 0},
                                                              .npp_attributes = 0,
                                                              .bd_attributes = 0,
                                                              .l2_service_port_attributes = 0,
                                                              .mac_lp_type = 0,
                                                              .ttl = 0,
                                                              .my_mac = 0,
                                                              .is_svi = 0,
                                                              .has_vlan_tag = 0,
                                                              .ip_not_first_fragment = 0}},
                                             .mask = {.ipv4 = {.dip = {.s_addr = 0},
                                                               .protocol = 0,
                                                               .l4_ports = {.src_port = 0, .dst_port = 0},
                                                               .npp_attributes = 0,
                                                               .bd_attributes = 0,
                                                               .l2_service_port_attributes = 0,
                                                               .mac_lp_type = 0,
                                                               .ttl = 0,
                                                               .my_mac = 0,
                                                               .is_svi = 0,
                                                               .has_vlan_tag = 0,
                                                               .ip_not_first_fragment = 0}}};

    sdk_key_val = ipv4_key_val;

    for (const auto field : la_key_val) {
        switch (field.type.ipv4) {
        case la_control_plane_classifier::ipv4_field_type_e::SWITCH_PROFILE_ID:
            sdk_key_val.val.ipv4.bd_attributes = (la_uint8_t)field.val.ipv4.switch_profile_id;
            sdk_key_val.mask.ipv4.bd_attributes = (la_uint8_t)field.mask.ipv4.switch_profile_id;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::ETHERNET_PROFILE_ID:
            sdk_key_val.val.ipv4.npp_attributes = (la_uint8_t)field.val.ipv4.ethernet_profile_id;
            sdk_key_val.mask.ipv4.npp_attributes = (la_uint8_t)field.mask.ipv4.ethernet_profile_id;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::L2_SERVICE_PORT_PROFILE_ID:
            sdk_key_val.val.ipv4.l2_service_port_attributes = (la_uint8_t)field.val.ipv4.l2_service_port_profile_id;
            sdk_key_val.mask.ipv4.l2_service_port_attributes = (la_uint8_t)field.mask.ipv4.l2_service_port_profile_id;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::LP_TYPE:
            sdk_key_val.val.ipv4.mac_lp_type = (la_uint8_t)field.val.ipv4.lp_type;
            sdk_key_val.mask.ipv4.mac_lp_type = (la_uint8_t)field.mask.ipv4.lp_type;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::IPV4_DIP:
            sdk_key_val.val.ipv4.dip.s_addr = field.val.ipv4.ipv4_dip.s_addr;
            sdk_key_val.mask.ipv4.dip.s_addr = field.mask.ipv4.ipv4_dip.s_addr;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::TTL:
            sdk_key_val.val.ipv4.ttl = field.val.ipv4.ttl;
            sdk_key_val.mask.ipv4.ttl = field.mask.ipv4.ttl;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::PROTOCOL:
            sdk_key_val.val.ipv4.protocol = field.val.ipv4.protocol;
            sdk_key_val.mask.ipv4.protocol = field.mask.ipv4.protocol;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::SPORT:
            sdk_key_val.val.ipv4.l4_ports.src_port = field.val.ipv4.sport;
            sdk_key_val.mask.ipv4.l4_ports.src_port = field.mask.ipv4.sport;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::DPORT:
            sdk_key_val.val.ipv4.l4_ports.dst_port = field.val.ipv4.dport;
            sdk_key_val.mask.ipv4.l4_ports.dst_port = field.mask.ipv4.dport;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::MY_MAC:
            sdk_key_val.val.ipv4.my_mac = field.val.ipv4.my_mac;
            sdk_key_val.mask.ipv4.my_mac = field.mask.ipv4.my_mac;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::IS_SVI:
            sdk_key_val.val.ipv4.is_svi = field.val.ipv4.is_svi;
            sdk_key_val.mask.ipv4.is_svi = field.mask.ipv4.is_svi;
            break;
        case la_control_plane_classifier::ipv4_field_type_e::HAS_VLAN_TAG:
            sdk_key_val.val.ipv4.has_vlan_tag = field.val.ipv4.has_vlan_tag;
            sdk_key_val.mask.ipv4.has_vlan_tag = field.mask.ipv4.has_vlan_tag;
            break;
        default:
            return LA_STATUS_EINVAL;
            break;
        }
    }
    sdk_key_val.val.ipv4.ip_not_first_fragment = 0;
    sdk_key_val.mask.ipv4.ip_not_first_fragment = 1;

    // In case of L3 force set my_mac and is_svi to dont care
    if (sdk_key_val.val.ipv4.mac_lp_type && sdk_key_val.mask.ipv4.mac_lp_type) {
        sdk_key_val.val.ipv4.my_mac = 0;
        sdk_key_val.mask.ipv4.my_mac = 0;
        sdk_key_val.val.ipv4.is_svi = 0;
        sdk_key_val.mask.ipv4.is_svi = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::convert_la_ipv6_key_to_sdk_ipv6_key(const la_control_plane_classifier::key& la_key_val, copc_key_t& sdk_key_val)
{
    la_copc_base::copc_key_t ipv6_key_val = {.type = la_control_plane_classifier::type_e::IPV6,
                                             .val = {.ipv6 = {.dip = {.s_addr = 0},
                                                              .next_header = 0,
                                                              .l4_ports = {.src_port = 0, .dst_port = 0},
                                                              .npp_attributes = 0,
                                                              .bd_attributes = 0,
                                                              .l2_service_port_attributes = 0,
                                                              .mac_lp_type = 0,
                                                              .hop_limit = 0,
                                                              .my_mac = 0,
                                                              .is_svi = 0,
                                                              .has_vlan_tag = 0,
                                                              .ip_not_first_fragment = 0}},
                                             .mask = {.ipv6 = {.dip = {.s_addr = 0},
                                                               .next_header = 0,
                                                               .l4_ports = {.src_port = 0, .dst_port = 0},
                                                               .npp_attributes = 0,
                                                               .bd_attributes = 0,
                                                               .l2_service_port_attributes = 0,
                                                               .mac_lp_type = 0,
                                                               .hop_limit = 0,
                                                               .my_mac = 0,
                                                               .is_svi = 0,
                                                               .has_vlan_tag = 0,
                                                               .ip_not_first_fragment = 0}}};
    sdk_key_val = ipv6_key_val;

    for (const auto field : la_key_val) {
        switch (field.type.ipv6) {
        case la_control_plane_classifier::ipv6_field_type_e::SWITCH_PROFILE_ID:
            sdk_key_val.val.ipv6.bd_attributes = (la_uint8_t)field.val.ipv6.switch_profile_id;
            sdk_key_val.mask.ipv6.bd_attributes = (la_uint8_t)field.mask.ipv6.switch_profile_id;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::ETHERNET_PROFILE_ID:
            sdk_key_val.val.ipv6.npp_attributes = (la_uint8_t)field.val.ipv6.ethernet_profile_id;
            sdk_key_val.mask.ipv6.npp_attributes = (la_uint8_t)field.mask.ipv6.ethernet_profile_id;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::L2_SERVICE_PORT_PROFILE_ID:
            sdk_key_val.val.ipv6.l2_service_port_attributes = (la_uint8_t)field.val.ipv6.l2_service_port_profile_id;
            sdk_key_val.mask.ipv6.l2_service_port_attributes = (la_uint8_t)field.mask.ipv6.l2_service_port_profile_id;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::LP_TYPE:
            sdk_key_val.val.ipv6.mac_lp_type = (la_uint8_t)field.val.ipv6.lp_type;
            sdk_key_val.mask.ipv6.mac_lp_type = (la_uint8_t)field.mask.ipv6.lp_type;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::IPV6_DIP:
            sdk_key_val.val.ipv6.dip.s_addr = field.val.ipv6.ipv6_dip.s_addr;
            sdk_key_val.mask.ipv6.dip.s_addr = field.mask.ipv6.ipv6_dip.s_addr;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::HOP_LIMIT:
            sdk_key_val.val.ipv6.hop_limit = field.val.ipv6.hop_limit;
            sdk_key_val.mask.ipv6.hop_limit = field.mask.ipv6.hop_limit;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::NEXT_HEADER:
            sdk_key_val.val.ipv6.next_header = field.val.ipv6.next_header;
            sdk_key_val.mask.ipv6.next_header = field.mask.ipv6.next_header;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::SPORT:
            sdk_key_val.val.ipv6.l4_ports.src_port = field.val.ipv6.sport;
            sdk_key_val.mask.ipv6.l4_ports.src_port = field.mask.ipv6.sport;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::DPORT:
            sdk_key_val.val.ipv6.l4_ports.dst_port = field.val.ipv6.dport;
            sdk_key_val.mask.ipv6.l4_ports.dst_port = field.mask.ipv6.dport;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::MY_MAC:
            sdk_key_val.val.ipv6.my_mac = field.val.ipv6.my_mac;
            sdk_key_val.mask.ipv6.my_mac = field.mask.ipv6.my_mac;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::IS_SVI:
            sdk_key_val.val.ipv6.is_svi = field.val.ipv6.is_svi;
            sdk_key_val.mask.ipv6.is_svi = field.mask.ipv6.is_svi;
            break;
        case la_control_plane_classifier::ipv6_field_type_e::HAS_VLAN_TAG:
            sdk_key_val.val.ipv6.has_vlan_tag = field.val.ipv6.has_vlan_tag;
            sdk_key_val.mask.ipv6.has_vlan_tag = field.mask.ipv6.has_vlan_tag;
            break;
        default:
            return LA_STATUS_EINVAL;
            break;
        }
    }
    sdk_key_val.val.ipv6.ip_not_first_fragment = 0;
    sdk_key_val.mask.ipv6.ip_not_first_fragment = 1;

    // In case of L3 force set my_mac and is_svi to dont care
    if (sdk_key_val.val.ipv6.mac_lp_type && sdk_key_val.mask.ipv6.mac_lp_type) {
        sdk_key_val.val.ipv6.my_mac = 0;
        sdk_key_val.mask.ipv6.my_mac = 0;
        sdk_key_val.val.ipv6.is_svi = 0;
        sdk_key_val.mask.ipv6.is_svi = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::convert_la_mac_key_to_sdk_mac_key(const la_control_plane_classifier::key& la_key_val,
                                                la_copc_base::copc_key_t& sdk_key_val)
{
    la_copc_base::copc_key_t mac_key_val = {.type = la_control_plane_classifier::type_e::MAC,
                                            .val = {.mac = {.mac_da = {.flat = 0},
                                                            .ether_type = 0,
                                                            .npp_attributes = 0,
                                                            .bd_attributes = 0,
                                                            .l2_service_port_attributes = 0,
                                                            .mac_lp_type = 0,
                                                            .my_mac = 0,
                                                            .is_svi = 0,
                                                            .has_vlan_tag = 0}},
                                            .mask = {.mac = {.mac_da = {.flat = 0},
                                                             .ether_type = 0,
                                                             .npp_attributes = 0,
                                                             .bd_attributes = 0,
                                                             .l2_service_port_attributes = 0,
                                                             .mac_lp_type = 0,
                                                             .my_mac = 0,
                                                             .is_svi = 0,
                                                             .has_vlan_tag = 0}}};
    sdk_key_val = mac_key_val;

    for (const auto field : la_key_val) {
        switch (field.type.mac) {
        case la_control_plane_classifier::mac_field_type_e::SWITCH_PROFILE_ID:
            sdk_key_val.val.mac.bd_attributes = (la_uint8_t)field.val.mac.switch_profile_id;
            sdk_key_val.mask.mac.bd_attributes = (la_uint8_t)field.mask.mac.switch_profile_id;
            break;
        case la_control_plane_classifier::mac_field_type_e::ETHERNET_PROFILE_ID:
            sdk_key_val.val.mac.npp_attributes = (la_uint8_t)field.val.mac.ethernet_profile_id;
            sdk_key_val.mask.mac.npp_attributes = (la_uint8_t)field.mask.mac.ethernet_profile_id;
            break;
        case la_control_plane_classifier::mac_field_type_e::L2_SERVICE_PORT_PROFILE_ID:
            sdk_key_val.val.mac.l2_service_port_attributes = (la_uint8_t)field.val.mac.l2_service_port_profile_id;
            sdk_key_val.mask.mac.l2_service_port_attributes = (la_uint8_t)field.mask.mac.l2_service_port_profile_id;
            break;
        case la_control_plane_classifier::mac_field_type_e::DA:
            sdk_key_val.val.mac.mac_da.flat = field.val.mac.da.flat;
            sdk_key_val.mask.mac.mac_da.flat = field.mask.mac.da.flat;
            break;
        case la_control_plane_classifier::mac_field_type_e::ETHERTYPE:
            sdk_key_val.val.mac.ether_type = field.val.mac.ethertype;
            sdk_key_val.mask.mac.ether_type = field.mask.mac.ethertype;
            break;
        case la_control_plane_classifier::mac_field_type_e::LP_TYPE:
            sdk_key_val.val.mac.mac_lp_type = (la_uint8_t)field.val.mac.lp_type;
            sdk_key_val.mask.mac.mac_lp_type = (la_uint8_t)field.mask.mac.lp_type;
            break;
        case la_control_plane_classifier::mac_field_type_e::MY_MAC:
            sdk_key_val.val.mac.my_mac = field.val.mac.my_mac;
            sdk_key_val.mask.mac.my_mac = field.mask.mac.my_mac;
            break;
        case la_control_plane_classifier::mac_field_type_e::IS_SVI:
            sdk_key_val.val.mac.is_svi = field.val.mac.is_svi;
            sdk_key_val.mask.mac.is_svi = field.mask.mac.is_svi;
            break;
        case la_control_plane_classifier::mac_field_type_e::HAS_VLAN_TAG:
            sdk_key_val.val.mac.has_vlan_tag = field.val.mac.has_vlan_tag;
            sdk_key_val.mask.mac.has_vlan_tag = field.mask.mac.has_vlan_tag;
            break;
        default:
            return LA_STATUS_EINVAL;
            break;
        }
    }

    // In case of L3 force set my_mac and is_svi to dont care
    if (sdk_key_val.val.mac.mac_lp_type && sdk_key_val.mask.mac.mac_lp_type) {
        sdk_key_val.val.mac.my_mac = 0;
        sdk_key_val.mask.mac.my_mac = 0;
        sdk_key_val.val.mac.is_svi = 0;
        sdk_key_val.mask.mac.is_svi = 0;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_copc_base::convert_la_key_to_sdk_key(const la_control_plane_classifier::key& la_key_val, copc_key_t& sdk_key_val)
{
    la_status status = LA_STATUS_SUCCESS;

    if (m_type == la_control_plane_classifier::type_e::IPV4) {
        status = convert_la_ipv4_key_to_sdk_ipv4_key(la_key_val, sdk_key_val);
    } else if (m_type == la_control_plane_classifier::type_e::IPV6) {
        status = convert_la_ipv6_key_to_sdk_ipv6_key(la_key_val, sdk_key_val);
    } else if (m_type == la_control_plane_classifier::type_e::MAC) {
        status = convert_la_mac_key_to_sdk_mac_key(la_key_val, sdk_key_val);
    } else {
        status = LA_STATUS_EINVAL;
    }

    return status;
}

} // namespace silicon_one
