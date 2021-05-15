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

#include <algorithm>
#include <vector>

#include "api/npu/la_l3_fec.h"
#include "api/npu/la_l3_port.h"
#include "api/npu/la_next_hop.h"
#include "api/system/la_spa_port.h"
#include "api/system/la_system_port.h"
#include "hld_utils.h"
#include "la_counter_set_impl.h"
#include "la_vrf_impl.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_lpm_bulk_types.h"
#include "npu/la_acl_impl.h"
#include "npu/la_ethernet_port_base.h"
#include "npu/la_ip_multicast_group_base.h"
#include "npu/la_l2_service_port_base.h"
#include "npu/la_prefix_object_base.h"
#include "resolution_utils.h"
#include "system/la_device_impl.h"

#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "la_strings.h"

#include "la_acl_delegate.h"
#include <sstream>

namespace silicon_one
{

la_vrf_impl::la_vrf_impl(const la_device_impl_wptr& device)
    : m_device(device), m_gid(0), m_ipv4_default_entry(nullptr), m_ipv6_default_entry(nullptr)
{
    m_urpf_allow_default = false;
}

la_vrf_impl::~la_vrf_impl()
{
}

la_object::object_type_e
la_vrf_impl::type() const
{
    return object_type_e::VRF;
}

la_object_id_t
la_vrf_impl::oid() const
{
    return m_oid;
}

std::string
la_vrf_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_vrf_impl(oid=" << m_oid << ")";
    return log_message.str();
}

const la_device*
la_vrf_impl::get_device() const
{
    return m_device.get();
}

la_vrf_gid_t
la_vrf_impl::get_gid() const
{
    return m_gid;
}

void
la_vrf_impl::populate_lpm_key(la_ipv4_addr_t addr, npl_ipv4_lpm_table_key_t& out_key) const
{
    out_key.l3_relay_id.id = m_gid;
    out_key.ipv4_ip_address_address = addr.s_addr;
}

void
la_vrf_impl::populate_lpm_key(la_ipv6_addr_t addr, npl_ipv6_lpm_table_key_t& out_key) const
{
    out_key.l3_relay_id.id = m_gid;
    out_key.ipv6_ip_address_address[0] = addr.q_addr[0];
    out_key.ipv6_ip_address_address[1] = addr.q_addr[1];
}

void
la_vrf_impl::update_em_entry_shadow(la_ipv4_addr_t addr, const la_l3_destination_wcptr& dest)
{
    m_ipv4_em_entries[addr] = dest;
}

void
la_vrf_impl::update_em_entry_shadow(la_ipv6_addr_t addr, const la_l3_destination_wcptr& dest)
{
    m_ipv6_em_entries[addr] = dest;
}

void
la_vrf_impl::delete_em_entry_shadow(la_ipv4_addr_t addr)
{
    m_ipv4_em_entries.erase(addr);
}

void
la_vrf_impl::delete_em_entry_shadow(la_ipv6_addr_t addr)
{
    m_ipv6_em_entries.erase(addr);
}

la_status
la_vrf_impl::get_route_info_from_em_shadow(la_ipv4_addr_t addr, la_ip_route_info& out_ip_route_info) const
{
    auto shadow_it = m_ipv4_em_entries.find(addr);

    if (shadow_it == m_ipv4_em_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_ip_route_info.is_host = false;
    out_ip_route_info.l3_dest = shadow_it->second.get();
    out_ip_route_info.user_data = 0;
    out_ip_route_info.latency_sensitive = true;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_route_info_from_em_shadow(la_ipv6_addr_t addr, la_ip_route_info& out_ip_route_info) const
{
    auto shadow_it = m_ipv6_em_entries.find(addr);

    if (shadow_it == m_ipv6_em_entries.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    out_ip_route_info.is_host = false;
    out_ip_route_info.l3_dest = shadow_it->second.get();
    out_ip_route_info.user_data = 0;
    out_ip_route_info.latency_sensitive = true;

    return LA_STATUS_SUCCESS;
}

bool
la_vrf_impl::is_em_eligible(const la_ipv4_prefix_t& prefix) const
{
    return false;
}

bool
la_vrf_impl::is_em_eligible(const la_ipv6_prefix_t& prefix) const
{
    // For IPv6, /128 routes can be placed in EM, all others are placed in LPM.
    if (prefix.length == 128) {
        return true;
    } else {
        return false;
    }
}

la_vrf_gid_t
la_vrf_impl::get_vrf_gid_from_key(const npl_ipv4_lpm_table_key_t& key) const
{
    la_vrf_gid_t vrf_gid = key.l3_relay_id.id;

    return vrf_gid;
}

la_vrf_gid_t
la_vrf_impl::get_vrf_gid_from_key(const npl_ipv6_lpm_table_key_t& key) const
{
    la_vrf_gid_t vrf_gid = key.l3_relay_id.id;

    return vrf_gid;
}

void
la_vrf_impl::set_default_entry(const npl_ipv4_lpm_table_entry_wptr_t& entry)
{
    m_ipv4_default_entry = entry;
}

void
la_vrf_impl::set_default_entry(const npl_ipv6_lpm_table_entry_wptr_t& entry)
{
    m_ipv6_default_entry = entry;
}

void
la_vrf_impl::get_default_entry(npl_ipv4_lpm_table_entry_wptr_t& out_entry) const
{
    out_entry = m_ipv4_default_entry;
}

void
la_vrf_impl::get_default_entry(npl_ipv6_lpm_table_entry_wptr_t& out_entry) const
{
    out_entry = m_ipv6_default_entry;
}

template <class _PrefixType>
bool
la_vrf_impl::is_prefix_valid(_PrefixType prefix) const
{
    _PrefixType dummy = prefix;
    apply_prefix_mask(dummy.addr, prefix.length);

    return (memcmp(&dummy.addr, &prefix.addr, sizeof(dummy.addr)) == 0);
}

bool
la_vrf_impl::is_prefix_multicast(la_ipv4_prefix_t prefix) const
{
    if (prefix.length < LA_IPV4_MC_PREFIX.length) {
        return false;
    }

    la_ipv4_prefix_t dummy = prefix;
    apply_prefix_mask(dummy.addr, LA_IPV4_MC_PREFIX.length);
    return (dummy.addr.s_addr == LA_IPV4_MC_PREFIX.addr.s_addr);
}

bool
la_vrf_impl::is_prefix_multicast(la_ipv6_prefix_t prefix) const
{
    if (prefix.length < LA_IPV6_MC_PREFIX.length) {
        return false;
    }

    la_ipv6_prefix_t dummy = prefix;
    apply_prefix_mask(dummy.addr, LA_IPV6_MC_PREFIX.length);
    return (dummy.addr.s_addr == LA_IPV6_MC_PREFIX.addr.s_addr);
}

la_status
la_vrf_impl::initialize(la_object_id_t oid, la_vrf_gid_t gid)
{
    m_oid = oid;
    m_gid = gid;
    npl_destination_t default_dest = {.val = la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION};
    npl_destination_t illegal_dip_dest = {.val = la_device_impl::LPM_ILLEGAL_DIP_DESTINATION};

    npl_destination_t drop_unmatched_mc_dest = {.val = DROP_UNMATCHED_MC_LPM_DESTINATION};

    // Create a catch-all entry for IPv4
    la_ipv4_prefix_t prefix_v4 = {.addr = {.s_addr = 0}, .length = 0};
    la_status status = add_lpm_entry(
        m_device->m_tables.ipv4_lpm_table, prefix_v4, default_dest, 0 /* user_data */, false /* latency_sensitive */);
    return_on_error(status);

    // Create a catch-all entry for IPv4 Multicast ranges
    status = add_lpm_entry(m_device->m_tables.ipv4_lpm_table,
                           LA_IPV4_MC_PREFIX,
                           drop_unmatched_mc_dest,
                           0 /* user_data */,
                           false /* latency_sensitive */);
    return_on_error(status);
    configure_implicit_mc_catch_all(LA_IPV4_MC_PREFIX, true /* Implicit default */);

    // TODO: change to 1 global entry instead of entry per VRF.
    la_ipv4_addr_t illegal_dip_v4 = {.s_addr = 0x0};
    status = add_em_entry(m_device->m_tables.ipv4_vrf_dip_em_table, illegal_dip_v4, illegal_dip_dest, nullptr /* l3_port */);
    return_on_error(status);

    // Create a catch-all entry for IPv6
    la_ipv6_prefix_t prefix_v6 = {.addr = {.s_addr = 0}, .length = 0};
    status = add_lpm_entry(
        m_device->m_tables.ipv6_lpm_table, prefix_v6, default_dest, 0 /* user_data */, false /* latency_sensitive */);
    return_on_error(status);

    // Create a catch-all entry for IPv6 Multicast ranges
    status = add_lpm_entry(m_device->m_tables.ipv6_lpm_table,
                           LA_IPV6_MC_PREFIX,
                           drop_unmatched_mc_dest,
                           0 /* user_data */,
                           false /* latency_sensitive */);
    return_on_error(status);
    configure_implicit_mc_catch_all(LA_IPV6_MC_PREFIX, true /* Implicit default */);

    // TODO: change to 1 global entry instead of entry per VRF.
    la_ipv6_addr_t illegal_dip_v6 = {.s_addr = 0x0};
    status = add_em_entry(m_device->m_tables.ipv6_vrf_dip_em_table, illegal_dip_v6, illegal_dip_dest, nullptr /* l3_port */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

template <class _TableType>
la_status
la_vrf_impl::remove_lpm_entry(const std::shared_ptr<_TableType>& table,
                              const typename _TableType::entry_wptr_type& entry,
                              bool clear_catch_all_entry)
{
    typename _TableType::key_type key = entry->key();
    size_t prefix_length = entry->length();

    if ((prefix_length != 0) || clear_catch_all_entry) {
        la_status status = table->erase(key, prefix_length);
        return_on_error(status);

    } else {

        typename _TableType::entry_wptr_type default_entry;
        get_default_entry(default_entry);

        typename _TableType::value_type default_value = default_entry->value();
        npl_destination_t default_dest = default_value.payloads.lpm_payload.destination;
        bool is_catch_all_entry_configured = (default_dest.val == la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION);

        if (is_catch_all_entry_configured) {

            // The entry with prefix 0 is the catch-all entry - don't remove it
            return LA_STATUS_ENOTFOUND;
        }

        // Removing the user-provided default entry - update with the catch-all entry

        typename _TableType::value_type new_value;
        new_value.payloads.lpm_payload.destination.val = la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION;

        la_status status = default_entry->update(new_value, 0 /* user_data */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _PrefixType>
la_status
la_vrf_impl::add_lpm_entry(const std::shared_ptr<_TableType>& table,
                           _PrefixType prefix,
                           npl_destination_t dest,
                           la_user_data_t user_data,
                           bool latency_sensitive)
{
    typename _TableType::key_type key;
    typename _TableType::value_type value;
    typename _TableType::entry_wptr_type entry;

    if (!is_prefix_valid(prefix)) {
        return LA_STATUS_EINVAL;
    }

    populate_lpm_key(prefix.addr, key);
    value.payloads.lpm_payload.destination = dest;

    if (prefix.length == 0) {
        typename _TableType::entry_wptr_type default_entry;
        get_default_entry(default_entry);

        // If default route is allowed under uRPF, then do not mark these routes as default
        if (!m_urpf_allow_default) {
            value.payloads.lpm_payload.destination.val |= DEFAULT_ROUTE_DESTINATION_BIT_MASK;
        }

        if (default_entry == nullptr) {
            la_status status = table->insert(key, prefix.length, value, user_data, latency_sensitive, entry);
            return_on_error(status);

            set_default_entry(entry);

            return LA_STATUS_SUCCESS;
        }

        typename _TableType::value_type default_value = default_entry->value();
        npl_destination_t default_dest = default_value.payloads.lpm_payload.destination;
        bool is_catch_all_entry_configured = (default_dest.val == la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION);

        if (!is_catch_all_entry_configured) {
            // user-provided default entry already exists
            return LA_STATUS_EEXIST;
        }

        la_status status = default_entry->update(value, user_data);

        return status;
    }

    la_status status = table->insert(key, prefix.length, value, user_data, latency_sensitive, entry);

    return status;
}

static void
populate_em_table_key(la_vrf_gid_t vrf_gid, la_ipv4_addr_t ip_addr, npl_ipv4_vrf_dip_em_table_key_t& out_em_key)
{
    out_em_key.l3_relay_id.id = vrf_gid;
    out_em_key.ip_address_31_20 = (ip_addr.s_addr >> 20) & 0xfff;
    out_em_key.ip_address_19_0 = ip_addr.s_addr & 0xfffff;
}

static void
populate_em_table_key(la_vrf_gid_t vrf_gid, la_ipv6_addr_t ip_addr, npl_ipv6_vrf_dip_em_table_key_t& out_em_key)
{
    out_em_key.l3_relay_id.id = vrf_gid;
    out_em_key.ipv6_ip_address_address[0] = ip_addr.q_addr[0];
    out_em_key.ipv6_ip_address_address[1] = ip_addr.q_addr[1];
}

template <class _TableType, class _AddrType>
la_status
la_vrf_impl::add_em_entry(const std::shared_ptr<_TableType>& table, _AddrType addr, const la_l3_destination_wcptr& destination)
{
    destination_id dest_id = get_destination_id(destination, RESOLUTION_STEP_FORWARD_L3);

    if (dest_id == DESTINATION_ID_INVALID) {
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    npl_destination_t dest{.val = dest_id.val};

    // For EM entries, to check uRPF L3 DLP needs to be programmed.
    la_l3_port* l3_port = nullptr;
    la_status status = get_l3_port(destination.get(), l3_port);

    status = add_em_entry(table, addr, dest, m_device->get_sptr(l3_port));
    return_on_error(status);

    update_em_entry_shadow(addr, destination);

    return status;
}

template <class _TableType, class _AddrType>
la_status
la_vrf_impl::add_em_entry(const std::shared_ptr<_TableType>& table,
                          _AddrType addr,
                          npl_destination_t dest,
                          const la_l3_port_wcptr& l3_port)
{
    typename _TableType::key_type key;
    typename _TableType::value_type value;
    typename _TableType::entry_wptr_type entry;

    npl_destination_prefix_lp_t l3_dlp_with_prefix;
    if (l3_port != nullptr) {
        uint64_t l3_dlp_gid = l3_port->get_gid();
        l3_dlp_with_prefix.msbs.l3_dlp_msbs.no_acls = get_l3_lp_msb(l3_dlp_gid);
        l3_dlp_with_prefix.lsbs.l3_dlp_lsbs = get_l3_lp_lsb(l3_dlp_gid);
        l3_dlp_with_prefix.prefix = NPL_LPM_COMPRESSED_DESTINATION_L3_DLP_SUBNET_PREFIX;
    } else {
        l3_dlp_with_prefix.unpack(LA_L3_PORT_GID_INVALID);
    }

    populate_em_table_key(m_gid, addr, key);
    value.payloads.em_lookup_result.result_type = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM;
    value.payloads.em_lookup_result.result.em_dest.dest = dest;
    value.payloads.em_lookup_result.result.em_dest.em_rpf_src = l3_dlp_with_prefix;

    la_status status = table->set(key, value, entry);

    return status;
}

template <class _TableType, class _AddrType>
la_status
la_vrf_impl::delete_em_entry(const std::shared_ptr<_TableType>& table, _AddrType addr)
{
    typename _TableType::key_type key;

    populate_em_table_key(m_gid, addr, key);

    la_status status = table->erase(key);

    return status;
}

template <class _TableType, class _AddrType>
la_status
la_vrf_impl::modify_em_entry(const std::shared_ptr<_TableType>& table,
                             const _AddrType& addr,
                             const la_l3_destination_wcptr& destination)
{
    typename _TableType::key_type key;
    typename _TableType::value_type value;
    typename _TableType::entry_wptr_type entry;

    // For EM entries, to check uRPF L3 DLP needs to be programmed.
    la_l3_port* l3_port = nullptr;
    la_status status = get_l3_port(destination.get(), l3_port);

    npl_destination_prefix_lp_t l3_dlp_with_prefix;
    if (l3_port != nullptr) {
        uint64_t l3_dlp_gid = l3_port->get_gid();
        l3_dlp_with_prefix.msbs.l3_dlp_msbs.no_acls = get_l3_lp_msb(l3_dlp_gid);
        l3_dlp_with_prefix.lsbs.l3_dlp_lsbs = get_l3_lp_lsb(l3_dlp_gid);
        l3_dlp_with_prefix.prefix = NPL_LPM_COMPRESSED_DESTINATION_L3_DLP_SUBNET_PREFIX;
    } else {
        l3_dlp_with_prefix.unpack(LA_L3_PORT_GID_INVALID);
    }

    populate_em_table_key(m_gid, addr, key);

    status = table->lookup(key, entry);
    return_on_error(status);

    npl_destination_t dest{.val = get_destination_id(destination, RESOLUTION_STEP_FORWARD_L3).val};
    value.payloads.em_lookup_result.result_type = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM;
    value.payloads.em_lookup_result.result.em_dest.dest = dest;
    value.payloads.em_lookup_result.result.em_dest.em_rpf_src = l3_dlp_with_prefix;

    status = entry->update(value);
    return_on_error(status);

    update_em_entry_shadow(addr, destination);

    return LA_STATUS_SUCCESS;
}

template <class _LpmTableType, class _EmTableType>
la_status
la_vrf_impl::clear_all_ip_routes(const std::shared_ptr<_LpmTableType>& lpm_table,
                                 const std::shared_ptr<_EmTableType>& em_table,
                                 bool clear_catch_all_entry)
{
    la_status status = clear_all_ip_lpm_routes(lpm_table, clear_catch_all_entry);
    return_on_error(status);

    status = clear_all_ip_em_routes(em_table);
    return_on_error(status);

    return status;
}

template <class _TableType>
la_status
la_vrf_impl::clear_all_ip_lpm_routes(const std::shared_ptr<_TableType>& table, bool clear_catch_all_entry)
{
    vector_alloc<typename _TableType::entry_wptr_type> entries_to_remove;

    for (const auto& entry_sptr : *table) {
        typename _TableType::key_type key = entry_sptr->key();
        la_vrf_gid_t vrf_gid = get_vrf_gid_from_key(key);

        if (vrf_gid != m_gid) {
            continue;
        }

        entries_to_remove.push_back(entry_sptr);
    }

    for (const auto& entry : entries_to_remove) {
        const la_l3_destination* l3_dest = nullptr;
        la_status is_user_added_route_status = get_l3_destination_from_table_entry(entry, l3_dest);

        la_status status = remove_lpm_entry(table, entry, clear_catch_all_entry);

        // remove_lpm_entry() returns ENOTFOUND in case the current entry is the catch-all-entry
        // and the caller didn't request to clear it. If this is the case then the error should be
        // ignored
        if (status == LA_STATUS_ENOTFOUND) {
            if ((entry->length() == 0) && !clear_catch_all_entry) {
                continue;
            }
        }

        return_on_error(status);

        if (is_user_added_route_status == LA_STATUS_SUCCESS) {
            status = uninstantiate_resolution_object(m_device->get_sptr(l3_dest), RESOLUTION_STEP_FORWARD_L3);
            return_on_error(status);

            m_device->remove_object_dependency(l3_dest, this);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::clear_all_ip_em_routes(npl_ipv4_vrf_dip_em_table_sptr_t v4_em_table)
{
    vector_alloc<la_ipv4_prefix_t> prefixes_to_remove;

    for (const auto& addr_dest : m_ipv4_em_entries) {
        la_ipv4_prefix_t prefix{.addr = addr_dest.first, .length = 32};
        prefixes_to_remove.push_back(prefix);
    }

    for (const auto& prefix : prefixes_to_remove) {
        la_status status = do_ipv4_route_action(la_route_entry_action_e::DELETE,
                                                prefix,
                                                nullptr,
                                                false /* user_data_set */,
                                                0,
                                                false /* latency_sensitive. don't care */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::clear_all_ip_em_routes(npl_ipv6_vrf_dip_em_table_sptr_t v6_em_table)
{
    vector_alloc<la_ipv6_prefix_t> prefixes_to_remove;

    for (const auto& addr_dest : m_ipv6_em_entries) {
        la_ipv6_prefix_t prefix{.addr = addr_dest.first, .length = 128};
        prefixes_to_remove.push_back(prefix);
    }

    for (const auto& prefix : prefixes_to_remove) {
        la_status status = do_ipv6_route_action(
            la_route_entry_action_e::DELETE, prefix, nullptr, false /* user_data_set */, 0, false /* latency_sensitive */);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class _EntryType>
la_status
la_vrf_impl::get_route_info_from_table_entry(weak_ptr_unsafe<_EntryType> entry, la_ip_route_info& out_ip_route_info) const
{
    lpm_destination_id lpm_dest_id(entry->value().payloads.lpm_payload.destination.val);

    if (lpm_dest_id.val == la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION) {
        // That's the catch-all entry - no route was configured for the given address
        return LA_STATUS_ENOTFOUND;
    }

    lpm_destination_id lpm_dest(lpm_dest_id.val);

    if (is_l3_lpm_destination(lpm_dest)) {
        out_ip_route_info.is_host = false;
        out_ip_route_info.l3_dest = m_device->m_l3_destinations[lpm_dest_id.val & ~DEFAULT_ROUTE_DESTINATION_BIT_MASK]
                                        .get(); // mapping is same regardless of defaultness
        out_ip_route_info.user_data = entry->user_data();
    } else {
        out_ip_route_info.is_host = true;
        out_ip_route_info.l3_dest = nullptr;
    }
    out_ip_route_info.latency_sensitive = entry->latency_sensitive();

    return LA_STATUS_SUCCESS;
}

template <class _EntryType>
la_status
la_vrf_impl::get_l3_destination_from_table_entry(weak_ptr_unsafe<_EntryType> entry, const la_l3_destination*& out_l3_dest) const
{
    la_ip_route_info ip_route_info{};
    la_status status = get_route_info_from_table_entry(entry, ip_route_info);

    return_on_error(status);

    if (ip_route_info.l3_dest == NULL) {
        return LA_STATUS_EUNKNOWN;
    }

    if (ip_route_info.is_host == true) {
        return LA_STATUS_ENOTFOUND;
    }

    out_l3_dest = ip_route_info.l3_dest;
    return LA_STATUS_SUCCESS;
}

template <class _LpmTableType, class _EmTableType, class _AddrType>
la_status
la_vrf_impl::get_route_info_from_addr(const std::shared_ptr<_LpmTableType>& lpm_table,
                                      const std::shared_ptr<_EmTableType>& em_table,
                                      _AddrType ip_addr,
                                      la_ip_route_info& out_ip_route_info) const
{
    la_status status = get_route_info_from_em_shadow(ip_addr, out_ip_route_info);
    if (status == LA_STATUS_SUCCESS) {
        return status;
    }

    if (status != LA_STATUS_ENOTFOUND) {
        return status;
    }

    typename _LpmTableType::key_type key;
    typename _LpmTableType::entry_wptr_type entry;

    populate_lpm_key(ip_addr, key);

    status = lpm_table->lookup(key, entry);
    if (status != LA_STATUS_SUCCESS) {
        return LA_STATUS_ENOTFOUND;
    }

    return get_route_info_from_table_entry(entry, out_ip_route_info);
}

template <class _LpmTableType, class _EmTableType, class _PrefixType>
la_status
la_vrf_impl::get_route_info_from_prefix(const std::shared_ptr<_LpmTableType>& lpm_table,
                                        const std::shared_ptr<_EmTableType>& em_table,
                                        _PrefixType prefix,
                                        la_ip_route_info& out_ip_route_info) const
{
    la_status status;
    if (is_em_eligible(prefix)) {
        status = get_route_info_from_em_shadow(prefix.addr, out_ip_route_info);
        if (status != LA_STATUS_ENOTFOUND) {
            return status;
        }
    }

    typename _LpmTableType::key_type key{};
    typename _LpmTableType::entry_wptr_type entry;

    populate_lpm_key(prefix.addr, key);
    status = lpm_table->find(key, prefix.length, entry);
    return_on_error(status);

    return get_route_info_from_table_entry(entry, out_ip_route_info);
}

la_status
la_vrf_impl::add_ipv4_route(la_ipv4_prefix_t prefix,
                            const la_l3_destination* destination,
                            la_user_data_t user_data,
                            bool latency_sensitive)
{
    start_api_call(
        "prefix=", prefix, "destination=", destination, "user_data=", user_data, "latency_sensitive=", latency_sensitive);

    return do_ipv4_route_action(la_route_entry_action_e::ADD,
                                prefix,
                                m_device->get_sptr(destination),
                                true /* user_data_set */,
                                user_data,
                                latency_sensitive);
}

la_status
la_vrf_impl::modify_ipv4_route(la_ipv4_prefix_t prefix, const la_l3_destination* destination)
{
    start_api_call("prefix=", prefix, "destination=", destination);

    return do_ipv4_route_action(la_route_entry_action_e::MODIFY,
                                prefix,
                                m_device->get_sptr(destination),
                                false /* user_data_set */,
                                0,
                                false /* latency_sensitive. don't care */);
}

la_status
la_vrf_impl::modify_ipv4_route(la_ipv4_prefix_t prefix, const la_l3_destination* destination, la_user_data_t user_data)
{
    start_api_call("prefix=", prefix, "destination=", destination, "user_data=", user_data);

    return do_ipv4_route_action(la_route_entry_action_e::MODIFY,
                                prefix,
                                m_device->get_sptr(destination),
                                true /* user_data_set */,
                                user_data,
                                false /* latency_sensitive. don't care  */);
}

la_status
la_vrf_impl::clear_all_ipv4_routes()
{
    start_api_call("");

    return clear_all_ip_routes(
        m_device->m_tables.ipv4_lpm_table, m_device->m_tables.ipv4_vrf_dip_em_table, false /* clear_catch_all_entry */);
}

la_status
la_vrf_impl::delete_ipv4_route(la_ipv4_prefix_t prefix)
{
    start_api_call("prefix=", prefix);

    return do_ipv4_route_action(
        la_route_entry_action_e::DELETE, prefix, nullptr, false /* user_data_set */, 0, false /* latency_sensitive. don't care  */);
}

la_status
la_vrf_impl::get_lpm_destination_from_l3_destination(const la_l3_destination_wcptr& destination,
                                                     npl_destination_t& out_lpm_dest) const
{
    lpm_destination_id lpm_dest_id = silicon_one::get_lpm_destination_id(destination, RESOLUTION_STEP_FORWARD_L3);

    if (lpm_dest_id == LPM_DESTINATION_ID_INVALID) {
        log_err(HLD, "la_vrf_impl::translate_destination lpm_dest_id Invalid\n");
        return LA_STATUS_ENOTIMPLEMENTED;
    }

    out_lpm_dest = {.val = lpm_dest_id.val};
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::is_destination_resolution_forwarding_supported(const la_l3_destination_wcptr& destination)
{
    if (destination == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (destination->type() == object_type_e::PREFIX_OBJECT) {
        const auto& pfx_obj = destination.weak_ptr_static_cast<const la_prefix_object_base>();
        if (!pfx_obj->is_resolution_forwarding_supported()) {
            return LA_STATUS_EINVAL;
        }
    }

    return LA_STATUS_SUCCESS;
}

template <class _LpmTableType, class _EmTableType, class _RouteEntry>
la_status
la_vrf_impl::common_pre_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                                    const std::shared_ptr<_EmTableType>& em_table,
                                    _RouteEntry& route_entry,
                                    npl_destination_t& out_lpm_dest,
                                    la_l3_destination_wcptr& out_old_destination,
                                    la_user_data_t& out_old_user_data)
{
    la_status status = LA_STATUS_SUCCESS;
    la_ip_route_info ri{};

    out_old_destination = nullptr;

    la_l3_destination_wcptr destination_wptr = m_device->get_sptr(route_entry.destination);

    switch (route_entry.action) {
    case la_route_entry_action_e::ADD:
        status = is_destination_resolution_forwarding_supported(destination_wptr);
        return_on_error(status);
        status = instantiate_resolution_object(destination_wptr, RESOLUTION_STEP_FORWARD_L3);
        return_on_error(status);
        status = get_lpm_destination_from_l3_destination(destination_wptr, out_lpm_dest);
        break;

    case la_route_entry_action_e::DELETE:
        route_entry.destination = nullptr;
        status = get_route_info_from_prefix(lpm_table, em_table, route_entry.prefix, ri);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }

        out_old_destination = m_device->get_sptr(ri.l3_dest);
        return status;

    case la_route_entry_action_e::MODIFY:
        status = is_destination_resolution_forwarding_supported(destination_wptr);
        return_on_error(status);
        status = instantiate_resolution_object(destination_wptr, RESOLUTION_STEP_FORWARD_L3);
        return_on_error(status);
        status = get_lpm_destination_from_l3_destination(destination_wptr, out_lpm_dest);
        if (status != LA_STATUS_SUCCESS) {
            break;
        }

        status = get_route_info_from_prefix(lpm_table, em_table, route_entry.prefix, ri);
        if (status != LA_STATUS_SUCCESS) {
            break;
        }

        out_old_destination = m_device->get_sptr(ri.l3_dest);
        out_old_user_data = ri.user_data;
        break;
    }

    if (status != LA_STATUS_SUCCESS) {
        la_status rollback_status = uninstantiate_resolution_object(destination_wptr, RESOLUTION_STEP_FORWARD_L3);
        if (rollback_status != LA_STATUS_SUCCESS) {
            return LA_STATUS_EDOUBLE_FAULT;
        }
    }

    return status;
}

template <class _RouteEntry>
void
la_vrf_impl::common_post_bulk_update(_RouteEntry& route_entry, const la_l3_destination_wcptr& old_destination)
{
    la_status status;

    switch (route_entry.action) {
    case la_route_entry_action_e::ADD:
        m_device->add_object_dependency(route_entry.destination, this);
        return;

    case la_route_entry_action_e::DELETE:
        if (!old_destination) {
            return;
        }
        status = uninstantiate_resolution_object(old_destination, RESOLUTION_STEP_FORWARD_L3);
        dassert_crit(status == LA_STATUS_SUCCESS);
        m_device->remove_object_dependency(old_destination, this);
        return;

    case la_route_entry_action_e::MODIFY:
        if (route_entry.destination) {
            m_device->add_object_dependency(route_entry.destination, this);
        }
        if (old_destination) {
            status = uninstantiate_resolution_object(old_destination, RESOLUTION_STEP_FORWARD_L3);
            dassert_crit(status == LA_STATUS_SUCCESS);
            m_device->remove_object_dependency(old_destination, this);
        }
        return;
    }
}

template <class _LpmTableType, class _RouteEntry>
la_status
la_vrf_impl::do_pre_bulk_default_route(const std::shared_ptr<_LpmTableType>& lpm_table,
                                       _RouteEntry& route_entry,
                                       npl_destination_t& out_lpm_dest)
{
    typename _LpmTableType::entry_wptr_type default_entry;
    get_default_entry(default_entry);

    // If default route is allowed under uRPF, then do not mark these routes as default
    if (!m_urpf_allow_default) {
        out_lpm_dest.val |= DEFAULT_ROUTE_DESTINATION_BIT_MASK;
    }

    // Add the default entry.
    if (default_entry == nullptr) {
        if (route_entry.action == la_route_entry_action_e::ADD) {
            return LA_STATUS_SUCCESS;
        }
        return LA_STATUS_ENOTFOUND;
    }

    typename _LpmTableType::value_type default_value = default_entry->value();
    npl_destination_t default_dest = default_value.payloads.lpm_payload.destination;
    bool is_catch_all_entry_configured = (default_dest.val == la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION);

    switch (route_entry.action) {
    case la_route_entry_action_e::ADD:
        if (!is_catch_all_entry_configured) {
            // user-provided default entry already exists
            return LA_STATUS_EEXIST;
        }

        route_entry.action = la_route_entry_action_e::MODIFY;
        break;

    case la_route_entry_action_e::MODIFY:
        if (is_catch_all_entry_configured) {
            return LA_STATUS_ENOTFOUND;
        }
        break;

    case la_route_entry_action_e::DELETE:
        if (is_catch_all_entry_configured) {

            // The entry with prefix 0 is the catch-all entry - don't remove it
            return LA_STATUS_ENOTFOUND;
        }

        // Removing the user-provided default entry - update with the catch-all entry
        out_lpm_dest.val = la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION;

        route_entry.user_data = 0;
        route_entry.is_user_data_set = true;
        route_entry.action = la_route_entry_action_e::MODIFY;

        break;
    }

    return LA_STATUS_SUCCESS;
}

template <class _LpmTableType, class _RouteEntry>
void
la_vrf_impl::do_post_bulk_default_route(const std::shared_ptr<_LpmTableType>& lpm_table, _RouteEntry& route_entry)
{
    typename _LpmTableType::entry_wptr_type default_entry;

    switch (route_entry.action) {
    case la_route_entry_action_e::ADD:
        get_default_entry(default_entry);

        if (default_entry == nullptr) {
            typename _LpmTableType::key_type key{};
            typename _LpmTableType::entry_wptr_type entry;

            populate_lpm_key(route_entry.prefix.addr, key);
            la_status status = lpm_table->find(key, route_entry.prefix.length, entry);
            dassert_crit(status == LA_STATUS_SUCCESS);

            set_default_entry(entry);
        }
        break;

    default:
        break;
    }
}

template <class _LpmTableType, class _EmTableType, class _RouteEntry>
la_status
la_vrf_impl::do_lpm_pre_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                                    const std::shared_ptr<_EmTableType>& em_table,
                                    _RouteEntry& route_entry,
                                    npl_destination_t& out_lpm_dest,
                                    la_l3_destination_wcptr& old_destination,
                                    la_user_data_t& out_old_user_data)
{
    la_status status = common_pre_bulk_update(lpm_table, em_table, route_entry, out_lpm_dest, old_destination, out_old_user_data);
    return_on_error(status);

    if (route_entry.prefix.length == 0) {
        status = do_pre_bulk_default_route(lpm_table, route_entry, out_lpm_dest);
        if (status != LA_STATUS_SUCCESS) {
            do_lpm_bulk_update_failed(route_entry);
        }
    }

    return status;
}

template <class _LpmTableType, class _RouteEntry>
void
la_vrf_impl::do_lpm_post_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                                     _RouteEntry& route_entry,
                                     const la_l3_destination_wcptr& old_destination)
{
    common_post_bulk_update(route_entry, old_destination);
    if (route_entry.prefix.length == 0) {
        do_post_bulk_default_route(lpm_table, route_entry);
    }
}

template <class _RouteEntry>
void
la_vrf_impl::do_lpm_bulk_update_failed(_RouteEntry& route_entry)
{
    la_status status;

    switch (route_entry.action) {
    case la_route_entry_action_e::ADD:
    case la_route_entry_action_e::MODIFY:
        if ((route_entry.prefix.length == 0) && !route_entry.destination) {
            break;
        }

        status = uninstantiate_resolution_object(m_device->get_sptr(route_entry.destination), RESOLUTION_STEP_FORWARD_L3);
        dassert_crit(status == LA_STATUS_SUCCESS);
        break;

    case la_route_entry_action_e::DELETE:
        break;
    }
}

npl_action_e
la_vrf_impl::translate_route_entry_action(const la_route_entry_action_e action) const
{
    npl_action_e ret_action = npl_action_e::ADD;

    switch (action) {
    case la_route_entry_action_e::ADD:
        ret_action = npl_action_e::ADD;
        break;

    case la_route_entry_action_e::DELETE:
        ret_action = npl_action_e::DELETE;
        break;

    case la_route_entry_action_e::MODIFY:
        ret_action = npl_action_e::MODIFY;
        break;
    }

    return ret_action;
}

template <class _LpmTableType, class _EmTableType, class _RouteEntryVec, class _LpmBulkEntries>
la_status
la_vrf_impl::lpm_pre_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                                  const std::shared_ptr<_EmTableType>& em_table,
                                  _RouteEntryVec& route_entry_vec,
                                  _LpmBulkEntries& lpm_bulk_entries,
                                  const uint32_t start_batch,
                                  const uint32_t end_batch,
                                  size_t& out_count_success)
{
    la_status status = LA_STATUS_SUCCESS;
    npl_destination_t lpm_dest;
    la_user_data_t old_user_data = 0;
    uint32_t count = 0;
    typename _LpmTableType::key_type key{};
    la_l3_destination_wcptr old_destination;

    for (uint32_t i = start_batch; i < end_batch; i++) {
        typename _LpmTableType::value_type value;

        lpm_dest.val = 0;

        status = do_lpm_pre_bulk_update(lpm_table, em_table, route_entry_vec[i], lpm_dest, old_destination, old_user_data);
        if (status != LA_STATUS_SUCCESS) {
            out_count_success = i - start_batch;
            return status;
        }

        count = i - start_batch;
        populate_lpm_key(route_entry_vec[i].prefix.addr, key);
        value.payloads.lpm_payload.destination = lpm_dest;
        lpm_bulk_entries[count].action = translate_route_entry_action(route_entry_vec[i].action);
        lpm_bulk_entries[count].key = key;
        lpm_bulk_entries[count].length = route_entry_vec[i].prefix.length;
        lpm_bulk_entries[count].value = value;
        lpm_bulk_entries[count].user_data = (route_entry_vec[i].is_user_data_set) ? route_entry_vec[i].user_data : old_user_data;
        lpm_bulk_entries[count].latency_sensitive = route_entry_vec[i].latency_sensitive;
        m_bulk_old_destinations[count] = old_destination;
    }

    out_count_success = end_batch - start_batch;
    return status;
}

template <class _LpmTableType, class _RouteEntryVec, class _LpmBulkEntries>
void
la_vrf_impl::lpm_post_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                                   _RouteEntryVec& route_entry_vec,
                                   _LpmBulkEntries& lpm_bulk_entries,
                                   const uint32_t start_batch,
                                   const uint32_t end_batch)
{
    uint32_t count = 0;

    for (uint32_t i = start_batch; i < end_batch; i++) {
        count = i - start_batch;

        log_debug(HLD,
                  "la_vrf_impl(oid=%zu)::lpm_post_bulk_updates (prefix=%s action=%u destination=%s old_destination=%s)",
                  m_oid,
                  silicon_one::to_string(route_entry_vec[i].prefix).c_str(),
                  to_utype(route_entry_vec[i].action),
                  route_entry_vec[i].destination ? silicon_one::to_string(route_entry_vec[i].destination).c_str() : "",
                  m_bulk_old_destinations[count] ? silicon_one::to_string(m_bulk_old_destinations[count]).c_str() : "");
        do_lpm_post_bulk_update(lpm_table, route_entry_vec[i], m_bulk_old_destinations[count]);
    }
}

template <class _RouteEntryVec>
void
la_vrf_impl::lpm_bulk_updates_failed(_RouteEntryVec& route_entry_vec,
                                     const uint32_t start_batch,
                                     const size_t count_success,
                                     const size_t pre_count_success)
{
    for (uint32_t i = start_batch + count_success; i < start_batch + pre_count_success; i++) {
        log_err(HLD,
                "la_vrf_impl(oid=%zu)::lpm_bulk_updates_failed (prefix=%s action=%u destination=%s)",
                m_oid,
                silicon_one::to_string(route_entry_vec[i].prefix).c_str(),
                to_utype(route_entry_vec[i].action),
                route_entry_vec[i].destination ? silicon_one::to_string(route_entry_vec[i].destination).c_str() : "");
        do_lpm_bulk_update_failed(route_entry_vec[i]);
    }
}

template <class _LpmTableType, class _EmTableType, class _RouteEntryVec, class _LpmBulkEntries>
la_status
la_vrf_impl::ip_lpm_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                                 const std::shared_ptr<_EmTableType>& em_table,
                                 _RouteEntryVec& route_entry_vec,
                                 _LpmBulkEntries& lpm_bulk_entries,
                                 const uint32_t start_batch,
                                 const uint32_t end_batch,
                                 size_t& out_count_success)
{
    la_status last_status = LA_STATUS_SUCCESS;
    la_status status = LA_STATUS_SUCCESS;
    size_t pre_count_success = 0;
    size_t count_success = 0;
    out_count_success = 0;

    lpm_bulk_entries.resize(end_batch - start_batch);
    m_bulk_old_destinations.resize(end_batch - start_batch);
    status
        = lpm_pre_bulk_updates(lpm_table, em_table, route_entry_vec, lpm_bulk_entries, start_batch, end_batch, pre_count_success);
    last_status = (status != LA_STATUS_SUCCESS) ? status : last_status;

    lpm_bulk_entries.resize(pre_count_success);
    status = lpm_table->bulk_updates(lpm_bulk_entries, count_success);
    last_status = (status != LA_STATUS_SUCCESS) ? status : last_status;

    lpm_post_bulk_updates(lpm_table, route_entry_vec, lpm_bulk_entries, start_batch, start_batch + count_success);
    lpm_bulk_updates_failed(route_entry_vec, start_batch, count_success, pre_count_success);

    out_count_success += count_success;
    return last_status;
}

// Currently em programming code is not batched.
template <class _LpmTableType, class _EmTableType, class _RouteEntryVec>
la_status
la_vrf_impl::ip_em_bulk_update(const std::shared_ptr<_LpmTableType>& lpm_table,
                               const std::shared_ptr<_EmTableType>& em_table,
                               _RouteEntryVec& route_entry_vec,
                               const uint32_t index,
                               size_t& out_count_success)
{
    la_status status;
    uint32_t i = index;
    npl_destination_t lpm_dest;
    la_l3_destination_wcptr old_destination;
    la_user_data_t old_user_data;
    out_count_success = 0;

    lpm_dest.val = 0;

    status = common_pre_bulk_update(lpm_table, em_table, route_entry_vec[i], lpm_dest, old_destination, old_user_data);
    if (status != LA_STATUS_SUCCESS) {
        return status;
    }

    switch (route_entry_vec[i].action) {
    case la_route_entry_action_e::ADD:
        status = add_em_entry(em_table, route_entry_vec[i].prefix.addr, m_device->get_sptr(route_entry_vec[i].destination));
        break;

    case la_route_entry_action_e::MODIFY:
        status = modify_em_entry(em_table, route_entry_vec[i].prefix.addr, m_device->get_sptr(route_entry_vec[i].destination));
        break;

    case la_route_entry_action_e::DELETE:
        status = delete_em_entry(em_table, route_entry_vec[i].prefix.addr);
        if (status != LA_STATUS_SUCCESS) {
            break;
        }
        delete_em_entry_shadow(route_entry_vec[i].prefix.addr);
        break;
    }

    if (status != LA_STATUS_SUCCESS) {
        do_lpm_bulk_update_failed(route_entry_vec[i]);
        return status;
    }

    common_post_bulk_update(route_entry_vec[i], old_destination);
    out_count_success++;
    return LA_STATUS_SUCCESS;
}

size_t
la_vrf_impl::hash_ipv4_prefix::operator()(const la_ipv4_prefix_t& pfx) const
{
    return std::hash<la_uint32_t>()(pfx.addr.s_addr);
}

size_t
la_vrf_impl::hash_ipv6_prefix::operator()(const la_ipv6_prefix_t& pfx) const
{
    return std::hash<la_uint64_t>()(pfx.addr.q_addr[0]) ^ std::hash<la_uint64_t>()(pfx.addr.q_addr[1]);
}

template <class _LpmTableType, class _EmTableType, class _RouteEntryVec, class _LpmBulkEntries, class _LpmBulkPfx>
la_status
la_vrf_impl::ip_route_bulk_updates(const std::shared_ptr<_LpmTableType>& lpm_table,
                                   const std::shared_ptr<_EmTableType>& em_table,
                                   _RouteEntryVec& route_entry_vec,
                                   _LpmBulkEntries& lpm_bulk_entries,
                                   _LpmBulkPfx& lpm_bulk_pfx,
                                   size_t& out_count_success)
{
    uint32_t start_batch = 0;
    uint32_t cur = 0;
    size_t num_actions = route_entry_vec.size();
    la_status status = LA_STATUS_SUCCESS;
    la_route_entry_action_e action;
    bool is_add_action = false;

    out_count_success = 0;
    lpm_bulk_pfx.clear();
    lpm_bulk_pfx.reserve(num_actions);

    // Check if all actions are same and there is no duplicate prefix in bulk update.
    for (cur = 0; cur < num_actions; cur++) {
        const auto& current_entry = route_entry_vec[cur];
        if (cur == 0) {
            action = current_entry.action;
            if (action == la_route_entry_action_e::ADD) {
                is_add_action = true;
            }
        }

        if (current_entry.action != action) {
            log_debug(HLD,
                      "la_vrf_impl(oid=%zu)::ip_route_bulk_updates (prefix=%s action=%u bulk_action=%u) mismatch",
                      m_oid,
                      silicon_one::to_string(current_entry.prefix).c_str(),
                      to_utype(current_entry.action),
                      to_utype(action));
            return LA_STATUS_SUCCESS;
        }

        auto ret = lpm_bulk_pfx.insert(current_entry.prefix);
        if (!ret.second) {
            log_debug(HLD,
                      "la_vrf_impl(oid=%zu)::ip_route_bulk_updates (prefix=%s action=%u) duplicate prefix",
                      m_oid,
                      silicon_one::to_string(current_entry.prefix).c_str(),
                      to_utype(current_entry.action));
            return LA_STATUS_SUCCESS;
        }
    }

    for (cur = 0; cur < num_actions; cur++) {
        // Create a batch for all routes before the prefix which need to go in em.
        const auto& current_entry = route_entry_vec[cur];
        if (!is_prefix_valid(current_entry.prefix) || is_prefix_multicast(current_entry.prefix)) {
            status = LA_STATUS_EINVAL;
            break;
        }

        if (is_add_action) {
            la_ip_route_info ri{};
            la_status routing_status = get_route_info_from_prefix(lpm_table, em_table, current_entry.prefix, ri);
            if (routing_status == LA_STATUS_SUCCESS) {
                status = LA_STATUS_EEXIST;
                break;
            }
        }

        bool is_em = is_em_eligible(current_entry.prefix);
        if (is_em) {
            // Program lpm bulk routes before em prefix.
            if (start_batch < cur) {
                size_t successful_lpm_routes;
                status = ip_lpm_bulk_updates(
                    lpm_table, em_table, route_entry_vec, lpm_bulk_entries, start_batch, cur, successful_lpm_routes);
                out_count_success += successful_lpm_routes;
                if (status != LA_STATUS_SUCCESS) {
                    break;
                }
            }

            log_debug(HLD,
                      "la_vrf_impl(oid=%zu)::%s prefix=%s database=EM",
                      m_oid,
                      __func__,
                      silicon_one::to_string(current_entry.prefix).c_str());

            // Program em route.
            size_t successful_em_routes;
            status = ip_em_bulk_update(lpm_table, em_table, route_entry_vec, cur, successful_em_routes);
            out_count_success += successful_em_routes;
            start_batch = cur + 1;
            if (status != LA_STATUS_SUCCESS) {
                break;
            }
        } else {
            log_debug(HLD,
                      "la_vrf_impl(oid=%zu)::%s prefix=%s latency_sensitive=%d database=LPM",
                      m_oid,
                      __func__,
                      silicon_one::to_string(current_entry.prefix).c_str(),
                      current_entry.latency_sensitive);
        }
    }

    if (status == LA_STATUS_SUCCESS) {
        if (start_batch < cur) {
            size_t successful_lpm_routes;
            status = ip_lpm_bulk_updates(
                lpm_table, em_table, route_entry_vec, lpm_bulk_entries, start_batch, cur, successful_lpm_routes);
            out_count_success += successful_lpm_routes;
        }
    }

    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD,
                "la_vrf_impl::ip_route_bulk_updates done: size=%zu, out_count_success=%zu, status=%s",
                num_actions,
                out_count_success,
                la_status2str(status).c_str());
        // EM error is for the specific route so return that to the user.
        // LPM error is during bulk programming which can be for any prefix in bulk.
        // LPM Prefix programming might succeed if tried one by one user.
    } else {
        log_debug(HLD, "la_vrf_impl::ip_route_bulk_updates done: size=%zu, out_count_success=%zu", num_actions, out_count_success);
    }

    if (out_count_success != 0) {
        return LA_STATUS_SUCCESS;
    }

    return status;
}

la_status
la_vrf_impl::ipv4_route_bulk_updates(la_ipv4_route_entry_parameters_vec route_entry_vec, size_t& out_count_success)
{
    start_api_call("count=", route_entry_vec.size());

    for (auto& route_entry : route_entry_vec) {
        // For convergence performance we log the Bulk update entries directly instead of using standard
        // API logging via start_api_call() which uses expensive std::stringstream and __cxa_demangle for
        // data type logging.
        log_debug(API,
                  route_entry_api_log_format,
                  silicon_one::to_string(route_entry.action).c_str(),
                  silicon_one::to_string(route_entry.prefix.addr).c_str(),
                  route_entry.prefix.length,
                  route_entry.destination ? silicon_one::to_string(route_entry.destination).c_str() : "nullptr",
                  silicon_one::to_string(route_entry.latency_sensitive).c_str());
    }

    la_status status = ip_route_bulk_updates(m_device->m_tables.ipv4_lpm_table,
                                             m_device->m_tables.ipv4_vrf_dip_em_table,
                                             route_entry_vec,
                                             m_ipv4_bulk_entries_vec,
                                             m_ipv4_bulk_prefix_set,
                                             out_count_success);

    if (status != LA_STATUS_SUCCESS) {
        log_info(API,
                 "la_vrf_impl::ipv4_route_bulk_updates done: size=%zu, out_count_success=%zu, status=%s",
                 route_entry_vec.size(),
                 out_count_success,
                 la_status2str(status).c_str());
    } else {
        log_info(API,
                 "la_vrf_impl::ipv4_route_bulk_updates done: size=%zu, out_count_success=%zu",
                 route_entry_vec.size(),
                 out_count_success);
    }

    // If out_count_success is 0, then try to insert first route to make progress in bulk.
    if ((status == LA_STATUS_SUCCESS) && (route_entry_vec.size() > 1) && (out_count_success == 0)) {
        switch (route_entry_vec[0].action) {
        case la_route_entry_action_e::ADD:
            status = add_ipv4_route(route_entry_vec[0].prefix,
                                    route_entry_vec[0].destination,
                                    route_entry_vec[0].user_data,
                                    route_entry_vec[0].latency_sensitive);
            break;

        case la_route_entry_action_e::MODIFY:
            if (route_entry_vec[0].is_user_data_set) {
                status = modify_ipv4_route(route_entry_vec[0].prefix, route_entry_vec[0].destination, route_entry_vec[0].user_data);
            } else {
                status = modify_ipv4_route(route_entry_vec[0].prefix, route_entry_vec[0].destination);
            }
            break;

        case la_route_entry_action_e::DELETE:
            status = delete_ipv4_route(route_entry_vec[0].prefix);
            break;
        }

        if (status == LA_STATUS_SUCCESS) {
            out_count_success++;
        }
    }

    return status;
}

la_status
la_vrf_impl::do_ipv4_route_action(const la_route_entry_action_e action,
                                  const la_ipv4_prefix_t& prefix,
                                  const la_l3_destination_wcptr& destination,
                                  const bool is_user_data_set,
                                  const la_user_data_t user_data,
                                  bool latency_sensitive)
{
    la_ipv4_route_entry_parameters_vec route_entry_vec(1);
    size_t dummy_count_success;

    route_entry_vec[0].action = action;
    route_entry_vec[0].prefix = prefix;
    route_entry_vec[0].destination = destination.get();
    route_entry_vec[0].is_user_data_set = is_user_data_set;
    route_entry_vec[0].user_data = user_data;
    route_entry_vec[0].latency_sensitive = latency_sensitive;

    return ip_route_bulk_updates(m_device->m_tables.ipv4_lpm_table,
                                 m_device->m_tables.ipv4_vrf_dip_em_table,
                                 route_entry_vec,
                                 m_ipv4_bulk_entries_vec,
                                 m_ipv4_bulk_prefix_set,
                                 dummy_count_success);
}

la_status
la_vrf_impl::get_ipv4_route(la_ipv4_addr_t ip_addr, la_ip_route_info& out_ip_route_info) const
{
    start_api_getter_call();

    return get_route_info_from_addr(
        m_device->m_tables.ipv4_lpm_table, m_device->m_tables.ipv4_vrf_dip_em_table, ip_addr, out_ip_route_info);
}

la_status
la_vrf_impl::delete_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr)
{
    start_api_call("saddr=", saddr, "gaddr=", gaddr);

    return do_delete_ipv4_multicast_route(saddr, gaddr);
}

la_status
la_vrf_impl::do_delete_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr)
{
    ipv4_mc_route_map_key_t map_key = ipv4_mc_route_map_key_t(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(map_key);
    if (it == m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    la_status status;
    const auto& desc = it->second;

    // unregister this route with the multicast group
    const auto& mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    status = mcg_base->unregister_mc_ipv4_vrf_route(m_device->get_sptr(this), saddr, gaddr);
    return_on_error(status);

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);
        npl_ipv4_vrf_dip_em_table_key_t key;

        populate_em_table_key(m_gid, gaddr, key);

        status = table->erase(key);
    } else {
        const auto& table(m_device->m_tables.ipv4_vrf_s_g_table);
        npl_ipv4_vrf_s_g_table_key_t key;

        key.l3_relay_id.id = m_gid;
        key.sip = saddr.s_addr;
        key.dip_27_20_ = (gaddr.s_addr >> 20) & 0xff;
        key.dip_19_0_ = gaddr.s_addr & 0xfffff;

        status = table->erase(key);
    }

    return_on_error(status);

    status = teardown_mc_route_counter(desc.counter);
    return_on_error(status);

    m_device->remove_object_dependency(desc.mcg, this);
    if (desc.rpf != nullptr) {
        m_device->remove_object_dependency(desc.rpf, this);
    }

    if (desc.counter != nullptr) {
        m_device->remove_object_dependency(desc.counter, this);
    }

    m_ipv4_mc_route_desc_map.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::clear_all_ipv4_multicast_routes()
{
    start_api_call("");

    auto temp = m_ipv4_mc_route_desc_map;

    for (auto temp_it : temp) {
        auto key = temp_it.first;
        la_ipv4_addr_t saddr = key.saddr;
        la_ipv4_addr_t gaddr = key.gaddr;

        la_status status = do_delete_ipv4_multicast_route(saddr, gaddr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

static void
populate_mc_result_payload(const la_ip_multicast_group_wcptr& mcg,
                           const la_l3_port_wcptr& rpf,
                           bool punt_on_rpf_fail,
                           bool punt_and_forward,
                           const bool use_rpfid,
                           const la_uint_t rpfid,
                           npl_ip_mc_result_payload_t& out_payload,
                           bool enable_rpf_check)
{
    const auto& mcg_base = mcg.weak_ptr_static_cast<const la_ip_multicast_group_base>();

    out_payload.global_mcid.id = mcg->get_gid();
    out_payload.local_mcid.id = mcg_base->get_local_mcid();
    out_payload.punt_and_fwd = punt_and_forward ? 1 : 0;
    out_payload.punt_on_rpf_fail = punt_on_rpf_fail ? 1 : 0;
    out_payload.rpf_destination.enable_mc_rpf = enable_rpf_check ? 1 : 0;

    if (!use_rpfid) {
        if ((rpf != nullptr)) {
            out_payload.rpf_destination.rpf_id_or_lp_id.rpf_id = rpf->get_gid();
        } else {
            // set invalid rpfid
            out_payload.rpf_destination.rpf_id_or_lp_id.rpf_id = rpfid;
        }

    } else {
        out_payload.rpf_destination.rpf_id_or_lp_id.rpf_id = rpfid;
    }
}

la_status
la_vrf_impl::add_to_ipv4_g_table(la_ipv4_addr_t gaddr,
                                 const la_ip_multicast_group_wcptr& mcg,
                                 const la_l3_port_wcptr& rpf,
                                 bool punt_and_forward,
                                 const bool use_rpfid,
                                 const la_uint_t rpfid,
                                 bool enable_rpf_check)
{
    const auto& table(m_device->m_tables.ipv4_vrf_dip_em_table);
    npl_ipv4_vrf_dip_em_table_key_t key;
    npl_ipv4_vrf_dip_em_table_value_t value;
    npl_ipv4_vrf_dip_em_table_entry_wptr_t entry;

    populate_em_table_key(m_gid, gaddr, key);
    value.action = NPL_IPV4_VRF_DIP_EM_TABLE_ACTION_WRITE;
    populate_mc_result_payload(mcg,
                               rpf,
                               false /* punt_on_rpf_fail only applies in S,G case as SIP is don't-care */,
                               punt_and_forward,
                               use_rpfid,
                               rpfid,
                               value.payloads.em_lookup_result.result.mc_result,
                               enable_rpf_check);

    value.payloads.em_lookup_result.result_type = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM;

    la_status status = table->set(key, value, entry);

    return status;
}

la_status
la_vrf_impl::add_to_ipv4_s_g_table(la_ipv4_addr_t saddr,
                                   la_ipv4_addr_t gaddr,
                                   const la_ip_multicast_group_wcptr& mcg,
                                   const la_l3_port_wcptr& rpf,
                                   bool punt_on_rpf_fail,
                                   bool punt_and_forward,
                                   bool use_rpfid,
                                   const la_uint_t rpfid,
                                   bool enable_rpf_check)
{
    const auto& table(m_device->m_tables.ipv4_vrf_s_g_table);
    npl_ipv4_vrf_s_g_table_key_t key;
    npl_ipv4_vrf_s_g_table_value_t value;
    npl_ipv4_vrf_s_g_table_entry_wptr_t entry;

    key.l3_relay_id.id = m_gid;
    key.sip = saddr.s_addr;
    key.dip_27_20_ = (gaddr.s_addr >> 20) & 0xff;
    key.dip_19_0_ = gaddr.s_addr & 0xfffff;
    value.action = NPL_IPV4_VRF_S_G_TABLE_ACTION_WRITE;
    populate_mc_result_payload(mcg,
                               rpf,
                               punt_on_rpf_fail,
                               punt_and_forward,
                               use_rpfid,
                               rpfid,
                               value.payloads.vrf_s_g_hw_ip_mc_result.raw_payload,
                               enable_rpf_check);

    la_status status = table->set(key, value, entry);

    return status;
}

la_status
la_vrf_impl::verify_mc_route_parameters(size_t max_gid,
                                        const la_ip_multicast_group_wcptr& mcg,
                                        const la_l3_port_wcptr& rpf,
                                        const la_counter_set_wcptr& counter,
                                        const bool use_rpfid,
                                        const la_uint_t rpfid)
{
    if (mcg == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(mcg, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    if (!use_rpfid) {
        if (rpf != nullptr) {
            if (!of_same_device(rpf, this)) {
                return LA_STATUS_EDIFFERENT_DEVS;
            }
        }
    } else {
        if (rpfid != la_device_impl::INVALID_RPF_ID) {
            la_uint64_t min_rpf_id;
            m_device->get_limit(limit_type_e::MLDP_MIN_RPF_ID, min_rpf_id);
            if (rpfid < min_rpf_id) {
                log_err(HLD, "%s: RPF ID must be larger than %lld ", __func__, min_rpf_id);
                return LA_STATUS_EINVAL;
            }
            la_uint64_t max_rpf_id;
            m_device->get_limit(limit_type_e::MLDP_MAX_RPF_ID, max_rpf_id);
            if (rpfid > max_rpf_id) {
                log_err(HLD, "%s: RPF ID must be smaller than %lld ", __func__, max_rpf_id);
                return LA_STATUS_EINVAL;
            }
        }
    }

    if (m_gid >= max_gid) {
        log_err(HLD, "%s: GID of IP multicast VRF must be in the %ld range", __func__, max_gid);

        return LA_STATUS_EINVAL;
    }

    if (counter && counter->get_set_size() != la_device_impl::MAX_ROUTE_STATS_SET_SIZE) {
        log_err(HLD,
                "%s: Invalid counter set size: %lu. Must be %d for route stats counter.",
                __func__,
                counter->get_set_size(),
                la_device_impl::MAX_ROUTE_STATS_SET_SIZE);
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::teardown_mc_route_counter(const la_counter_set_wptr& counter)
{
    if (counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = LA_STATUS_EUNKNOWN;
    const auto& counter_impl = counter.weak_ptr_static_cast<la_counter_set_impl>();

    m_device->remove_ifg_dependency(this, counter_impl);
    m_device->remove_object_dependency(counter_impl, this);
    status = counter_impl->remove_pq_counter_user(m_device->get_sptr(this));
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::configure_mc_route_counter(const la_counter_set_wptr& counter)
{
    if (counter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // Add the VRF as a Q-counter user
    const auto& counter_impl = counter.weak_ptr_static_cast<la_counter_set_impl>();
    la_status status = counter_impl->add_pq_counter_user(
        m_device->get_sptr(this), la_counter_set::type_e::QOS, COUNTER_DIRECTION_INGRESS, true /*is_aggregate*/);
    return_on_error(status);

    m_device->add_ifg_dependency(this, counter_impl);
    m_device->add_object_dependency(counter_impl, this);

    return LA_STATUS_SUCCESS;
}
/*
 * get_max_vrf_gids - Since Prefix compression lists (PCLs) use some
 * of the VRF IDs at the top of the range, there is an integer
 * device property that has been added to allow reclaiming some, or
 * all of those VRF IDs should the user decide to exclude
 * Prefix compression lists, or to reduce the number allocated.
*/
la_status
la_vrf_impl::get_max_vrf_gids(la_uint_t& out_max_vrf_gids) const
{
    int max_num_pcl_gids;

    dassert_crit(la_device_impl::MAX_VRF_GID == la_device_impl::IPV4_MC_VRF_GID_RANGE_LIMIT);
    dassert_crit(la_device_impl::MAX_VRF_GID == la_device_impl::IPV6_VRF_GID_RANGE_LIMIT);
    la_status status = m_device->get_int_property(la_device_property_e::MAX_NUM_PCL_GIDS, max_num_pcl_gids);
    return_on_error(status);
    out_max_vrf_gids = la_device_impl::MAX_VRF_GID - max_num_pcl_gids;
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                      la_ipv4_addr_t gaddr,
                                      la_ip_multicast_group* mcg,
                                      const la_l3_port* rpf,
                                      bool punt_on_rpf_fail,
                                      bool punt_and_forward,
                                      la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "counter=",
                   counter);
    const auto& mcg_base_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    bool use_rpfid = false;
    // set rpfid = invalid
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    bool enable_rpf_check = false;
    if (rpf_sptr != nullptr) {
        enable_rpf_check = true;
    }

    status = verify_mc_route_parameters(max_vrf_gids, mcg_base_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv4_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(map_key);
    if (it != m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_EEXIST;
    }

    status = configure_mc_route_counter(counter_sptr);
    return_on_error(status);

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        status = add_to_ipv4_g_table(gaddr, mcg_base_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv4_s_g_table(
            saddr, gaddr, mcg_base_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    }
    return_on_error(status);

    // register this route with the multicast group
    const auto& vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base_sptr->register_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    mc_route_desc desc = {.mcg = mcg_base_sptr,
                          .rpf = rpf_sptr,
                          .punt_on_rpf_fail = punt_on_rpf_fail,
                          .punt_and_forward = punt_and_forward,
                          .counter = counter_sptr,
                          .v6_compressed_sip = 0,
                          .use_rpfid = use_rpfid,
                          .rpfid = rpfid,
                          .enable_rpf_check = enable_rpf_check};
    m_ipv4_mc_route_desc_map[map_key] = desc;

    m_device->add_object_dependency(mcg_base_sptr, this);
    if (rpf_sptr != nullptr) {
        m_device->add_object_dependency(rpf_sptr, this);
    }

    if (counter_sptr != nullptr) {
        m_device->add_object_dependency(counter_sptr, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                      la_ipv4_addr_t gaddr,
                                      la_ip_multicast_group* mcg,
                                      const la_l3_port* rpf,
                                      bool punt_on_rpf_fail,
                                      bool punt_and_forward,
                                      bool enable_rpf_check,
                                      la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);
    const auto& mcg_base_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    bool use_rpfid = false;
    // set rpfid = invalid
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    status = verify_mc_route_parameters(max_vrf_gids, mcg_base_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv4_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(map_key);
    if (it != m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_EEXIST;
    }

    status = configure_mc_route_counter(counter_sptr);
    return_on_error(status);

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        status = add_to_ipv4_g_table(gaddr, mcg_base_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv4_s_g_table(
            saddr, gaddr, mcg_base_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    }
    return_on_error(status);

    // register this route with the multicast group
    const auto& vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base_sptr->register_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    mc_route_desc desc = {.mcg = mcg_base_sptr,
                          .rpf = rpf_sptr,
                          .punt_on_rpf_fail = punt_on_rpf_fail,
                          .punt_and_forward = punt_and_forward,
                          .counter = counter_sptr,
                          .v6_compressed_sip = 0,
                          .use_rpfid = use_rpfid,
                          .rpfid = rpfid,
                          .enable_rpf_check = enable_rpf_check};
    m_ipv4_mc_route_desc_map[map_key] = desc;

    m_device->add_object_dependency(mcg_base_sptr, this);
    if (rpf_sptr != nullptr) {
        m_device->add_object_dependency(rpf_sptr, this);
    }

    if (counter_sptr != nullptr) {
        m_device->add_object_dependency(counter_sptr, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                      la_ipv4_addr_t gaddr,
                                      la_ip_multicast_group* mcg,
                                      la_uint_t rpfid,
                                      bool punt_on_rpf_fail,
                                      bool punt_and_forward,
                                      bool enable_rpf_check,
                                      la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpfid=",
                   rpfid,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);

    la_l3_port* rpf = nullptr;
    bool use_rpfid = true;

    const auto& mcg_base_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    status = verify_mc_route_parameters(max_vrf_gids, mcg_base_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv4_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(map_key);
    if (it != m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_EEXIST;
    }

    status = configure_mc_route_counter(counter_sptr);
    return_on_error(status);

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        status = add_to_ipv4_g_table(gaddr, mcg_base_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv4_s_g_table(
            saddr, gaddr, mcg_base_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    }
    return_on_error(status);

    // register this route with the multicast group
    const auto& vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base_sptr->register_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    mc_route_desc desc = {.mcg = mcg_base_sptr,
                          .rpf = rpf_sptr,
                          .punt_on_rpf_fail = punt_on_rpf_fail,
                          .punt_and_forward = punt_and_forward,
                          .counter = counter_sptr,
                          .v6_compressed_sip = 0,
                          .use_rpfid = use_rpfid,
                          .rpfid = rpfid,
                          .enable_rpf_check = enable_rpf_check};
    m_ipv4_mc_route_desc_map[map_key] = desc;

    m_device->add_object_dependency(mcg_base_sptr, this);
    if (rpf_sptr != nullptr) {
        m_device->add_object_dependency(rpf_sptr, this);
    }

    if (counter_sptr != nullptr) {
        m_device->add_object_dependency(counter_sptr, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                         la_ipv4_addr_t gaddr,
                                         la_ip_multicast_group* mcg,
                                         const la_l3_port* rpf,
                                         bool punt_on_rpf_fail,
                                         bool punt_and_forward,
                                         la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "counter=",
                   counter);

    bool use_rpfid = false;
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    const auto& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    bool enable_rpf_check = false;
    if (rpf_sptr != nullptr) {
        enable_rpf_check = true;
    }

    la_status status = verify_mc_route_parameters(
        la_device_impl::IPV4_MC_VRF_GID_RANGE_LIMIT, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv4_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(map_key);
    if (it == m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto& desc = it->second;

    // unregister this route with the multicast group
    auto mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base->unregister_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = configure_mc_route_counter(counter_sptr);
        return_on_error(status);
    }

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        status = add_to_ipv4_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv4_s_g_table(
            saddr, gaddr, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    }

    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = teardown_mc_route_counter(desc.counter);
        return_on_error(status);
    }

    // register this route with the multicast group
    mcg_base = mcg_sptr;
    status = mcg_base->register_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    update_mc_desc(desc, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, counter_sptr, use_rpfid, rpfid, enable_rpf_check);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                         la_ipv4_addr_t gaddr,
                                         la_ip_multicast_group* mcg,
                                         const la_l3_port* rpf,
                                         bool punt_on_rpf_fail,
                                         bool punt_and_forward,
                                         bool enable_rpf_check,
                                         la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);

    bool use_rpfid = false;
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    const auto& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    la_status status = verify_mc_route_parameters(
        la_device_impl::IPV4_MC_VRF_GID_RANGE_LIMIT, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv4_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(map_key);
    if (it == m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto& desc = it->second;

    // unregister this route with the multicast group
    auto mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base->unregister_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = configure_mc_route_counter(counter_sptr);
        return_on_error(status);
    }

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        status = add_to_ipv4_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv4_s_g_table(
            saddr, gaddr, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    }

    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = teardown_mc_route_counter(desc.counter);
        return_on_error(status);
    }

    // register this route with the multicast group
    mcg_base = mcg_sptr;
    status = mcg_base->register_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    update_mc_desc(desc, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, counter_sptr, use_rpfid, rpfid, enable_rpf_check);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::modify_ipv4_multicast_route(la_ipv4_addr_t saddr,
                                         la_ipv4_addr_t gaddr,
                                         la_ip_multicast_group* mcg,
                                         la_uint_t rpfid,
                                         bool punt_on_rpf_fail,
                                         bool punt_and_forward,
                                         bool enable_rpf_check,
                                         la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpfid=",
                   rpfid,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);

    la_l3_port* rpf = nullptr;
    bool use_rpfid = true;

    const auto& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    la_status status = verify_mc_route_parameters(
        la_device_impl::IPV4_MC_VRF_GID_RANGE_LIMIT, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv4_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(map_key);
    if (it == m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto& desc = it->second;

    // unregister this route with the multicast group
    auto mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base->unregister_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = configure_mc_route_counter(counter_sptr);
        return_on_error(status);
    }

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        status = add_to_ipv4_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv4_s_g_table(
            saddr, gaddr, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    }

    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = teardown_mc_route_counter(desc.counter);
        return_on_error(status);
    }

    // register this route with the multicast group
    mcg_base = mcg_sptr;
    status = mcg_base->register_mc_ipv4_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    update_mc_desc(desc, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, counter_sptr, use_rpfid, rpfid, enable_rpf_check);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr, la_ip_mc_route_info& out_ip_mc_route_info) const
{
    start_api_getter_call();
    auto it = m_ipv4_mc_route_desc_map.find(ipv4_mc_route_map_key_t(saddr, gaddr));
    if (it == m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    auto& desc = it->second;

    out_ip_mc_route_info.mcg = desc.mcg.get();
    out_ip_mc_route_info.rpf = desc.rpf.get();
    out_ip_mc_route_info.punt_and_forward = desc.punt_and_forward;
    out_ip_mc_route_info.counter = desc.counter.get();
    out_ip_mc_route_info.punt_on_rpf_fail = desc.punt_on_rpf_fail;
    out_ip_mc_route_info.use_rpfid = desc.use_rpfid;
    out_ip_mc_route_info.rpfid = desc.rpfid;
    out_ip_mc_route_info.enable_rpf_check = desc.enable_rpf_check;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::update_ipv4_multicast_route(la_ipv4_addr_t saddr, la_ipv4_addr_t gaddr)
{
    ipv4_mc_route_map_key_t key(saddr, gaddr);
    auto it = m_ipv4_mc_route_desc_map.find(key);
    if (it == m_ipv4_mc_route_desc_map.end()) {
        return LA_STATUS_EUNKNOWN;
    }
    const auto& desc = it->second;
    la_status status;

    if (saddr.s_addr == LA_IPV4_ANY_IP.s_addr) {
        status = add_to_ipv4_g_table(
            gaddr, desc.mcg, desc.rpf, desc.punt_and_forward, desc.use_rpfid, desc.rpfid, desc.enable_rpf_check);
    } else {
        status = add_to_ipv4_s_g_table(saddr,
                                       gaddr,
                                       desc.mcg,
                                       desc.rpf,
                                       desc.punt_on_rpf_fail,
                                       desc.punt_and_forward,
                                       desc.use_rpfid,
                                       desc.rpfid,
                                       desc.enable_rpf_check);
    }
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::update_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr)
{
    ipv6_mc_route_map_key_t key(saddr, gaddr);
    auto it = find_ipv6_mc_route_map_entry_full_gaddr(key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return LA_STATUS_EUNKNOWN;
    }
    const auto& desc = it->second;
    la_status status;

    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = add_to_ipv6_g_table(
            gaddr, desc.mcg, desc.rpf, desc.punt_and_forward, desc.use_rpfid, desc.rpfid, desc.enable_rpf_check);
    } else {
        status = add_to_ipv6_s_g_table(saddr,
                                       gaddr,
                                       desc.mcg,
                                       desc.rpf,
                                       desc.punt_on_rpf_fail,
                                       desc.punt_and_forward,
                                       desc.use_rpfid,
                                       desc.rpfid,
                                       desc.v6_compressed_sip,
                                       desc.enable_rpf_check);
    }
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::delete_ipv6_route(la_ipv6_prefix_t prefix)
{
    start_api_call("prefix=", prefix);

    return do_ipv6_route_action(
        la_route_entry_action_e::DELETE, prefix, nullptr, false /* user_data_set */, 0, false /* latency_sensitive */);
}

la_status
la_vrf_impl::ipv6_route_bulk_updates(la_ipv6_route_entry_parameters_vec route_entry_vec, size_t& out_count_success)
{
    start_api_call("count=", route_entry_vec.size());

    for (auto& route_entry : route_entry_vec) {
        // For convergence performance we log the Bulk update entries directly instead of using standard
        // API logging via start_api_call() which uses expensive std::stringstream and __cxa_demangle for
        // data type logging.
        log_debug(API,
                  route_entry_api_log_format,
                  silicon_one::to_string(route_entry.action).c_str(),
                  silicon_one::to_string(route_entry.prefix.addr).c_str(),
                  route_entry.prefix.length,
                  route_entry.destination ? silicon_one::to_string(route_entry.destination).c_str() : "nullptr",
                  silicon_one::to_string(route_entry.latency_sensitive).c_str());
    }

    la_status status = ip_route_bulk_updates(m_device->m_tables.ipv6_lpm_table,
                                             m_device->m_tables.ipv6_vrf_dip_em_table,
                                             route_entry_vec,
                                             m_ipv6_bulk_entries_vec,
                                             m_ipv6_bulk_prefix_set,
                                             out_count_success);
    if (status != LA_STATUS_SUCCESS) {
        log_info(API,
                 "la_vrf_impl::ipv6_route_bulk_updates done: size=%zu, out_count_success=%zu, status=%s",
                 route_entry_vec.size(),
                 out_count_success,
                 la_status2str(status).c_str());
    } else {
        log_info(API,
                 "la_vrf_impl::ipv6_route_bulk_updates done: size=%zu, out_count_success=%zu",
                 route_entry_vec.size(),
                 out_count_success);
    }

    // If out_count_success is 0, then try to insert first route to make progress in bulk.
    if ((status == LA_STATUS_SUCCESS) && (route_entry_vec.size() > 1) && (out_count_success == 0)) {
        switch (route_entry_vec[0].action) {
        case la_route_entry_action_e::ADD:
            status = add_ipv6_route(route_entry_vec[0].prefix,
                                    route_entry_vec[0].destination,
                                    route_entry_vec[0].user_data,
                                    route_entry_vec[0].latency_sensitive);
            break;

        case la_route_entry_action_e::MODIFY:
            if (route_entry_vec[0].is_user_data_set) {
                status = modify_ipv6_route(route_entry_vec[0].prefix, route_entry_vec[0].destination, route_entry_vec[0].user_data);
            } else {
                status = modify_ipv6_route(route_entry_vec[0].prefix, route_entry_vec[0].destination);
            }
            break;

        case la_route_entry_action_e::DELETE:
            status = delete_ipv6_route(route_entry_vec[0].prefix);
            break;
        }

        if (status == LA_STATUS_SUCCESS) {
            out_count_success++;
        }
    }

    return status;
}

la_status
la_vrf_impl::do_ipv6_route_action(const la_route_entry_action_e action,
                                  const la_ipv6_prefix_t& prefix,
                                  const la_l3_destination_wcptr& destination,
                                  const bool is_user_data_set,
                                  const la_user_data_t user_data,
                                  const bool latency_sensitive)
{
    la_ipv6_route_entry_parameters_vec route_entry_vec(1);
    size_t dummy_count_success;

    route_entry_vec[0].action = action;
    route_entry_vec[0].prefix = prefix;
    route_entry_vec[0].destination = destination.get();
    route_entry_vec[0].is_user_data_set = is_user_data_set;
    route_entry_vec[0].user_data = user_data;
    route_entry_vec[0].latency_sensitive = latency_sensitive;

    return ip_route_bulk_updates(m_device->m_tables.ipv6_lpm_table,
                                 m_device->m_tables.ipv6_vrf_dip_em_table,
                                 route_entry_vec,
                                 m_ipv6_bulk_entries_vec,
                                 m_ipv6_bulk_prefix_set,
                                 dummy_count_success);
}

la_status
la_vrf_impl::clear_all_ipv6_routes()
{
    start_api_call("");

    return clear_all_ip_routes(
        m_device->m_tables.ipv6_lpm_table, m_device->m_tables.ipv6_vrf_dip_em_table, false /* clear_catch_all_entry */);
}

la_status
la_vrf_impl::add_ipv6_route(la_ipv6_prefix_t prefix,
                            const la_l3_destination* destination,
                            la_user_data_t user_data,
                            bool latency_sensitive)
{
    start_api_call(
        "prefix=", prefix, "destination=", destination, "user_data=", user_data, "latency_sensitive=", latency_sensitive);

    if (m_gid >= la_device_impl::IPV6_VRF_GID_RANGE_LIMIT) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return do_ipv6_route_action(la_route_entry_action_e::ADD,
                                prefix,
                                m_device->get_sptr(destination),
                                true /* user_data_set */,
                                user_data,
                                latency_sensitive);
}

la_status
la_vrf_impl::modify_ipv6_route(la_ipv6_prefix_t prefix, const la_l3_destination* destination)
{
    start_api_call("prefix=", prefix, "destination=", destination);

    return do_ipv6_route_action(la_route_entry_action_e::MODIFY,
                                prefix,
                                m_device->get_sptr(destination),
                                false /* user_data_set */,
                                0,
                                false /* latency_sensitive */);
}

la_status
la_vrf_impl::modify_ipv6_route(la_ipv6_prefix_t prefix, const la_l3_destination* destination, la_user_data_t user_data)
{
    start_api_call("prefix=", prefix, "destination=", destination, "user_data=", user_data);

    return do_ipv6_route_action(la_route_entry_action_e::MODIFY,
                                prefix,
                                m_device->get_sptr(destination),
                                true /* user_data_set */,
                                user_data,
                                false /* latency_sensitive */);
}

la_status
la_vrf_impl::set_fallback_vrf(const la_vrf* fallback_vrf)
{
    start_api_call("fallback_vrf=", fallback_vrf);
    if (fallback_vrf) {
        la_vrf_gid_t gid = fallback_vrf->get_gid();
        if (gid != 0) {
            log_err(HLD,
                    "la_vrf_impl::set_fallback_vrf(%s): only default VRF supported as fallback VRF.",
                    silicon_one::to_string(fallback_vrf).c_str());
            return LA_STATUS_EINVAL;
        }
    }

    auto old_vrf = m_fallback_vrf;
    m_fallback_vrf = m_device->get_sptr(fallback_vrf);
    attribute_management_details amd;
    amd.op = attribute_management_op::VRF_FALLBACK_CHANGED;
    la_amd_undo_callback_funct_t undo = [this, old_vrf](attribute_management_details amd) {
        m_fallback_vrf = old_vrf;
        return amd;
    };
    return m_device->notify_attribute_changed(this, amd, undo);
}

la_status
la_vrf_impl::get_fallback_vrf(const la_vrf*& out_vrf) const
{
    start_api_getter_call();
    out_vrf = m_fallback_vrf.get();

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv6_route(la_ipv6_addr_t ip_addr, la_ip_route_info& out_ip_route_info) const
{
    start_api_getter_call();

    return get_route_info_from_addr(
        m_device->m_tables.ipv6_lpm_table, m_device->m_tables.ipv6_vrf_dip_em_table, ip_addr, out_ip_route_info);
}

la_status
la_vrf_impl::delete_from_ipv6_g_table(la_ipv6_addr_t gaddr)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);
    npl_ipv6_vrf_dip_em_table_key_t key;

    populate_em_table_key(m_gid, gaddr, key);

    la_status status = table->erase(key);

    return status;
}

la_status
la_vrf_impl::delete_from_ipv6_s_g_table(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr)
{
    const auto& table(m_device->m_tables.ipv6_vrf_s_g_table);
    npl_ipv6_vrf_s_g_table_key_t key;

    auto it = m_device->m_ipv6_compressed_sip_map.find(saddr.s_addr);
    if (it == m_device->m_ipv6_compressed_sip_map.end()) {
        log_err(HLD, "%s: SIP was not found in IPv6 compressed SIP map", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    la_device_impl::ipv6_compressed_sip_desc desc = it->second;
    uint64_t compressed_sip = desc.code;

    key.l3_relay_id.id = m_gid;
    key.compressed_sip = compressed_sip;
    key.dip_32_lsb = gaddr.d_addr[0];

    la_status status = table->erase(key);
    return_on_error(status);

    status = m_device->release_ipv6_compressed_sip(saddr);

    return status;
}

la_status
la_vrf_impl::delete_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr)
{
    start_api_call("saddr=", saddr, "gaddr=", gaddr);

    return do_delete_ipv6_multicast_route(saddr, gaddr);
}

la_status
la_vrf_impl::do_delete_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr)
{
    ipv6_mc_route_map_key_t key(saddr, gaddr);
    auto it = find_ipv6_mc_route_map_entry_full_gaddr(key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    la_status status;
    const auto& desc = it->second;

    // unregister this route with the multicast group
    const auto& mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl* vrf_impl = this;
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr(vrf_impl);
    status = mcg_base->unregister_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = delete_from_ipv6_g_table(gaddr);
    } else {
        status = delete_from_ipv6_s_g_table(saddr, gaddr);
    }
    return_on_error(status);

    status = teardown_mc_route_counter(desc.counter);
    return_on_error(status);

    m_device->remove_object_dependency(desc.mcg, this);
    if (desc.rpf != nullptr) {
        m_device->remove_object_dependency(desc.rpf, this);
    }

    if (desc.counter != nullptr) {
        m_device->remove_object_dependency(desc.counter, this);
    }

    m_ipv6_mc_route_desc_map.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::clear_all_ipv6_multicast_routes()
{
    start_api_call("");

    auto temp = m_ipv6_mc_route_desc_map;

    for (auto temp_it : temp) {
        auto key = temp_it.first;

        la_ipv6_addr_t saddr = key.saddr;
        la_ipv6_addr_t gaddr = key.gaddr;

        la_status status = do_delete_ipv6_multicast_route(saddr, gaddr);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_to_ipv6_g_table(la_ipv6_addr_t gaddr,
                                 const la_ip_multicast_group_wcptr& mcg,
                                 const la_l3_port_wcptr& rpf,
                                 bool punt_and_forward,
                                 bool use_rpfid,
                                 la_uint_t rpfid,
                                 bool enable_rpf_check)
{
    const auto& table(m_device->m_tables.ipv6_vrf_dip_em_table);
    npl_ipv6_vrf_dip_em_table_key_t key;
    npl_ipv6_vrf_dip_em_table_value_t value;
    npl_ipv6_vrf_dip_em_table_entry_wptr_t entry;

    populate_em_table_key(m_gid, gaddr, key);
    value.action = NPL_IPV6_VRF_DIP_EM_TABLE_ACTION_WRITE;
    populate_mc_result_payload(mcg,
                               rpf,
                               false /* punt_on_rpf_fail only applies in S,G case, as SIP is don't-care */,
                               punt_and_forward,
                               use_rpfid,
                               rpfid,
                               value.payloads.em_lookup_result.result.mc_result,
                               enable_rpf_check);
    value.payloads.em_lookup_result.result_type = NPL_IP_EM_LPM_RESULT_TYPE_DESTINATION_FROM_EM;

    la_status status = table->set(key, value, entry);

    return status;
}

la_status
la_vrf_impl::add_to_ipv6_s_g_table(la_ipv6_addr_t saddr,
                                   la_ipv6_addr_t gaddr,
                                   const la_ip_multicast_group_wcptr& mcg,
                                   const la_l3_port_wcptr& rpf,
                                   bool punt_on_rpf_fail,
                                   bool punt_and_forward,
                                   bool use_rpfid,
                                   la_uint_t rpfid,
                                   uint64_t compressed_sip,
                                   bool enable_rpf_check)
{
    const auto& table(m_device->m_tables.ipv6_vrf_s_g_table);
    npl_ipv6_vrf_s_g_table_key_t key;
    npl_ipv6_vrf_s_g_table_value_t value;
    npl_ipv6_vrf_s_g_table_entry_wptr_t entry;

    key.l3_relay_id.id = m_gid;
    key.compressed_sip = compressed_sip;
    key.dip_32_lsb = gaddr.d_addr[0];

    value.action = NPL_IPV6_VRF_S_G_TABLE_ACTION_WRITE;
    populate_mc_result_payload(mcg,
                               rpf,
                               punt_on_rpf_fail,
                               punt_and_forward,
                               use_rpfid,
                               rpfid,
                               value.payloads.vrf_s_g_hw_ip_mc_result.raw_payload,
                               enable_rpf_check);

    la_status status = table->set(key, value, entry);

    return status;
}

la_status
la_vrf_impl::add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                      la_ipv6_addr_t gaddr,
                                      la_ip_multicast_group* mcg,
                                      const la_l3_port* rpf,
                                      bool punt_on_rpf_fail,
                                      bool punt_and_forward,
                                      la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "counter=",
                   counter);

    bool use_rpfid = false;
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    const la_ip_multicast_group_base_wptr& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    bool enable_rpf_check = false;
    if (rpf_sptr != nullptr) {
        enable_rpf_check = true;
    }

    la_status status
        = verify_mc_route_parameters(la_device_impl::IPV6_VRF_GID_RANGE_LIMIT, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv6_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv6_mc_route_desc_map.find(map_key);
    if (it != m_ipv6_mc_route_desc_map.end()) {
        log_err(HLD, "%s: a group-address with similar lower 32 bit already exists", __func__);
        return LA_STATUS_EEXIST;
    }

    status = configure_mc_route_counter(counter_sptr);
    return_on_error(status);

    uint64_t compressed_sip = 0;
    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = add_to_ipv6_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = m_device->allocate_ipv6_compressed_sip(saddr, compressed_sip);
        return_on_error(status);

        status = add_to_ipv6_s_g_table(saddr,
                                       gaddr,
                                       mcg_sptr,
                                       rpf_sptr,
                                       punt_on_rpf_fail,
                                       punt_and_forward,
                                       use_rpfid,
                                       rpfid,
                                       compressed_sip,
                                       enable_rpf_check);
    }
    return_on_error(status);

    // register this route with the multicast group
    const auto& mcg_base = mcg_sptr.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base->register_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    mc_route_desc desc = {.mcg = mcg_sptr,
                          .rpf = rpf_sptr,
                          .punt_on_rpf_fail = punt_on_rpf_fail,
                          .punt_and_forward = punt_and_forward,
                          .counter = counter_sptr,
                          .v6_compressed_sip = compressed_sip,
                          .use_rpfid = use_rpfid,
                          .rpfid = rpfid,
                          .enable_rpf_check = enable_rpf_check};
    m_ipv6_mc_route_desc_map[map_key] = desc;

    m_device->add_object_dependency(mcg_sptr, this);
    if (rpf_sptr != nullptr) {
        m_device->add_object_dependency(rpf_sptr, this);
    }

    if (counter_sptr != nullptr) {
        m_device->add_object_dependency(counter_sptr, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                      la_ipv6_addr_t gaddr,
                                      la_ip_multicast_group* mcg,
                                      const la_l3_port* rpf,
                                      bool punt_on_rpf_fail,
                                      bool punt_and_forward,
                                      bool enable_rpf_check,
                                      la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);

    bool use_rpfid = false;
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    const la_ip_multicast_group_base_wptr& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    la_status status
        = verify_mc_route_parameters(la_device_impl::IPV6_VRF_GID_RANGE_LIMIT, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv6_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv6_mc_route_desc_map.find(map_key);
    if (it != m_ipv6_mc_route_desc_map.end()) {
        log_err(HLD, "%s: a group-address with similar lower 32 bit already exists", __func__);
        return LA_STATUS_EEXIST;
    }

    status = configure_mc_route_counter(counter_sptr);
    return_on_error(status);

    uint64_t compressed_sip = 0;
    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = add_to_ipv6_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = m_device->allocate_ipv6_compressed_sip(saddr, compressed_sip);
        return_on_error(status);

        status = add_to_ipv6_s_g_table(saddr,
                                       gaddr,
                                       mcg_sptr,
                                       rpf_sptr,
                                       punt_on_rpf_fail,
                                       punt_and_forward,
                                       use_rpfid,
                                       rpfid,
                                       compressed_sip,
                                       enable_rpf_check);
    }
    return_on_error(status);

    // register this route with the multicast group
    const auto& mcg_base = mcg_sptr.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base->register_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    mc_route_desc desc = {.mcg = mcg_sptr,
                          .rpf = rpf_sptr,
                          .punt_on_rpf_fail = punt_on_rpf_fail,
                          .punt_and_forward = punt_and_forward,
                          .counter = counter_sptr,
                          .v6_compressed_sip = compressed_sip,
                          .use_rpfid = use_rpfid,
                          .rpfid = rpfid,
                          .enable_rpf_check = enable_rpf_check};
    m_ipv6_mc_route_desc_map[map_key] = desc;

    m_device->add_object_dependency(mcg_sptr, this);
    if (rpf_sptr != nullptr) {
        m_device->add_object_dependency(rpf_sptr, this);
    }

    if (counter_sptr != nullptr) {
        m_device->add_object_dependency(counter_sptr, this);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                      la_ipv6_addr_t gaddr,
                                      la_ip_multicast_group* mcg,
                                      la_uint_t rpfid,
                                      bool punt_on_rpf_fail,
                                      bool punt_and_forward,
                                      bool enable_rpf_check,
                                      la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpfid=",
                   rpfid,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);

    la_l3_port* rpf = nullptr;
    bool use_rpfid = true;

    const la_ip_multicast_group_base_wptr& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& counter_sptr = m_device->get_sptr(counter);
    const auto& rpf_sptr = m_device->get_sptr(rpf);

    la_status status
        = verify_mc_route_parameters(la_device_impl::IPV6_VRF_GID_RANGE_LIMIT, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv6_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = m_ipv6_mc_route_desc_map.find(map_key);
    if (it != m_ipv6_mc_route_desc_map.end()) {
        log_err(HLD, "%s: a group-address with similar lower 32 bit already exists", __func__);
        return LA_STATUS_EEXIST;
    }

    status = configure_mc_route_counter(counter_sptr);
    return_on_error(status);

    uint64_t compressed_sip = 0;
    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = add_to_ipv6_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = m_device->allocate_ipv6_compressed_sip(saddr, compressed_sip);
        return_on_error(status);

        status = add_to_ipv6_s_g_table(saddr,
                                       gaddr,
                                       mcg_sptr,
                                       rpf_sptr,
                                       punt_on_rpf_fail,
                                       punt_and_forward,
                                       use_rpfid,
                                       rpfid,
                                       compressed_sip,
                                       enable_rpf_check);
    }
    return_on_error(status);

    // register this route with the multicast group
    const auto& mcg_base = mcg_sptr.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr<la_vrf_impl>(this);
    status = mcg_base->register_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    mc_route_desc desc = {.mcg = mcg_sptr,
                          .rpf = rpf_sptr,
                          .punt_on_rpf_fail = punt_on_rpf_fail,
                          .punt_and_forward = punt_and_forward,
                          .counter = counter_sptr,
                          .v6_compressed_sip = compressed_sip,
                          .use_rpfid = use_rpfid,
                          .rpfid = rpfid,
                          .enable_rpf_check = enable_rpf_check};
    m_ipv6_mc_route_desc_map[map_key] = desc;

    m_device->add_object_dependency(mcg_sptr, this);
    if (rpf_sptr != nullptr) {
        m_device->add_object_dependency(rpf_sptr, this);
    }

    if (counter_sptr != nullptr) {
        m_device->add_object_dependency(counter_sptr, this);
    }

    return LA_STATUS_SUCCESS;
}

void
la_vrf_impl::update_mc_desc(mc_route_desc& desc,
                            const la_ip_multicast_group_wptr& mcg,
                            const la_l3_port_wcptr& rpf,
                            bool punt_on_rpf_fail,
                            bool punt_and_forward,
                            const la_counter_set_wptr& counter,
                            bool use_rpfid,
                            la_uint_t rpfid,
                            bool enable_rpf_check)
{
    if (mcg != desc.mcg) {
        m_device->remove_object_dependency(desc.mcg, this);
        m_device->add_object_dependency(mcg, this);
    }

    if (rpf != desc.rpf) {
        if (desc.rpf != nullptr) {
            m_device->remove_object_dependency(desc.rpf, this);
        }

        if (rpf != nullptr) {
            m_device->add_object_dependency(rpf, this);
        }
    }

    if (counter != desc.counter) {
        if (desc.counter != nullptr) {
            m_device->remove_object_dependency(desc.counter, this);
        }

        if (counter != nullptr) {
            m_device->add_object_dependency(counter, this);
        }
    }

    desc.mcg = mcg;
    desc.rpf = rpf;
    desc.punt_and_forward = punt_and_forward;
    desc.punt_on_rpf_fail = punt_on_rpf_fail;
    desc.counter = counter;
    desc.use_rpfid = use_rpfid;
    desc.rpfid = rpfid;
    desc.enable_rpf_check = enable_rpf_check;
}

std::map<la_vrf_impl::ipv6_mc_route_map_key_t, la_vrf_impl::mc_route_desc>::const_iterator
la_vrf_impl::find_ipv6_mc_route_map_entry_full_gaddr(const ipv6_mc_route_map_key_t& map_key) const
{
    std::map<la_vrf_impl::ipv6_mc_route_map_key_t, la_vrf_impl::mc_route_desc>::const_iterator it
        = m_ipv6_mc_route_desc_map.find(map_key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return m_ipv6_mc_route_desc_map.end();
    }

    // The less-than operator used for the IPv6 route-descriptor map uses only 32 LSbits,
    // so the find() operation could return a key with different full gaddr.
    if (it->first.gaddr.s_addr != map_key.gaddr.s_addr) {
        return m_ipv6_mc_route_desc_map.end();
    }

    return it;
}

std::map<la_vrf_impl::ipv6_mc_route_map_key_t, la_vrf_impl::mc_route_desc>::iterator
la_vrf_impl::find_ipv6_mc_route_map_entry_full_gaddr(const ipv6_mc_route_map_key_t& map_key)
{
    std::map<la_vrf_impl::ipv6_mc_route_map_key_t, la_vrf_impl::mc_route_desc>::iterator it
        = m_ipv6_mc_route_desc_map.find(map_key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return m_ipv6_mc_route_desc_map.end();
    }

    // The less-than operator used for the IPv6 route-descriptor map uses only 32 LSbits,
    // so the find() operation could return a key with different full gaddr.
    if (it->first.gaddr.s_addr != map_key.gaddr.s_addr) {
        return m_ipv6_mc_route_desc_map.end();
    }

    return it;
}

la_status
la_vrf_impl::modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                         la_ipv6_addr_t gaddr,
                                         la_ip_multicast_group* mcg,
                                         const la_l3_port* rpf,
                                         bool punt_on_rpf_fail,
                                         bool punt_and_forward,
                                         la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "counter=",
                   counter);

    bool use_rpfid = false;
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    const auto& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& rpf_sptr = m_device->get_sptr(rpf);
    const auto& counter_sptr = m_device->get_sptr(counter);

    bool enable_rpf_check = false;
    if (rpf_sptr != nullptr) {
        enable_rpf_check = true;
    }

    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    status = verify_mc_route_parameters(max_vrf_gids, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv6_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = find_ipv6_mc_route_map_entry_full_gaddr(map_key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto& desc = it->second;

    // unregister this route with the multicast group
    auto mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl* vrf_impl = this;
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr(vrf_impl);
    status = mcg_base->unregister_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = configure_mc_route_counter(counter_sptr);
        return_on_error(status);
    }

    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = add_to_ipv6_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv6_s_g_table(saddr,
                                       gaddr,
                                       mcg_sptr,
                                       rpf_sptr,
                                       punt_on_rpf_fail,
                                       punt_and_forward,
                                       use_rpfid,
                                       rpfid,
                                       desc.v6_compressed_sip,
                                       enable_rpf_check);
    }

    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = teardown_mc_route_counter(desc.counter);
        return_on_error(status);
    }

    // register this route with the multicast group
    mcg_base = mcg_sptr;
    status = mcg_base->register_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    update_mc_desc(desc, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, counter_sptr, use_rpfid, rpfid, enable_rpf_check);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                         la_ipv6_addr_t gaddr,
                                         la_ip_multicast_group* mcg,
                                         const la_l3_port* rpf,
                                         bool punt_on_rpf_fail,
                                         bool punt_and_forward,
                                         bool enable_rpf_check,
                                         la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpf=",
                   rpf,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);

    bool use_rpfid = false;
    la_uint_t rpfid = la_device_impl::INVALID_RPF_ID;

    const auto& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& rpf_sptr = m_device->get_sptr(rpf);
    const auto& counter_sptr = m_device->get_sptr(counter);

    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    status = verify_mc_route_parameters(max_vrf_gids, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv6_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = find_ipv6_mc_route_map_entry_full_gaddr(map_key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto& desc = it->second;

    // unregister this route with the multicast group
    auto mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl* vrf_impl = this;
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr(vrf_impl);
    status = mcg_base->unregister_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = configure_mc_route_counter(counter_sptr);
        return_on_error(status);
    }

    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = add_to_ipv6_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv6_s_g_table(saddr,
                                       gaddr,
                                       mcg_sptr,
                                       rpf_sptr,
                                       punt_on_rpf_fail,
                                       punt_and_forward,
                                       use_rpfid,
                                       rpfid,
                                       desc.v6_compressed_sip,
                                       enable_rpf_check);
    }

    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = teardown_mc_route_counter(desc.counter);
        return_on_error(status);
    }

    // register this route with the multicast group
    mcg_base = mcg_sptr;
    status = mcg_base->register_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    update_mc_desc(desc, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, counter_sptr, use_rpfid, rpfid, enable_rpf_check);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::modify_ipv6_multicast_route(la_ipv6_addr_t saddr,
                                         la_ipv6_addr_t gaddr,
                                         la_ip_multicast_group* mcg,
                                         la_uint_t rpfid,
                                         bool punt_on_rpf_fail,
                                         bool punt_and_forward,
                                         bool enable_rpf_check,
                                         la_counter_set* counter)
{
    start_api_call("saddr=",
                   saddr,
                   "gaddr=",
                   gaddr,
                   "mcg=",
                   mcg,
                   "rpfid=",
                   rpfid,
                   "punt_on_rpf_fail=",
                   punt_on_rpf_fail,
                   "punt_and_forward=",
                   punt_and_forward,
                   "enable_rpf_check=",
                   enable_rpf_check,
                   "counter=",
                   counter);

    la_l3_port* rpf = nullptr;
    bool use_rpfid = true;

    const auto& mcg_sptr = m_device->get_sptr<la_ip_multicast_group_base>(mcg);
    const auto& rpf_sptr = m_device->get_sptr(rpf);
    const auto& counter_sptr = m_device->get_sptr(counter);

    la_uint_t max_vrf_gids;
    la_status status = get_max_vrf_gids(max_vrf_gids);
    return_on_error(status);

    status = verify_mc_route_parameters(max_vrf_gids, mcg_sptr, rpf_sptr, counter_sptr, use_rpfid, rpfid);
    return_on_error(status);

    ipv6_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = find_ipv6_mc_route_map_entry_full_gaddr(map_key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }
    auto& desc = it->second;

    // unregister this route with the multicast group
    auto mcg_base = desc.mcg.weak_ptr_static_cast<la_ip_multicast_group_base>();
    la_vrf_impl* vrf_impl = this;
    la_vrf_impl_sptr vrf_impl_sptr = m_device->get_sptr(vrf_impl);
    status = mcg_base->unregister_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = configure_mc_route_counter(counter_sptr);
        return_on_error(status);
    }

    if (saddr.s_addr == LA_IPV6_ANY_IP.s_addr) {
        status = add_to_ipv6_g_table(gaddr, mcg_sptr, rpf_sptr, punt_and_forward, use_rpfid, rpfid, enable_rpf_check);
    } else {
        status = add_to_ipv6_s_g_table(saddr,
                                       gaddr,
                                       mcg_sptr,
                                       rpf_sptr,
                                       punt_on_rpf_fail,
                                       punt_and_forward,
                                       use_rpfid,
                                       rpfid,
                                       desc.v6_compressed_sip,
                                       enable_rpf_check);
    }

    return_on_error(status);

    if (counter_sptr != desc.counter) {
        status = teardown_mc_route_counter(desc.counter);
        return_on_error(status);
    }

    // register this route with the multicast group
    mcg_base = mcg_sptr;
    status = mcg_base->register_mc_ipv6_vrf_route(vrf_impl_sptr, saddr, gaddr);
    return_on_error(status);

    update_mc_desc(desc, mcg_sptr, rpf_sptr, punt_on_rpf_fail, punt_and_forward, counter_sptr, use_rpfid, rpfid, enable_rpf_check);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv6_multicast_route(la_ipv6_addr_t saddr, la_ipv6_addr_t gaddr, la_ip_mc_route_info& out_ip_mc_route_info) const
{
    start_api_getter_call();

    ipv6_mc_route_map_key_t map_key(saddr, gaddr);
    auto it = find_ipv6_mc_route_map_entry_full_gaddr(map_key);
    if (it == m_ipv6_mc_route_desc_map.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    const auto& desc = it->second;

    out_ip_mc_route_info.mcg = desc.mcg.get();
    out_ip_mc_route_info.rpf = desc.rpf.get();
    out_ip_mc_route_info.punt_and_forward = desc.punt_and_forward;
    out_ip_mc_route_info.counter = desc.counter.get();
    out_ip_mc_route_info.punt_on_rpf_fail = desc.punt_on_rpf_fail;
    out_ip_mc_route_info.use_rpfid = desc.use_rpfid;
    out_ip_mc_route_info.rpfid = desc.rpfid;
    out_ip_mc_route_info.enable_rpf_check = desc.enable_rpf_check;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::verify_unmatched_multicast_punt_prefix(la_ipv4_prefix_t group_prefix) const
{
    if (!is_prefix_valid(group_prefix) || !is_prefix_multicast(group_prefix)) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::verify_unmatched_multicast_punt_prefix(la_ipv6_prefix_t group_prefix) const
{
    if (!is_prefix_valid(group_prefix) || !is_prefix_multicast(group_prefix)) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

bool
la_vrf_impl::is_implicit_mc_catch_all_configured(la_ipv4_prefix_t default_prefix) const
{
    return m_ipv4_implicit_mc_catch_all_configured;
}

bool
la_vrf_impl::is_implicit_mc_catch_all_configured(la_ipv6_prefix_t default_prefix) const
{
    return m_ipv6_implicit_mc_catch_all_configured;
}

void
la_vrf_impl::configure_implicit_mc_catch_all(la_ipv4_prefix_t default_prefix, bool value)
{
    m_ipv4_implicit_mc_catch_all_configured = value;
}

void
la_vrf_impl::configure_implicit_mc_catch_all(la_ipv6_prefix_t default_prefix, bool value)
{
    m_ipv6_implicit_mc_catch_all_configured = value;
}

template <class _TableType, class _PrefixType>
la_status
la_vrf_impl::get_unmatched_multicast_punt_enabled(const std::shared_ptr<_TableType>& table,
                                                  _PrefixType group_prefix,
                                                  _PrefixType default_prefix,
                                                  bool& out_punt_enabled) const
{
    typename _TableType::key_type key;
    typename _TableType::value_type value;
    typename _TableType::entry_wptr_type entry;

    la_status status = verify_unmatched_multicast_punt_prefix(group_prefix);
    return_on_error(status);

    populate_lpm_key(group_prefix.addr, key);

    status = table->find(key, group_prefix.length, entry);
    return_on_error(status);

    npl_destination_t destination = entry->value().payloads.lpm_payload.destination;

    if (group_prefix.length == default_prefix.length && is_implicit_mc_catch_all_configured(default_prefix)) {
        return LA_STATUS_ENOTFOUND;
    }

    if (destination.val == DROP_UNMATCHED_MC_LPM_DESTINATION) {
        out_punt_enabled = false;
    } else {
        out_punt_enabled = true;
    }

    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _PrefixType>
la_status
la_vrf_impl::set_unmatched_multicast_punt_enabled(const std::shared_ptr<_TableType>& table,
                                                  _PrefixType group_prefix,
                                                  bool punt_enabled,
                                                  _PrefixType default_prefix)
{
    la_status status = verify_unmatched_multicast_punt_prefix(group_prefix);
    return_on_error(status);

    npl_destination_t destination;
    if (punt_enabled) {
        destination.val = PUNT_UNMATCHED_MC_LPM_DESTINATION;
    } else {
        destination.val = DROP_UNMATCHED_MC_LPM_DESTINATION;
    }

    typename _TableType::entry_wptr_type entry;
    typename _TableType::key_type key;
    typename _TableType::value_type value;

    populate_lpm_key(group_prefix.addr, key);
    value.payloads.lpm_payload.destination = destination;

    // Handle user-configured MC catch-all vs default entry
    if (group_prefix.length == default_prefix.length) {
        status = table->find(key, group_prefix.length, entry);
        return_on_error(status);
        status = entry->update(value, 0 /* user_data */);
        return_on_error(status);
        configure_implicit_mc_catch_all(default_prefix, false /* User-configured default */);
    } else {
        status = table->find(key, group_prefix.length, entry);
        if (status == LA_STATUS_ENOTFOUND) {
            status = add_lpm_entry(table, group_prefix, destination, 0 /* user_data */, false /* latency_sensitive */);
            return_on_error(status);
        } else {
            status = entry->update(value, 0 /* user_data */);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

template <class _TableType, class _PrefixType>
la_status
la_vrf_impl::clear_unmatched_multicast_punt_enabled(const std::shared_ptr<_TableType>& table,
                                                    _PrefixType group_prefix,
                                                    _PrefixType default_prefix)
{
    la_status status = verify_unmatched_multicast_punt_prefix(group_prefix);
    return_on_error(status);

    typename _TableType::key_type key;
    typename _TableType::entry_wptr_type entry;

    populate_lpm_key(group_prefix.addr, key);

    status = table->find(key, group_prefix.length, entry);
    return_on_error(status);

    // Handle default entry
    if (group_prefix.length == default_prefix.length) {
        if (!is_implicit_mc_catch_all_configured(default_prefix)) {
            typename _TableType::value_type value;
            value.payloads.lpm_payload.destination = {.val = DROP_UNMATCHED_MC_LPM_DESTINATION};

            status = entry->update(value, 0 /* user_data */);
            return_on_error(status);
            configure_implicit_mc_catch_all(default_prefix, true /* Implicit default */);
        } else {
            return LA_STATUS_ENOTFOUND;
        }
    } else {
        status = remove_lpm_entry(table, entry, false);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::set_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix, bool punt_enabled)
{
    start_api_call("group_prefix=", group_prefix, "punt_enabled=", punt_enabled);

    return set_unmatched_multicast_punt_enabled(m_device->m_tables.ipv4_lpm_table, group_prefix, punt_enabled, LA_IPV4_MC_PREFIX);
}

la_status
la_vrf_impl::clear_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix)
{
    start_api_call("group_prefix=", group_prefix);

    return clear_unmatched_multicast_punt_enabled(m_device->m_tables.ipv4_lpm_table, group_prefix, LA_IPV4_MC_PREFIX);
}

la_status
la_vrf_impl::get_unmatched_ipv4_multicast_punt_enabled(la_ipv4_prefix_t group_prefix, bool& out_punt_enabled) const
{
    start_api_getter_call();

    return get_unmatched_multicast_punt_enabled(
        m_device->m_tables.ipv4_lpm_table, group_prefix, LA_IPV4_MC_PREFIX, out_punt_enabled);
}

la_status
la_vrf_impl::set_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix, bool punt_enabled)
{
    start_api_call("group_prefix=", group_prefix, "punt_enabled=", punt_enabled);

    return set_unmatched_multicast_punt_enabled(m_device->m_tables.ipv6_lpm_table, group_prefix, punt_enabled, LA_IPV6_MC_PREFIX);
}

la_status
la_vrf_impl::clear_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix)
{
    start_api_call("group_prefix=", group_prefix);

    return clear_unmatched_multicast_punt_enabled(m_device->m_tables.ipv6_lpm_table, group_prefix, LA_IPV6_MC_PREFIX);
}

la_status
la_vrf_impl::get_unmatched_ipv6_multicast_punt_enabled(la_ipv6_prefix_t group_prefix, bool& out_punt_enabled) const
{
    start_api_getter_call();

    return get_unmatched_multicast_punt_enabled(
        m_device->m_tables.ipv6_lpm_table, group_prefix, LA_IPV6_MC_PREFIX, out_punt_enabled);
}

la_status
la_vrf_impl::do_create_pbr_acl(bool is_ipv4)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::do_destroy_pbr_acl(bool is_ipv4)
{
    auto& acl = is_ipv4 ? m_pbr_v4_acl : m_pbr_v6_acl;
    la_status status;

    if (acl == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    // Destroy ACL object
    auto acl_delegate = acl->get_delegate();
    status = remove_current_ifgs(this, acl_delegate);
    return_on_error(status);

    m_device->remove_object_dependency(acl, this);
    status = m_device->do_destroy(acl);
    return_on_error(status);
    acl = nullptr;

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::destory_pbr_acls()
{
    la_status status;

    status = do_destroy_pbr_acl(true /*is_ipv4*/);
    return_on_error(status);

    status = do_destroy_pbr_acl(false /*is_ipv4*/);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv4_pbr_acl(la_acl*& out_ipv4_pbr_acl)
{
    start_api_call("");

    if (m_pbr_v4_acl == nullptr) {
        la_status status = do_create_pbr_acl(true /*is_ipv4*/);
        return_on_error(status);
    }

    out_ipv4_pbr_acl = m_pbr_v4_acl.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv6_pbr_acl(la_acl*& out_ipv6_pbr_acl)
{
    start_api_call("");

    if (m_pbr_v6_acl == nullptr) {
        la_status status = do_create_pbr_acl(false /*is_ipv4*/);
        return_on_error(status);
    }

    out_ipv6_pbr_acl = m_pbr_v6_acl.get();
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::destroy()
{
    if (m_device->is_in_use(this)) {
        return LA_STATUS_EBUSY;
    }

    la_status status = clear_all_ip_routes(
        m_device->m_tables.ipv4_lpm_table, m_device->m_tables.ipv4_vrf_dip_em_table, true /* clear_catch_all_entry */);
    return_on_error(status);

    la_ipv4_addr_t illegal_dip_v4 = {.s_addr = 0x0};
    status = delete_em_entry(m_device->m_tables.ipv4_vrf_dip_em_table, illegal_dip_v4);
    return_on_error(status);

    status = clear_all_ip_routes(
        m_device->m_tables.ipv6_lpm_table, m_device->m_tables.ipv6_vrf_dip_em_table, true /* clear_catch_all_entry */);
    return_on_error(status);

    la_ipv6_addr_t illegal_dip_v6 = {.s_addr = 0x0};
    status = delete_em_entry(m_device->m_tables.ipv6_vrf_dip_em_table, illegal_dip_v6);
    return_on_error(status);

    status = clear_all_ipv4_multicast_routes();
    return_on_error(status);

    status = clear_all_ipv6_multicast_routes();
    return_on_error(status);

    status = destory_pbr_acls();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

static uint64_t
signal_sflow(const la_l3_port_wcptr& l3_port, uint64_t orig_dest_val)
{
    bool sflow_enabled = false;
    la_status status = l3_port->get_egress_sflow_enabled(sflow_enabled);
    dassert_crit(status == LA_STATUS_SUCCESS);

    uint64_t sflow_bit = 1; // First bit signals sflow.
    if (sflow_enabled) {
        return orig_dest_val |= sflow_bit;
    } else {
        return orig_dest_val &= ~sflow_bit;
    }
}

template <class _TableType, class _PrefixType>
la_status
la_vrf_impl::update_ip_subnet(const std::shared_ptr<_TableType>& table, _PrefixType subnet, const la_l3_port_wcptr& l3_port)
{
    if (!is_prefix_valid(subnet)) {
        return LA_STATUS_EINVAL;
    }

    // Find existing entry
    typename _TableType::key_type key;
    populate_lpm_key(subnet.addr, key);
    typename _TableType::entry_wptr_type entry;
    la_status status = table->lookup(key, entry);
    return_on_error(status);

    // Update sflow bit
    typename _TableType::value_type value(entry->value());
    npl_destination_t& dest = value.payloads.lpm_payload.destination;
    dest.val = signal_sflow(l3_port, dest.val);

    // Update table entry
    status = entry->update(value, entry->user_data());
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::update_ipv4_subnet(la_ipv4_prefix_t subnet, const la_l3_port_wcptr& l3_port)
{
    la_status status = update_ip_subnet(m_device->m_tables.ipv4_lpm_table, subnet, l3_port);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_ipv4_subnet(la_ipv4_prefix_t subnet, const la_l3_port_wptr& l3_port)
{
    la_l3_port_gid_t gid = l3_port->get_gid();
    npl_destination_t dest = {.val = NPL_LPM_COMPRESSED_DESTINATION_L3_DLP_SUBNET_MASK | get_l3_dlp_value_from_gid(gid)};
    dest.val = signal_sflow(l3_port, dest.val);
    const auto& table(m_device->m_tables.ipv4_lpm_table);

    la_status status = add_lpm_entry(table, subnet, dest, 0 /* user_data */, false /* latency_sensitive */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::update_ipv6_subnet(la_ipv6_prefix_t subnet, const la_l3_port_wcptr& l3_port)
{
    la_status status = update_ip_subnet(m_device->m_tables.ipv6_lpm_table, subnet, l3_port);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_ipv6_subnet(la_ipv6_prefix_t subnet, const la_l3_port_wptr& l3_port)
{
    if (m_gid >= la_device_impl::IPV6_VRF_GID_RANGE_LIMIT) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_l3_port_gid_t gid = l3_port->get_gid();
    npl_destination_t dest = {.val = NPL_LPM_COMPRESSED_DESTINATION_L3_DLP_SUBNET_MASK | get_l3_dlp_value_from_gid(gid)};
    dest.val = signal_sflow(l3_port, dest.val);
    const auto& table(m_device->m_tables.ipv6_lpm_table);

    la_status status = add_lpm_entry(table, subnet, dest, 0 /* user_data */, false /* latency_sensitive */);

    return status;
}

la_status
la_vrf_impl::delete_ipv4_subnet(la_ipv4_prefix_t subnet)
{
    return delete_ip_subnet(m_device->m_tables.ipv4_lpm_table, subnet);
}

la_status
la_vrf_impl::delete_ipv6_subnet(la_ipv6_prefix_t subnet)
{
    return delete_ip_subnet(m_device->m_tables.ipv6_lpm_table, subnet);
}

template <class _TableType, class _PrefixType>
la_status
la_vrf_impl::delete_ip_subnet(const std::shared_ptr<_TableType>& table, const _PrefixType& subnet)
{
    typename _TableType::key_type key{};
    typename _TableType::entry_wptr_type entry;

    populate_lpm_key(subnet.addr, key);

    la_status status = table->find(key, subnet.length, entry);
    return_on_error(status);

    status = remove_lpm_entry(table, entry, false /* clear catch all entry */);

    return status;
}

la_status
la_vrf_impl::get_ipv4_routing_entry(la_ipv4_prefix_t prefix, la_ip_route_info& out_ip_route_info) const
{
    start_api_getter_call();

    return get_route_info_from_prefix(
        m_device->m_tables.ipv4_lpm_table, m_device->m_tables.ipv4_vrf_dip_em_table, prefix, out_ip_route_info);
}

la_status
la_vrf_impl::get_ipv6_routing_entry(la_ipv6_prefix_t prefix, la_ip_route_info& out_ip_route_info) const
{
    start_api_getter_call();

    return get_route_info_from_prefix(
        m_device->m_tables.ipv6_lpm_table, m_device->m_tables.ipv6_vrf_dip_em_table, prefix, out_ip_route_info);
}

slice_ifg_vec_t
la_vrf_impl::get_ifgs() const
{
    // VRFs don't track IFG usage
    slice_ifg_vec_t enabled_ifgs;
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        la_slice_mode_e slice_mode;
        la_status status = m_device->get_slice_mode(slice, slice_mode);
        if (status != LA_STATUS_SUCCESS) {
            // Shouldn't happen
            log_err(HLD, "la_vrf_impl::%s: get_slice_mode failed %s", __func__, la_status2str(status).c_str());
            return slice_ifg_vec_t();
        }

        if (slice_mode != la_slice_mode_e::NETWORK) {
            continue;
        }

        for (la_ifg_id_t ifg = 0; ifg < NUM_IFGS_PER_SLICE; ifg++) {
            la_slice_ifg slice_ifg = {.slice = slice, .ifg = ifg};
            enabled_ifgs.push_back(slice_ifg);
        }
    }

    return enabled_ifgs;
}

la_status
la_vrf_impl::get_ipv4_route_entries_count(la_uint32_t& out_count) const
{
    start_api_getter_call();

    out_count = 0;
    for (const auto& entry : *(m_device->m_tables.ipv4_lpm_table)) {
        typename npl_ipv4_lpm_table_t::key_type key = entry->key();
        la_vrf_gid_t vrf_gid = get_vrf_gid_from_key(key);

        if (vrf_gid != m_gid) {
            continue;
        }
        out_count++;
    }

    out_count += m_ipv4_em_entries.size();

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv4_route_entries(la_ipv4_route_entry_vec& out_route_entries)
{
    start_api_getter_call();
    out_route_entries.clear();
    la_status status = get_all_ipv4_lpm_routes(m_device->m_tables.ipv4_lpm_table, out_route_entries);
    return_on_error(status);

    status = get_all_ipv4_em_routes(m_device->m_tables.ipv4_vrf_dip_em_table, out_route_entries);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

template <class _TableType>
la_status
la_vrf_impl::get_all_ipv4_lpm_routes(std::shared_ptr<_TableType>& table, la_ipv4_route_entry_vec& out_route_entries)
{
    la_ipv4_route_entry tmp_entry{};
    for (const auto& entry : *table) {
        typename _TableType::key_type key = entry->key();
        la_vrf_gid_t vrf_gid = get_vrf_gid_from_key(key);

        if (vrf_gid != m_gid) {
            continue;
        }

        tmp_entry.prefix.addr.s_addr = key.ipv4_ip_address_address;
        tmp_entry.prefix.length = (la_uint_t)entry->length();
        out_route_entries.push_back(tmp_entry);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_all_ipv4_em_routes(std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& v4_em_table,
                                    la_ipv4_route_entry_vec& out_route_entries)
{
    la_ipv4_route_entry tmp_entry{};
    for (const auto& addr_dest : m_ipv4_em_entries) {
        tmp_entry.prefix.addr = addr_dest.first;
        tmp_entry.prefix.length = 32;
        out_route_entries.push_back(tmp_entry);
    }

    return LA_STATUS_SUCCESS;
}

template <class _TableType>
la_status
la_vrf_impl::get_all_ipv6_lpm_routes(std::shared_ptr<_TableType>& table, la_ipv6_route_entry_vec& out_route_entries)
{
    la_ipv6_route_entry tmp_entry{};
    for (const auto& entry : *table) {
        typename _TableType::key_type key = entry->key();
        la_vrf_gid_t vrf_gid = get_vrf_gid_from_key(key);

        if (vrf_gid != m_gid) {
            continue;
        }

        tmp_entry.prefix.addr.q_addr[0] = key.ipv6_ip_address_address[0];
        tmp_entry.prefix.addr.q_addr[1] = key.ipv6_ip_address_address[1];
        tmp_entry.prefix.length = (la_uint_t)entry->length();
        out_route_entries.push_back(tmp_entry);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_all_ipv6_em_routes(std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& v6_em_table,
                                    la_ipv6_route_entry_vec& out_route_entries)
{
    la_ipv6_route_entry tmp_entry{};
    for (const auto& addr_dest : m_ipv6_em_entries) {
        tmp_entry.prefix.addr.q_addr[0] = addr_dest.first.q_addr[0];
        tmp_entry.prefix.addr.q_addr[1] = addr_dest.first.q_addr[1];
        tmp_entry.prefix.length = 128;
        out_route_entries.push_back(tmp_entry);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv6_route_entries_count(la_uint32_t& out_count) const
{
    start_api_getter_call();
    out_count = 0;
    for (const auto& entry : *(m_device->m_tables.ipv6_lpm_table)) {
        typename npl_ipv6_lpm_table_t::key_type key = entry->key();
        la_vrf_gid_t vrf_gid = get_vrf_gid_from_key(key);

        if (vrf_gid != m_gid) {
            continue;
        }
        out_count++;
    }

    out_count += m_ipv6_em_entries.size();
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::get_ipv6_route_entries(la_ipv6_route_entry_vec& out_route_entries)
{
    start_api_getter_call();
    out_route_entries.clear();
    la_status status = get_all_ipv6_lpm_routes(m_device->m_tables.ipv6_lpm_table, out_route_entries);
    return_on_error(status);

    status = get_all_ipv6_em_routes(m_device->m_tables.ipv6_vrf_dip_em_table, out_route_entries);
    return_on_error(status);
    return LA_STATUS_SUCCESS;
}

la_status
la_vrf_impl::add_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t sgt)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::modify_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t sgt)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::delete_security_group_tag(la_ipv4_prefix_t prefix)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::get_security_group_tag(la_ipv4_prefix_t prefix, la_sgt_t& out_sgt) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::add_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t sgt)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::modify_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t sgt)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::delete_security_group_tag(la_ipv6_prefix_t prefix)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::get_security_group_tag(la_ipv6_prefix_t prefix, la_sgt_t& out_sgt) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_vrf_impl::set_urpf_allow_default(bool enable)
{
    start_api_call("enable=", enable);

    la_status status = LA_STATUS_SUCCESS;
    npl_destination_t lpm_dest;
    m_urpf_allow_default = enable;

    if (m_ipv4_default_entry != nullptr) {
        auto default_value = m_ipv4_default_entry->value();
        if (default_value.payloads.lpm_payload.destination.val != la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION) {
            auto l3_dest
                = m_device
                      ->m_l3_destinations[default_value.payloads.lpm_payload.destination.val & ~DEFAULT_ROUTE_DESTINATION_BIT_MASK];
            status = get_lpm_destination_from_l3_destination(l3_dest, lpm_dest);
            if (status == LA_STATUS_SUCCESS) {
                if (!enable) {
                    lpm_dest.val |= DEFAULT_ROUTE_DESTINATION_BIT_MASK;
                }
                default_value.payloads.lpm_payload.destination = lpm_dest;
                m_ipv4_default_entry->update(default_value, 0);
            }
        }
    }

    if (m_ipv6_default_entry != nullptr) {
        auto default_value = m_ipv6_default_entry->value();
        if (default_value.payloads.lpm_payload.destination.val != la_device_impl::LPM_CATCH_ALL_DROP_DESTINATION) {
            auto l3_dest
                = m_device
                      ->m_l3_destinations[default_value.payloads.lpm_payload.destination.val & ~DEFAULT_ROUTE_DESTINATION_BIT_MASK];
            status = get_lpm_destination_from_l3_destination(l3_dest, lpm_dest);
            if (status == LA_STATUS_SUCCESS) {
                if (!enable) {
                    lpm_dest.val |= DEFAULT_ROUTE_DESTINATION_BIT_MASK;
                }
                default_value.payloads.lpm_payload.destination = lpm_dest;
                m_ipv6_default_entry->update(default_value, 0);
            }
        }
    }

    return status;
}

bool
la_vrf_impl::get_urpf_allow_default() const
{
    return m_urpf_allow_default;
}

} // namespace silicon_one
