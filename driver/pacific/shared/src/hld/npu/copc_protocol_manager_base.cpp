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

#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "copc_protocol_manager_base.h"
#include "la_strings.h"
#include "system/la_device_impl.h"

using namespace std;

namespace silicon_one
{

copc_protocol_manager_base::copc_protocol_manager_base(const la_device_impl_wptr& device) : m_device(device)
{
}

copc_protocol_manager_base::~copc_protocol_manager_base() = default;

la_status
copc_protocol_manager_base::update_entry(const copc_protocol_entry& sdk_entry,
                                         npl_l2_lpts_protocol_table_t::key_type& key,
                                         npl_l2_lpts_protocol_table_t::key_type& mask,
                                         npl_l2_lpts_protocol_table_t::value_type& value)
{
    // Copy L3 protocol and mask
    key.next_protocol_type = static_cast<npl_protocol_type_e>(sdk_entry.l3_protocol & 0x1f);
    if ((sdk_entry.l3_protocol == NPL_PROTOCOL_TYPE_IPV4) || (sdk_entry.l3_protocol == NPL_PROTOCOL_TYPE_IPV6)) {
        mask.next_protocol_type = static_cast<npl_protocol_type_e>(0x0f);
    } else if (sdk_entry.l3_protocol) {
        mask.next_protocol_type = static_cast<npl_protocol_type_e>(0x1f);
    } else {
        mask.next_protocol_type = static_cast<npl_protocol_type_e>(0x0);
    }

    // Copy L4 protocol and mask
    key.next_header_1_type = static_cast<npl_protocol_type_e>(sdk_entry.l4_protocol & 0x1f);
    if (sdk_entry.l4_protocol) {
        mask.next_header_1_type = static_cast<npl_protocol_type_e>(0x1f);
    } else {
        mask.next_header_1_type = static_cast<npl_protocol_type_e>(0x0);
    }

    // Copy Destination Port
    key.dst_udp_port = static_cast<uint64_t>(sdk_entry.dst_port & 0xffff);
    if (sdk_entry.dst_port) {
        mask.dst_udp_port = static_cast<uint64_t>(0xffff);
    } else {
        mask.dst_udp_port = static_cast<uint64_t>(0);
    }

    // Copy copc mac da table bit
    key.mac_da_use_l2_lpts = sdk_entry.mac_da_use_copc;
    if (sdk_entry.mac_da_use_copc) {
        mask.mac_da_use_l2_lpts = true;
    } else {
        mask.mac_da_use_l2_lpts = false;
    }

    // Set COPC protocol table output value.
    value.payloads.use_l2_lpts = true;

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::insert_entry(npl_l2_lpts_protocol_table_t::key_type& key,
                                         npl_l2_lpts_protocol_table_t::key_type& mask,
                                         npl_l2_lpts_protocol_table_t::value_type& value)
{
    size_t location = 0;
    transaction txn;
    const auto& table(m_device->m_tables.l2_lpts_protocol_table);
    npl_l2_lpts_protocol_table_t::entry_pointer_type dummy;

    // Locate a free entry in COPC protocol table
    txn.status = table->locate_first_free_entry(location);
    if (txn.status != LA_STATUS_SUCCESS) {
        if (txn.status == LA_STATUS_ENOTFOUND) {
            txn.status = LA_STATUS_ERESOURCE;
        }
        return_on_error(txn.status);
    }

    // Insert an entry into corresponding location
    txn.status = table->insert(location, key, mask, value, dummy);
    txn.on_fail([&table, location]() { table->erase(location); });
    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::clear_entry(npl_l2_lpts_protocol_table_t::key_type& key, npl_l2_lpts_protocol_table_t::key_type& mask)
{
    size_t location = 0;
    const auto& table(m_device->m_tables.l2_lpts_protocol_table);
    npl_l2_lpts_protocol_table_t::entry_pointer_type dummy;

    // Find table location of a given entry
    la_status status = table->find(key, mask, dummy, location);
    return_on_error(status);

    // Erase entry from particular location
    status = table->erase(location);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::populate_copc_entry(const la_control_plane_classifier::protocol_table_data& copc_protocol_data,
                                                copc_protocol_entry& copc_entry)
{
    // Update L3 protocol
    switch (copc_protocol_data.l3_protocol) {
    case la_ip_version_e::IPV4:
        copc_entry.l3_protocol = NPL_PROTOCOL_TYPE_IPV4;
        break;
    case la_ip_version_e::IPV6:
        copc_entry.l3_protocol = NPL_PROTOCOL_TYPE_IPV6;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    // Update L4 protocol
    switch (copc_protocol_data.l4_protocol) {
    case la_l4_protocol_e::ICMP:
        copc_entry.l4_protocol = NPL_PROTOCOL_TYPE_ICMP;
        break;
    case la_l4_protocol_e::TCP:
        copc_entry.l4_protocol = NPL_PROTOCOL_TYPE_TCP;
        break;
    case la_l4_protocol_e::UDP:
        copc_entry.l4_protocol = NPL_PROTOCOL_TYPE_UDP;
        break;
    default:
        // Need to Add IGMP and V6 extension header
        return LA_STATUS_EINVAL;
    }

    // Update destination port
    copc_entry.dst_port = static_cast<uint64_t>(copc_protocol_data.dst_port);

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::convert_copc_entry(const copc_protocol_entry& copc_entry,
                                               la_control_plane_classifier::protocol_table_data& copc_protocol_data)
{
    // Update L3 protocol
    switch (copc_entry.l3_protocol) {
    case NPL_PROTOCOL_TYPE_IPV4:
        copc_protocol_data.l3_protocol = la_ip_version_e::IPV4;
        break;
    case NPL_PROTOCOL_TYPE_IPV6:
        copc_protocol_data.l3_protocol = la_ip_version_e::IPV6;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    // Update L4 protocol
    switch (copc_entry.l4_protocol) {
    case NPL_PROTOCOL_TYPE_ICMP:
        copc_protocol_data.l4_protocol = la_l4_protocol_e::ICMP;
        break;
    case NPL_PROTOCOL_TYPE_TCP:
        copc_protocol_data.l4_protocol = la_l4_protocol_e::TCP;
        break;
    case NPL_PROTOCOL_TYPE_UDP:
        copc_protocol_data.l4_protocol = la_l4_protocol_e::UDP;
        break;
    default:
        // Need to Add IGMP and V6 extension header
        return LA_STATUS_EINVAL;
    }

    // Update destination port
    copc_protocol_data.dst_port = static_cast<la_uint16_t>(copc_entry.dst_port);

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::initialize()
{
    std::vector<copc_protocol_entry> entries;
    copc_protocol_entry se;

    // ARP
    se.l3_protocol = NPL_PROTOCOL_TYPE_ARP;
    se.l4_protocol = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.dst_port = 0;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // PTP
    se.l3_protocol = NPL_PROTOCOL_TYPE_PTP;
    se.l4_protocol = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.dst_port = 0;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // ICMP - IPv6
    se.l3_protocol = NPL_PROTOCOL_TYPE_IPV6;
    se.l4_protocol = NPL_PROTOCOL_TYPE_ICMP;
    se.dst_port = 0;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // IGMP - IPv4
    se.l3_protocol = NPL_PROTOCOL_TYPE_IPV4;
    se.l4_protocol = NPL_PROTOCOL_TYPE_IGMP;
    se.dst_port = 0;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // DHCP IPv4 - Server (To)
    se.l3_protocol = NPL_PROTOCOL_TYPE_IPV4;
    se.l4_protocol = NPL_PROTOCOL_TYPE_UDP;
    se.dst_port = 67;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // DHCP IPv6 - Server (To)
    se.l3_protocol = NPL_PROTOCOL_TYPE_IPV6;
    se.l4_protocol = NPL_PROTOCOL_TYPE_UDP;
    se.dst_port = 547;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // DHCP IPv4 - Client (To)
    se.l3_protocol = NPL_PROTOCOL_TYPE_IPV4;
    se.l4_protocol = NPL_PROTOCOL_TYPE_UDP;
    se.dst_port = 68;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // DHCP IPv6 - Client (To)
    se.l3_protocol = NPL_PROTOCOL_TYPE_IPV6;
    se.l4_protocol = NPL_PROTOCOL_TYPE_UDP;
    se.dst_port = 546;
    se.mac_da_use_copc = false;
    entries.push_back(se);

    // Add default entry to set use_copc bit when mac_da_use_copc is set
    se.l3_protocol = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.l4_protocol = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.dst_port = 0;
    se.mac_da_use_copc = true;
    entries.push_back(se);

    for (auto entry : entries) {
        npl_l2_lpts_protocol_table_t::key_type key;
        npl_l2_lpts_protocol_table_t::key_type mask;
        npl_l2_lpts_protocol_table_t::value_type value;

        update_entry(entry, key, mask, value);

        // Insert an entry into COPC protocol table
        la_status status = insert_entry(key, mask, value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::add(const la_control_plane_classifier::protocol_table_data& copc_protocol_data)
{
    copc_protocol_entry copc_entry;

    // Populate copc entry
    la_status status = populate_copc_entry(copc_protocol_data, copc_entry);
    return_on_error(status);

    npl_l2_lpts_protocol_table_t::key_type key;
    npl_l2_lpts_protocol_table_t::key_type mask;
    npl_l2_lpts_protocol_table_t::value_type value;

    // mac_da_use_copc should be set to false for all dynamic entries
    key.mac_da_use_l2_lpts = false;
    mask.mac_da_use_l2_lpts = false;

    update_entry(copc_entry, key, mask, value);

    // Insert an entry into COPC protocol table
    status = insert_entry(key, mask, value);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::remove(const la_control_plane_classifier::protocol_table_data& copc_protocol_data)
{
    copc_protocol_entry copc_entry;

    // Populate copc entry
    la_status status = populate_copc_entry(copc_protocol_data, copc_entry);
    return_on_error(status);

    npl_l2_lpts_protocol_table_t::key_type key;
    npl_l2_lpts_protocol_table_t::key_type mask;
    npl_l2_lpts_protocol_table_t::value_type value;

    // mac_da_use_copc should be set to false in case of dynamic entries
    key.mac_da_use_l2_lpts = false;
    mask.mac_da_use_l2_lpts = false;

    update_entry(copc_entry, key, mask, value);

    // Erase specific entry from COPC protocol table
    status = clear_entry(key, mask);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::clear()
{
    // Get total number of COPC protocol entries
    size_t entries_total = m_device->m_tables.l2_lpts_protocol_table->size();

    // Get all entries from COPC protocol table
    vector_alloc<npl_l2_lpts_protocol_table_t::entry_pointer_type> entries(entries_total, nullptr);
    size_t entries_num = m_device->m_tables.l2_lpts_protocol_table->get_entries(&entries[0], entries_total);
    dassert_ncrit(entries_num <= entries_total);

    // Clear all dynamic entries from COPC protocol table
    for (size_t i = 0; i < entries_num; i++) {
        npl_l2_lpts_protocol_table_t::key_type key(entries[i]->key());
        npl_l2_lpts_protocol_table_t::key_type mask(entries[i]->mask());

        // Skip static entry
        if (key.mac_da_use_l2_lpts == true) {
            continue;
        }

        // Erase specific entry from COPC protocol table
        la_status status = clear_entry(key, mask);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
copc_protocol_manager_base::get(la_control_plane_classifier::protocol_table_data_vec& out_la_copc_protocol_vec)
{
    // Get total number of COPC protocol entries
    size_t entries_total = m_device->m_tables.l2_lpts_protocol_table->size();

    // Get all entries from COPC protocol table
    vector_alloc<npl_l2_lpts_protocol_table_t::entry_pointer_type> entries(entries_total, nullptr);
    size_t entries_num = m_device->m_tables.l2_lpts_protocol_table->get_entries(&entries[0], entries_total);
    dassert_ncrit(entries_num <= entries_total);

    // Update all dynamic entries from COPC protocol table to sdk structure
    for (size_t i = 0; i < entries_num; i++) {
        copc_protocol_entry entry;
        la_control_plane_classifier::protocol_table_data copc_data;
        npl_l2_lpts_protocol_table_t::key_type k(entries[i]->key());

        // Skip static entry
        if (k.mac_da_use_l2_lpts == true) {
            continue;
        }
        // Push entry to output vector
        entry.l3_protocol = k.next_protocol_type;
        entry.l4_protocol = k.next_header_1_type;
        entry.dst_port = k.dst_udp_port;

        // Convert protocol entries
        la_status status = convert_copc_entry(entry, copc_data);
        return_on_error(status);
        out_la_copc_protocol_vec.push_back(copc_data);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
