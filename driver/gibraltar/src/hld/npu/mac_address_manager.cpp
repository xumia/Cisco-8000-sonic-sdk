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
#include "la_strings.h"
#include "mac_address_manager.h"
#include "system/la_device_impl.h"

using namespace std;

namespace silicon_one
{

mac_address_manager::mac_address_manager(const la_device_impl_wptr& device) : m_device(device)
{
}

la_status
mac_address_manager::initialize()
{
    struct static_entry {
        la_mac_addr_t addr;
        la_mac_addr_t mask;
        npl_mac_da_type_e type;
        npl_protocol_type_e prot_type;
        bool use_l2_lpts;
        bool mac_l2_lpts_lkup;
    };

    vector<static_entry> entries;

    // IPv4 MC
    static_entry se;
    se.addr.flat = 0x01005e000000ULL;
    se.mask.flat = 0xffffff800000ULL;
    se.type = NPL_MAC_DA_TYPE_IPV4_COMP_MC;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 0;
    se.mac_l2_lpts_lkup = 0;
    entries.push_back(se);

    // IPv6 MC
    se.addr.flat = 0x333300000000ULL;
    se.mask.flat = 0xffff00000000ULL;
    se.type = NPL_MAC_DA_TYPE_IPV6_COMP_MC;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 0;
    se.mac_l2_lpts_lkup = 0;
    entries.push_back(se);

    // ISIS (two entries)
    se.addr.flat = 0x0180c2000014ULL;
    se.mask.flat = 0xfffffffffffeULL;
    se.type = NPL_MAC_DA_TYPE_ISIS;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 1;
    se.mac_l2_lpts_lkup = 1;
    entries.push_back(se);

    se.addr.flat = 0x09002b000004ULL;
    se.mask.flat = 0xfffffffffffeULL;
    se.type = NPL_MAC_DA_TYPE_ISIS;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 1;
    se.mac_l2_lpts_lkup = 1;
    entries.push_back(se);

    se.addr.flat = 0x01005e900002ULL;
    se.mask.flat = 0xfffffffffffeULL;
    se.type = NPL_MAC_DA_TYPE_ISIS;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 1;
    se.mac_l2_lpts_lkup = 1;
    entries.push_back(se);

    // L2CP - Must be lower priority than CFM and ISIS
    se.addr.flat = 0x0180c2000000ULL;
    se.mask.flat = 0xffffffffff00ULL; // ignore last byte
    se.type = NPL_MAC_DA_TYPE_L2CP;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 1;
    se.mac_l2_lpts_lkup = 1;
    entries.push_back(se);

    // CDP   01:00:0C:CC:CC:CC
    // VTP   01:00:0C:CC:CC:CC
    // DTP   01:00:0C:CC:CC:CC
    // PAgP  01:00:0C:CC:CC:CC
    // UDLD  01:00:0C:CC:CC:CC
    // PVSTP 01:00:0C:CC:CC:CD
    se.addr.flat = 0x01000CCCCCCCULL;
    se.mask.flat = 0xfffffffffffeULL;
    se.type = NPL_MAC_DA_TYPE_CISCO_PROTOCOLS;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 1;
    se.mac_l2_lpts_lkup = 1;
    entries.push_back(se);

    // BFD V4 Micro
    se.addr.flat = 0x01005e900001ULL;
    se.mask.flat = 0xffffffffffffULL;
    se.type = NPL_MAC_DA_TYPE_IPV4_COMP_MC;
    se.prot_type = NPL_PROTOCOL_TYPE_IPV4;
    se.use_l2_lpts = 0;
    se.mac_l2_lpts_lkup = 0;
    entries.push_back(se);

    // BFD V6 Micro
    se.addr.flat = 0x01005e900001ULL;
    se.mask.flat = 0xffffffffffffULL;
    se.type = NPL_MAC_DA_TYPE_IPV6_COMP_MC;
    se.prot_type = NPL_PROTOCOL_TYPE_IPV6;
    se.use_l2_lpts = 0;
    se.mac_l2_lpts_lkup = 0;
    entries.push_back(se);

    // MACSEC
    se.addr.flat = 0x0ULL;
    se.mask.flat = 0x0ULL;
    se.type = NPL_MAC_DA_TYPE_UC;
    se.prot_type = NPL_PROTOCOL_TYPE_MACSEC;
    se.use_l2_lpts = 1;
    se.mac_l2_lpts_lkup = 1;
    entries.push_back(se);

    // BCAST
    se.addr.flat = 0xffffffffffffULL;
    se.mask.flat = 0xffffffffffffULL;
    se.type = NPL_MAC_DA_TYPE_BCAST;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 1;
    se.mac_l2_lpts_lkup = 0;
    entries.push_back(se);

    // All Zero
    se.addr.flat = 0x0ULL;
    se.mask.flat = 0xffffffffffffULL;
    se.type = NPL_MAC_DA_TYPE_ZERO;
    se.prot_type = NPL_PROTOCOL_TYPE_UNKNOWN;
    se.use_l2_lpts = 0;
    se.mac_l2_lpts_lkup = 0;
    entries.push_back(se);

    // mac_da_table has no hit indication, so avoid index 0.
    size_t index = 16;

    for (auto entry : entries) {
        const auto& table(m_device->m_tables.mac_da_table);
        npl_mac_da_table_t::entry_pointer_type dummy;
        npl_mac_da_table_t::key_type key;
        npl_mac_da_table_t::key_type mask;
        npl_mac_da_table_t::value_type value;

        key.packet_ethernet_header_da.mac_address = entry.addr.flat;
        mask.packet_ethernet_header_da.mac_address = entry.mask.flat;

        key.next_protocol_type = entry.prot_type;
        if ((entry.prot_type == NPL_PROTOCOL_TYPE_IPV4) || (entry.prot_type == NPL_PROTOCOL_TYPE_IPV6)) {
            mask.next_protocol_type = static_cast<npl_protocol_type_e>(0x0f);
        } else if (entry.prot_type) {
            mask.next_protocol_type = static_cast<npl_protocol_type_e>(0x1f);
        } else {
            mask.next_protocol_type = static_cast<npl_protocol_type_e>(0x0);
        }

        npl_mac_da_t& v(value.payloads.mac_da);
        v.compound_termination_control.append_relay = NPL_APPEND_RELAY;
        v.compound_termination_control.attempt_termination = 1;
        v.type = entry.type;
        v.is_vrrp = 0;
        v.is_ipv4_mc = (v.type == NPL_MAC_DA_TYPE_IPV4_COMP_MC) ? 1 : 0;
        v.is_ipv6_mc = (v.type == NPL_MAC_DA_TYPE_IPV6_COMP_MC) ? 1 : 0;
        v.is_mc = v.is_ipv4_mc | v.is_ipv6_mc;
        // Don't care
        v.prefix = 0;

        // Set use_l2_lpts
        v.use_l2_lpts = entry.use_l2_lpts;
        v.mac_l2_lpts_lkup = entry.mac_l2_lpts_lkup;

        la_status status = table->insert(index, key, mask, value, dummy);
        return_on_error(status);

        index++;
    }

    m_first_dynamic_prefix_index = 1;
    // The number of entries is set to the number of prefixes, as long as the protocol type is ignored
    size_t max_mac_da_table_size
        = NUM_OF_ALLOWED_PREFIXES; // static entries do not have a prefix as they are not used for encapsulating mac

    m_msbs = vector<uint64_t>(max_mac_da_table_size, 0);
    m_msbs_refcount = vector<uint64_t>(max_mac_da_table_size, 0);

    return LA_STATUS_SUCCESS;
}

uint64_t
mac_address_manager::get_lsbits(la_mac_addr_t mac_addr)
{
    uint64_t addr = mac_addr.flat;
    uint64_t mask = (1ULL << NUM_OF_LSB_BITS) - 1;
    uint64_t lsb = (addr & mask);

    return lsb;
}

uint64_t
mac_address_manager::get_msbits(la_mac_addr_t mac_addr)
{
    uint64_t addr = mac_addr.flat;
    addr &= (1ULL << NUM_OF_MAC_ADDR_BITS) - 1; // call it paranoia
    uint64_t msb = (addr >> NUM_OF_LSB_BITS);

    return msb;
}

la_status
mac_address_manager::add(la_mac_addr_t mac_addr, npl_mac_da_type_e type)
{
    uint64_t index;

    // see if the address is already in the list
    la_status status = get_index(mac_addr, index);
    if (status == LA_STATUS_SUCCESS) {
        m_msbs_refcount[index]++;

        return LA_STATUS_SUCCESS;
    }

    // try to find a free dynamic slot for the address
    auto it = std::find(m_msbs_refcount.begin() + m_first_dynamic_prefix_index, m_msbs_refcount.end(), 0);
    if (it == m_msbs_refcount.end()) {

        return LA_STATUS_ERESOURCE;
    }

    index = std::distance(m_msbs_refcount.begin(), it);
    log_debug(HLD, "mac_address_manager::%s: address=%s index=%ld", __func__, to_string(mac_addr).c_str(), index);
    m_msbs[index] = get_msbits(mac_addr);
    m_msbs_refcount[index] = 1;

    // update the address compress/decompress tables in the device
    status = add_to_mac_da_table(mac_addr, index, type);
    return_on_error(status);

    if (type == NPL_MAC_DA_TYPE_UC) {
        status = add_to_sa_prefix_table(mac_addr, index);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_address_manager::remove(la_mac_addr_t mac_addr, npl_mac_da_type_e type)
{
    uint64_t index;

    la_status status = get_index(mac_addr, index);
    return_on_error(status);
    m_msbs_refcount[index]--;

    if (m_msbs_refcount[index] == 0) {
        if (type == NPL_MAC_DA_TYPE_UC) {
            status = remove_from_sa_prefix_table(mac_addr, index);
            return_on_error(status);
        }

        status = remove_from_mac_da_table(mac_addr, index);
        return_on_error(status);

        log_debug(HLD, "mac_address_manager::%s: index=%ld", __func__, index);
    }

    return LA_STATUS_SUCCESS;
}

la_status
mac_address_manager::get_index(la_mac_addr_t mac_addr, uint64_t& out_prefix) const
{
    uint64_t msb = get_msbits(mac_addr);

    for (uint64_t index = m_first_dynamic_prefix_index; index < m_msbs.size(); index++) {
        if ((m_msbs[index] == msb) && (m_msbs_refcount[index] > 0)) {
            out_prefix = index;

            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
mac_address_manager::add_to_mac_da_table(la_mac_addr_t mac_addr, uint64_t index, npl_mac_da_type_e type)
{
    const auto& table(m_device->m_tables.mac_da_table);
    npl_mac_da_table_entry_t* dummy;
    npl_mac_da_table_key_t key;
    npl_mac_da_table_key_t mask;

    key.packet_ethernet_header_da.mac_address = mac_addr.flat;
    key.next_protocol_type = static_cast<npl_protocol_type_e>(0); // Will be masked out anyway
    mask.packet_ethernet_header_da.mac_address = ((1ULL << NUM_OF_MSB_BITS) - 1) << NUM_OF_LSB_BITS;

    // Don't care about the protocol for now. Look only for the DA. When this changes -
    // the size of the indices vectors should be changed to reflect the real size of the table.
    // See setting the size of m_msbs_refcount and m_msbs at initialize().
    mask.next_protocol_type = static_cast<npl_protocol_type_e>(0);

    npl_mac_da_table_value_t value;
    npl_mac_da_t& v(value.payloads.mac_da);
    v.compound_termination_control.append_relay = NPL_APPEND_RELAY;
    v.compound_termination_control.attempt_termination = 1;
    v.type = type;
    v.is_vrrp = 0;
    v.is_ipv4_mc = 0;
    v.is_ipv6_mc = 0;
    v.prefix = index;
    if (type == NPL_MAC_DA_TYPE_CISCO_PROTOCOLS && mac_addr.flat == 0x01000CCDCDD0ULL) {
        v.use_l2_lpts = 1;
        v.mac_l2_lpts_lkup = 1;
    }

    la_status status = table->insert(index, key, mask, value, dummy);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_address_manager::add_to_sa_prefix_table(la_mac_addr_t mac_addr, uint64_t index)
{
    npl_ene_rewrite_sa_prefix_index_table_key_t key;
    npl_ene_rewrite_sa_prefix_index_table_value_t value;
    const auto& table(m_device->m_tables.ene_rewrite_sa_prefix_index_table);
    npl_ene_rewrite_sa_prefix_index_table_entry_t* dummy;

    key.rewrite_sa_index = index;
    value.payloads.sa_msb.msb = get_msbits(mac_addr);
    la_status status = table->insert(key, value, dummy);
    return_on_error(status);

    npl_ene_rewrite_punt_sa_prefix_index_table_key_t k_punt;
    npl_ene_rewrite_punt_sa_prefix_index_table_value_t v_punt;
    const auto& table_punt(m_device->m_tables.ene_rewrite_punt_sa_prefix_index_table);
    npl_ene_rewrite_punt_sa_prefix_index_table_entry_t* dummy_punt;

    k_punt.rewrite_sa_index = index;
    v_punt.payloads.sa_msb.msb = get_msbits(mac_addr);
    status = table_punt->insert(k_punt, v_punt, dummy_punt);
    return_on_error(status);

    return status;
}

la_status
mac_address_manager::remove_from_sa_prefix_table(la_mac_addr_t mac_addr, uint64_t index)
{
    const auto& table(m_device->m_tables.ene_rewrite_sa_prefix_index_table);
    npl_ene_rewrite_sa_prefix_index_table_key_t key;
    key.rewrite_sa_index = index;

    la_status status = table->erase(key);
    return_on_error(status);

    const auto& table_punt(m_device->m_tables.ene_rewrite_punt_sa_prefix_index_table);
    npl_ene_rewrite_punt_sa_prefix_index_table_key_t k_punt;
    k_punt.rewrite_sa_index = index;

    status = table_punt->erase(k_punt);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_address_manager::remove_from_mac_da_table(la_mac_addr_t mac_addr, uint64_t index)
{
    const auto& table(m_device->m_tables.mac_da_table);
    la_status status = table->erase(index);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
mac_address_manager::get_prefix(la_mac_addr_t mac_addr, uint64_t& out_prefix) const
{
    uint64_t index;

    la_status status = get_index(mac_addr, index);
    return_on_error(status);

    out_prefix = index;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
