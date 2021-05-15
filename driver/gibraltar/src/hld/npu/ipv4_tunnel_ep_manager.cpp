// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "ipv4_tunnel_ep_manager.h"
#include "api/npu/la_vrf.h"
#include "common/bit_utils.h"
#include "common/logger.h"
#include "la_strings.h"
#include "nplapi/npl_constants.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

#include <sstream>
#include <tuple>

// Only the bits [3:2] of the 5-bit L4 protocol type are used as key for my_ipv4_table
// This reduces the key-size
#define L4_PROTOCOL_SEL(l4_protocol_type) ((l4_protocol_type >> 2) & 0x3UL)

namespace silicon_one
{

ipv4_tunnel_ep_manager::ipv4_tunnel_ep_manager(const la_device_impl_wptr& device) : m_device(device)
{
}

const la_device_impl_wptr&
ipv4_tunnel_ep_manager::get_device() const
{
    return m_device;
}

la_status
ipv4_tunnel_ep_manager::add_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                           const la_vrf_wcptr& vrf,
                                           uint64_t sip_index,
                                           npl_protocol_type_e l4_protocol_type,
                                           npl_termination_logical_db_e db)
{
    // check if the local_ip_prefix is already programmed.
    // if not, programm it in the my_ipv4_table and set the refcount to 1
    // if already programmed, increase the refcount by 1
    ipv4_tunnel_ep_t local_ep;
    uint64_t l4_protocol_sel = L4_PROTOCOL_SEL(l4_protocol_type);
    local_ep.ipv4_prefix = local_ip_prefix;
    local_ep.relay_id = vrf->get_gid();
    local_ep.l4_protocol_sel = (uint8_t)l4_protocol_sel;

    if (m_ipv4_tunnel_ep_map.find(local_ep) == m_ipv4_tunnel_ep_map.end()) {
        ipv4_tunnel_entry_t ep_entry;

        memset(&ep_entry, 0, sizeof(ep_entry));

        for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {

            // insert it to the my_ipv4_table
            const auto& table(m_device->m_tables.my_ipv4_table[slice]);
            npl_my_ipv4_table_t::key_type key;
            npl_my_ipv4_table_t::key_type mask;
            npl_my_ipv4_table_t::value_type value;
            npl_my_ipv4_table_t::entry_type* dummy;

            key.l3_relay_id.id = local_ep.relay_id;
            key.dip = local_ep.ipv4_prefix.addr.s_addr;
            key.l4_protocol_type_3_2 = l4_protocol_sel;
            mask.l3_relay_id.id = la_device_impl::MAX_VRF_GID - 1;
            mask.dip
                = bit_utils::get_range_mask(bit_utils::BITS_IN_UINT32 - local_ep.ipv4_prefix.length, local_ep.ipv4_prefix.length);
            mask.l4_protocol_type_3_2 = 0x3UL;

            value.action = NPL_MY_IPV4_TABLE_ACTION_WRITE;
            value.payloads.ip_tunnel_termination_attr.ip_termination_type = db;
            value.payloads.ip_tunnel_termination_attr.ip_tunnel_termination_attr_or_slp.sip_ip_tunnel_termination_attr.my_dip_index
                = sip_index;
            value.payloads.ip_tunnel_termination_attr.ip_tunnel_termination_attr_or_slp.sip_ip_tunnel_termination_attr
                .vxlan_tunnel_loopback
                = sip_index;

            size_t entry_loc = -1; // without the initialization, Werror yell for no apparent reason
            bool allocated = m_device->m_index_generators.slice[slice].my_ipv4_table_id.allocate(entry_loc);
            if (!allocated) {
                log_err(HLD,
                        "my_ipv4_table index allocation failed, vrf=%u, ipv4 address=%s//%u",
                        vrf->get_gid(),
                        silicon_one::to_string(local_ip_prefix.addr).c_str(),
                        local_ip_prefix.length);
                return LA_STATUS_ERESOURCE;
            }

            // insert to the free location
            la_status status = table->insert(entry_loc, key, mask, value, dummy);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD,
                        "my_ipv4_table insertion failed (%s), vrf=%u, ipv4 address=%s//%u",
                        la_status2str(status).c_str(),
                        vrf->get_gid(),
                        silicon_one::to_string(local_ip_prefix.addr).c_str(),
                        local_ip_prefix.length);
                return status;
            }

            ep_entry.loc[slice] = entry_loc;
        }

        // set the refcount to 1
        ep_entry.ref_cnt = 1;
        ep_entry.sip_index = sip_index;
        ep_entry.db = db;
        m_ipv4_tunnel_ep_map[local_ep] = ep_entry;
    } else {
        if ((sip_index != m_ipv4_tunnel_ep_map[local_ep].sip_index) || (db != m_ipv4_tunnel_ep_map[local_ep].db)) {
            log_err(HLD, "sip_index or db do not match");
            return LA_STATUS_EINVAL;
        }
        m_ipv4_tunnel_ep_map[local_ep].ref_cnt++;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ipv4_tunnel_ep_manager::remove_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                              const la_vrf_wcptr& vrf,
                                              npl_protocol_type_e l4_protocol_type,
                                              uint64_t sip_index)
{
    ipv4_tunnel_ep_t local_ep;
    uint64_t l4_protocol_sel = L4_PROTOCOL_SEL(l4_protocol_type);
    local_ep.ipv4_prefix = local_ip_prefix;
    local_ep.relay_id = vrf->get_gid();
    local_ep.l4_protocol_sel = (uint8_t)l4_protocol_sel;

    if (m_ipv4_tunnel_ep_map.find(local_ep) == m_ipv4_tunnel_ep_map.end()) {
        log_err(HLD,
                "vrf %u ipv4 address %s//%u not found in vlan endpoint database",
                vrf->get_gid(),
                to_string(local_ip_prefix.addr).c_str(),
                local_ip_prefix.length);
        return LA_STATUS_EINVAL;
    }

    if (m_ipv4_tunnel_ep_map[local_ep].ref_cnt == 0) {
        // this should never happen
        log_err(HLD,
                "internal error: refcount for vrf %u ipv4 address %s//%u is zero",
                vrf->get_gid(),
                to_string(local_ip_prefix.addr).c_str(),
                local_ip_prefix.length);
        return LA_STATUS_EINVAL;
    }

    if (m_ipv4_tunnel_ep_map[local_ep].sip_index != sip_index) {
        log_err(HLD, "sip_index not match");
        return LA_STATUS_EINVAL;
    }

    m_ipv4_tunnel_ep_map[local_ep].ref_cnt--;

    if (m_ipv4_tunnel_ep_map[local_ep].ref_cnt == 0) {
        for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
            const auto& table(m_device->m_tables.my_ipv4_table[slice]);

            uint64_t tunnel_ep_index = m_ipv4_tunnel_ep_map[local_ep].loc[slice];
            la_status status = table->erase(tunnel_ep_index);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD,
                        "my_ipv4_table deletion failed (%s), vrf=%u, ipv4 address=%s//%u",
                        la_status2str(status).c_str(),
                        vrf->get_gid(),
                        to_string(local_ip_prefix.addr).c_str(),
                        local_ip_prefix.length);
                return status;
            }
            m_device->m_index_generators.slice[slice].my_ipv4_table_id.release(tunnel_ep_index);
        }
        m_ipv4_tunnel_ep_map.erase(local_ep);
    }

    return LA_STATUS_SUCCESS;
}

size_t
ipv4_tunnel_ep_manager::size()
{
    return m_ipv4_tunnel_ep_map.size();
}

la_status
ipv4_tunnel_ep_manager::get_local_ep_entry_info(la_ipv4_prefix_t local_ip_prefix,
                                                const la_vrf_wcptr& vrf,
                                                npl_protocol_type_e l4_protocol_type,
                                                uint32_t& ref_cnt,
                                                uint64_t& sip_index,
                                                npl_termination_logical_db_e& term_db)
{
    ipv4_tunnel_ep_t local_ep;
    uint64_t l4_protocol_sel = L4_PROTOCOL_SEL(l4_protocol_type);

    local_ep.ipv4_prefix = local_ip_prefix;
    local_ep.relay_id = vrf->get_gid();
    local_ep.l4_protocol_sel = (uint8_t)l4_protocol_sel;
    if (m_ipv4_tunnel_ep_map.find(local_ep) == m_ipv4_tunnel_ep_map.end()) {
        return LA_STATUS_ENOTFOUND;
    } else {
        ref_cnt = m_ipv4_tunnel_ep_map[local_ep].ref_cnt;
        sip_index = m_ipv4_tunnel_ep_map[local_ep].sip_index;
        term_db = m_ipv4_tunnel_ep_map[local_ep].db;
        return LA_STATUS_SUCCESS;
    }
}

la_status
ipv4_tunnel_ep_manager::add_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                           const la_vrf_wcptr& vrf,
                                           std::vector<uint64_t> sip_index_or_local_slp_id,
                                           npl_protocol_type_e l4_protocol_type,
                                           npl_termination_logical_db_e db)
{
    // check if the local_ip_prefix is already programmed.
    // if not, programm it in the my_ipv4_table and set the refcount to 1
    // if already programmed, increase the refcount by 1
    ipv4_tunnel_ep_t local_ep;
    uint64_t l4_protocol_sel = L4_PROTOCOL_SEL(l4_protocol_type);
    local_ep.ipv4_prefix = local_ip_prefix;
    local_ep.relay_id = vrf->get_gid();
    local_ep.l4_protocol_sel = (uint8_t)l4_protocol_sel;

    if (m_ipv4_tunnel_ep_map.find(local_ep) == m_ipv4_tunnel_ep_map.end()) {
        ipv4_tunnel_entry_t ep_entry;

        memset(&ep_entry, 0, sizeof(ep_entry));

        for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {

            // insert it to the my_ipv4_table
            const auto& table(m_device->m_tables.my_ipv4_table[slice]);
            npl_my_ipv4_table_t::key_type key;
            npl_my_ipv4_table_t::key_type mask;
            npl_my_ipv4_table_t::value_type value;
            npl_my_ipv4_table_t::entry_type* dummy;

            key.l3_relay_id.id = local_ep.relay_id;
            key.dip = local_ep.ipv4_prefix.addr.s_addr;
            key.l4_protocol_type_3_2 = l4_protocol_sel;
            mask.l3_relay_id.id = la_device_impl::MAX_VRF_GID - 1;
            mask.dip
                = bit_utils::get_range_mask(bit_utils::BITS_IN_UINT32 - local_ep.ipv4_prefix.length, local_ep.ipv4_prefix.length);
            mask.l4_protocol_type_3_2 = 0x3UL;

            value.action = NPL_MY_IPV4_TABLE_ACTION_WRITE;
            value.payloads.ip_tunnel_termination_attr.ip_termination_type = db;

            if (db == NPL_TERMINATION_DIP_LDB) {
                value.payloads.ip_tunnel_termination_attr.ip_tunnel_termination_attr_or_slp.tunnel_slp_id.id
                    = sip_index_or_local_slp_id[slice];
            } else {
                value.payloads.ip_tunnel_termination_attr.ip_tunnel_termination_attr_or_slp.sip_ip_tunnel_termination_attr
                    .my_dip_index
                    = sip_index_or_local_slp_id[slice];
                value.payloads.ip_tunnel_termination_attr.ip_tunnel_termination_attr_or_slp.sip_ip_tunnel_termination_attr
                    .vxlan_tunnel_loopback
                    = sip_index_or_local_slp_id[slice];
            }

            size_t entry_loc = -1; // without the initialization, Werror yell for no apparent reason
            la_status status = table->locate_first_free_entry(entry_loc);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD, "failed to find free entry in my_ipv4_table failed (%s)", la_status2str(status).c_str());
                return status;
            }

            // insert to the free location
            status = table->insert(entry_loc, key, mask, value, dummy);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD,
                        "my_ipv4_table insertion failed (%s), vrf=%u, ipv4 address=%s//%u",
                        la_status2str(status).c_str(),
                        vrf->get_gid(),
                        silicon_one::to_string(local_ip_prefix.addr).c_str(),
                        local_ip_prefix.length);
                return status;
            }

            ep_entry.loc[slice] = entry_loc;
        }

        // set the refcount to 1
        ep_entry.ref_cnt = 1;
        ep_entry.sip_index_or_local_slp_id = sip_index_or_local_slp_id;
        ep_entry.db = db;
        m_ipv4_tunnel_ep_map[local_ep] = ep_entry;
    } else {
        for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
            if (m_ipv4_tunnel_ep_map[local_ep].sip_index_or_local_slp_id[slice] != sip_index_or_local_slp_id[slice]) {
                log_err(HLD, "sip_index_or_local_slp_id not match");
                return LA_STATUS_EINVAL;
            }
        }

        if (db != m_ipv4_tunnel_ep_map[local_ep].db) {
            log_err(HLD, "sip_index or db do not match");
            return LA_STATUS_EINVAL;
        }
        m_ipv4_tunnel_ep_map[local_ep].ref_cnt++;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ipv4_tunnel_ep_manager::remove_local_ep_entry(la_ipv4_prefix_t local_ip_prefix,
                                              const la_vrf_wcptr& vrf,
                                              npl_protocol_type_e l4_protocol_type,
                                              std::vector<uint64_t> sip_index_or_local_slp_id)
{
    ipv4_tunnel_ep_t local_ep;
    uint64_t l4_protocol_sel = L4_PROTOCOL_SEL(l4_protocol_type);
    local_ep.ipv4_prefix = local_ip_prefix;
    local_ep.relay_id = vrf->get_gid();
    local_ep.l4_protocol_sel = (uint8_t)l4_protocol_sel;

    if (m_ipv4_tunnel_ep_map.find(local_ep) == m_ipv4_tunnel_ep_map.end()) {
        log_err(HLD,
                "vrf %u ipv4 address %s//%u not found in vlan endpoint database",
                vrf->get_gid(),
                to_string(local_ip_prefix.addr).c_str(),
                local_ip_prefix.length);
        return LA_STATUS_EINVAL;
    }

    if (m_ipv4_tunnel_ep_map[local_ep].ref_cnt == 0) {
        // this should never happen
        log_err(HLD,
                "internal error: refcount for vrf %u ipv4 address %s//%u is zero",
                vrf->get_gid(),
                to_string(local_ip_prefix.addr).c_str(),
                local_ip_prefix.length);
        return LA_STATUS_EINVAL;
    }

    for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
        if (m_ipv4_tunnel_ep_map[local_ep].sip_index_or_local_slp_id[slice] != sip_index_or_local_slp_id[slice]) {
            log_err(HLD, "sip_index not match");
            return LA_STATUS_EINVAL;
        }
    }

    m_ipv4_tunnel_ep_map[local_ep].ref_cnt--;

    if (m_ipv4_tunnel_ep_map[local_ep].ref_cnt == 0) {
        for (la_slice_id_t slice : get_slices(m_device, la_slice_mode_e::NETWORK)) {
            const auto& table(m_device->m_tables.my_ipv4_table[slice]);

            la_status status = table->erase(m_ipv4_tunnel_ep_map[local_ep].loc[slice]);
            if (status != LA_STATUS_SUCCESS) {
                log_err(HLD,
                        "my_ipv4_table deletion failed (%s), vrf=%u, ipv4 address=%s//%u",
                        la_status2str(status).c_str(),
                        vrf->get_gid(),
                        to_string(local_ip_prefix.addr).c_str(),
                        local_ip_prefix.length);
                return status;
            }
        }
        m_ipv4_tunnel_ep_map.erase(local_ep);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ipv4_tunnel_ep_manager::get_local_ep_entry_info(la_ipv4_prefix_t local_ip_prefix,
                                                const la_vrf_wcptr& vrf,
                                                npl_protocol_type_e l4_protocol_type,
                                                uint32_t& ref_cnt,
                                                std::vector<uint64_t>& sip_index_or_local_slp_id,
                                                npl_termination_logical_db_e& term_db)
{
    ipv4_tunnel_ep_t local_ep;
    uint64_t l4_protocol_sel = L4_PROTOCOL_SEL(l4_protocol_type);

    local_ep.ipv4_prefix = local_ip_prefix;
    local_ep.relay_id = vrf->get_gid();
    local_ep.l4_protocol_sel = (uint8_t)l4_protocol_sel;
    if (m_ipv4_tunnel_ep_map.find(local_ep) == m_ipv4_tunnel_ep_map.end()) {
        return LA_STATUS_ENOTFOUND;
    } else {
        ref_cnt = m_ipv4_tunnel_ep_map[local_ep].ref_cnt;
        sip_index_or_local_slp_id = m_ipv4_tunnel_ep_map[local_ep].sip_index_or_local_slp_id;
        term_db = m_ipv4_tunnel_ep_map[local_ep].db;
        return LA_STATUS_SUCCESS;
    }
}
}
