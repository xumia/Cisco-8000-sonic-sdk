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

#include "la_acl_egress_sec_ipv6.h"
#include "nplapi/npl_types.h"
#include "system/la_device_impl.h"

#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "nplapi/npl_table_types.h"

namespace silicon_one
{

la_acl_egress_sec_ipv6::la_acl_egress_sec_ipv6(const la_device_impl_wptr& device, const la_acl_wptr& parent)
    : la_acl_delegate(device, parent)
{
}

// Object life-cycle API-s
la_status
la_acl_egress_sec_ipv6::initialize(const la_acl_key_profile_base_wcptr& acl_key_profile,
                                   const la_acl_command_profile_base_wcptr& acl_command_profile)
{
    m_acl_key_profile = acl_key_profile;
    m_acl_command_profile = acl_command_profile;

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::destroy()
{
    return clear();
}

la_status
la_acl_egress_sec_ipv6::clear_tcam_line(la_slice_id_t slice, size_t tcam_line)
{
    npl_table_t::entry_pointer_type e1 = nullptr;
    la_status status = m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->get_entry(tcam_line, e1);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    return_on_error(status);

    status = m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->erase(tcam_line);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::copy_npl_to_field(const npl_table_t::key_type& npl_key,
                                          const npl_table_t::key_type& npl_mask,
                                          la_acl_field_def acl_field_def,
                                          la_acl_field& acl_field) const
{
    switch (acl_field_def.type) {
    // Base protocol header - the first protocol on the packet (IPv6)
    case la_acl_field_type_e::IPV6_SIP:
        acl_field.type = la_acl_field_type_e::IPV6_SIP;
        acl_field.val.ipv6_sip.q_addr[0] = npl_key.sip[0];
        acl_field.val.ipv6_sip.q_addr[1] = npl_key.sip[1];
        acl_field.mask.ipv6_sip.q_addr[0] = npl_mask.sip[0];
        acl_field.mask.ipv6_sip.q_addr[1] = npl_mask.sip[1];
        break;
    case la_acl_field_type_e::IPV6_DIP:
        acl_field.type = la_acl_field_type_e::IPV6_DIP;
        acl_field.val.ipv6_dip.q_addr[0] = npl_key.dip[0];
        acl_field.val.ipv6_dip.q_addr[1] = npl_key.dip[1];
        acl_field.mask.ipv6_dip.q_addr[0] = npl_mask.dip[0];
        acl_field.mask.ipv6_dip.q_addr[1] = npl_mask.dip[1];
        break;
    case la_acl_field_type_e::TOS:
        acl_field.type = la_acl_field_type_e::TOS;
        acl_field.val.tos.fields.dscp = npl_key.qos_tag;
        acl_field.mask.tos.fields.dscp = npl_mask.qos_tag;
        break;
    case la_acl_field_type_e::LAST_NEXT_HEADER:
        acl_field.type = la_acl_field_type_e::LAST_NEXT_HEADER;
        acl_field.val.last_next_header = npl_key.next_header;
        acl_field.mask.last_next_header = npl_mask.next_header;
        break;

    // "Base protocol + 1" header (TCP)
    case la_acl_field_type_e::SPORT:
        acl_field.type = la_acl_field_type_e::SPORT;
        acl_field.val.sport = npl_key.src_port;
        acl_field.mask.sport = npl_mask.src_port;
        break;
    case la_acl_field_type_e::MSG_CODE:
        acl_field.type = la_acl_field_type_e::MSG_CODE;
        acl_field.val.sport = npl_key.src_port;
        acl_field.mask.sport = npl_mask.src_port;
        break;
    case la_acl_field_type_e::MSG_TYPE:
        acl_field.type = la_acl_field_type_e::MSG_TYPE;
        acl_field.val.sport = (npl_key.src_port >> 8);
        acl_field.mask.sport = (npl_mask.src_port >> 8);
        break;
    case la_acl_field_type_e::DPORT:
        acl_field.type = la_acl_field_type_e::DPORT;
        acl_field.val.dport = npl_key.dst_port;
        acl_field.mask.dport = npl_mask.dst_port;
        break;
    case la_acl_field_type_e::TCP_FLAGS:
        acl_field.type = la_acl_field_type_e::TCP_FLAGS;
        acl_field.val.tcp_flags.flat = npl_key.tcp_flags;
        acl_field.mask.tcp_flags.flat = npl_mask.tcp_flags;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::copy_npl_to_key_mask(const npl_table_t::key_type& npl_key,
                                             const npl_table_t::key_type& npl_mask,
                                             la_acl_key& out_key_mask) const
{
    la_acl_field acl_field;
    for (auto acl_field_def : LA_ACL_KEY_IPV6) {
        memset(&acl_field, 0, sizeof(acl_field));

        la_status status = copy_npl_to_field(npl_key, npl_mask, acl_field_def, acl_field);
        return_on_error(status);

        out_key_mask.push_back(acl_field);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::copy_field_to_npl(const la_acl_field acl_field,
                                          npl_table_t::key_type& npl_key,
                                          npl_table_t::key_type& npl_mask) const
{
    switch (acl_field.type) {
    // Base protocol header - the first protocol on the packet (IPv6)
    case la_acl_field_type_e::IPV6_SIP:
        npl_key.sip[0] = acl_field.val.ipv6_sip.q_addr[0];
        npl_key.sip[1] = acl_field.val.ipv6_sip.q_addr[1];
        npl_mask.sip[0] = acl_field.mask.ipv6_sip.q_addr[0];
        npl_mask.sip[1] = acl_field.mask.ipv6_sip.q_addr[1];
        break;
    case la_acl_field_type_e::IPV6_DIP:
        npl_key.dip[0] = acl_field.val.ipv6_dip.q_addr[0];
        npl_key.dip[1] = acl_field.val.ipv6_dip.q_addr[1];
        npl_mask.dip[0] = acl_field.mask.ipv6_dip.q_addr[0];
        npl_mask.dip[1] = acl_field.mask.ipv6_dip.q_addr[1];
        break;
    case la_acl_field_type_e::TOS:
        npl_key.qos_tag = acl_field.val.tos.fields.dscp;
        npl_mask.qos_tag = acl_field.mask.tos.fields.dscp;
        break;
    case la_acl_field_type_e::LAST_NEXT_HEADER:
        npl_key.next_header = acl_field.val.last_next_header;
        npl_mask.next_header = acl_field.mask.last_next_header;
        break;

    // "Base protocol + 1" header (TCP)
    case la_acl_field_type_e::SPORT:
        npl_key.src_port = acl_field.val.sport;
        npl_mask.src_port = acl_field.mask.sport;
        break;
    case la_acl_field_type_e::MSG_CODE:
        npl_key.src_port = bit_utils::set_bits(npl_key.src_port, 7, 0, acl_field.val.mcode);
        npl_mask.src_port = bit_utils::set_bits(npl_mask.src_port, 7, 0, acl_field.mask.mcode);
        break;
    case la_acl_field_type_e::MSG_TYPE:
        npl_key.src_port = bit_utils::set_bits(npl_key.src_port, 15, 8, acl_field.val.mtype);
        npl_mask.src_port = bit_utils::set_bits(npl_mask.src_port, 15, 8, acl_field.mask.mtype);
        break;
    case la_acl_field_type_e::DPORT:
        npl_key.dst_port = acl_field.val.dport;
        npl_mask.dst_port = acl_field.mask.dport;
        break;
    case la_acl_field_type_e::TCP_FLAGS:
        npl_key.tcp_flags = acl_field.val.tcp_flags.flat;
        npl_mask.tcp_flags = acl_field.mask.tcp_flags.flat;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::copy_key_mask_to_npl(la_slice_id_t slice,
                                             const la_acl_key& key_mask,
                                             npl_table_t::key_type& npl_key,
                                             npl_table_t::key_type& npl_mask) const
{
    // ACL ID
    npl_key.acl_id = m_slice_pair_data[slice / 2].acl_id;
    npl_mask.acl_id = 0xF;

    for (const auto acl_field : key_mask) {
        la_status status = copy_field_to_npl(acl_field, npl_key, npl_mask);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
la_acl_egress_sec_ipv6::get_tcam_size(la_slice_id_t slice) const
{
    return m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->max_size();
}

la_status
la_acl_egress_sec_ipv6::get_tcam_max_available_space(la_slice_id_t slice, size_t& out_space) const
{
    return m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->get_available_entries(out_space);
}

size_t
la_acl_egress_sec_ipv6::get_tcam_fullness(la_slice_id_t slice) const
{
    return m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->size();
}

la_status
la_acl_egress_sec_ipv6::copy_entry_to_npl(la_slice_id_t slice,
                                          const la_acl_key& key_val,
                                          const la_acl_command_actions& cmd,
                                          npl_table_t::key_type& k1,
                                          npl_table_t::key_type& m1,
                                          npl_table_t::value_type& v1)
{
    la_status status = copy_key_mask_to_npl(slice, key_val, k1, m1);
    return_on_error(status);

    status = copy_acl_command_to_npl(slice, cmd, v1.payloads.sec_action);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::set_tcam_line(la_slice_id_t slice,
                                      size_t tcam_line,
                                      bool is_push,
                                      const la_acl_key& key_val,
                                      const la_acl_command_actions& cmd)
{
    npl_table_t::key_type k1{};
    npl_table_t::key_type m1{};
    npl_table_t::value_type v1{};
    npl_table_t::entry_pointer_type e1 = nullptr;

    la_status status = copy_entry_to_npl(slice, key_val, cmd, k1, m1, v1);
    return_on_error(status);

    if (is_push) {
        status = m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->push(tcam_line, k1, m1, v1, e1);
    } else {
        status = m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->set(tcam_line, k1, m1, v1, e1);
    }

    return status;
}

la_status
la_acl_egress_sec_ipv6::push_tcam_lines(la_slice_id_t slice,
                                        size_t first_tcam_line,
                                        size_t entries_num,
                                        const vector_alloc<acl_entry_desc>& entries)
{
    vector_alloc<npl_table_t::npl_entry_desc> entries_info(entries_num);

    for (size_t i = 0; i < entries_num; i++) {
        npl_table_t::key_type k{};
        npl_table_t::key_type m{};
        npl_table_t::value_type v{};

        la_status status = copy_entry_to_npl(slice, entries[i].key_val, entries[i].cmd_actions, k, m, v);
        return_on_error(status);

        entries_info[i].key = k;
        entries_info[i].mask = m;
        entries_info[i].value = v;
    }

    la_status status
        = m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->push_bulk(first_tcam_line, entries_num, entries_info);

    return status;
}

la_status
la_acl_egress_sec_ipv6::locate_free_tcam_line_after_last_entry(la_slice_id_t slice, size_t& position) const
{
    return m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->get_free_tcam_line_after_last_entry(position);
}

la_status
la_acl_egress_sec_ipv6::get_tcam_line(la_slice_id_t slice,
                                      size_t tcam_line,
                                      la_acl_key& out_key_val,
                                      la_acl_command_actions& out_cmd) const
{
    npl_table_t::entry_pointer_type e1 = nullptr;

    la_status status = m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->get_entry(tcam_line, e1);
    return_on_error(status);

    npl_table_t::key_type k1 = e1->key();
    npl_table_t::key_type m1 = e1->mask();
    npl_table_t::value_type v1 = e1->value();

    status = copy_npl_to_key_mask(k1, m1, out_key_val);
    return_on_error(status);
    copy_npl_to_acl_command(v1.payloads.sec_action, out_cmd);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::is_tcam_line_contains_ace(la_slice_id_t slice, size_t tcam_line, bool& contains) const
{
    npl_table_t::entry_pointer_type e1 = nullptr;
    la_status status = m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->get_entry(tcam_line, e1);

    if (status == LA_STATUS_ENOTFOUND) {
        // Empty
        contains = false;
        return LA_STATUS_SUCCESS;
    }

    return_on_error(status);

    contains = (e1->key().acl_id == m_slice_pair_data[slice / 2].acl_id);
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_egress_sec_ipv6::erase_tcam_line(la_slice_id_t slice, size_t tcam_line)
{
    return m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->pop(tcam_line);
}

la_status
la_acl_egress_sec_ipv6::locate_free_tcam_entry(la_slice_id_t slice, size_t start, size_t& position) const
{
    return m_device->m_tables.default_egress_ipv6_acl_sec_table[slice]->locate_free_entry(start, position);
}

la_status
la_acl_egress_sec_ipv6::allocate_acl_id(la_slice_pair_id_t slice_pair)
{
    return allocate_ipv6_egress_sec_acl_id(slice_pair);
}

la_status
la_acl_egress_sec_ipv6::release_acl_id(la_slice_pair_id_t slice_pair)
{
    return release_ipv6_egress_sec_acl_id(slice_pair);
}
}
