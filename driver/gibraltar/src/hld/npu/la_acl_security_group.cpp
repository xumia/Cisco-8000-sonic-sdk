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

#include "la_acl_security_group.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "nplapi/npl_table_types.h"
#include "nplapi/npl_types.h"

namespace silicon_one
{

la_acl_security_group::la_acl_security_group(const la_device_impl_wptr& device, const la_acl_wptr& parent)
    : la_acl_delegate(device, parent)
{
}

la_acl_security_group::~la_acl_security_group()
{
}

// Object life-cycle API-s
la_status
la_acl_security_group::initialize(const la_acl_key_profile_base_wcptr& acl_key_profile,
                                  const la_acl_command_profile_base_wcptr& acl_command_profile)
{
    m_acl_key_profile = acl_key_profile;
    m_acl_command_profile = acl_command_profile;

    if ((m_sgacl_id = m_device->allocate_security_group_acl_id()) == 0) {
        return LA_STATUS_ERESOURCE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::destroy()
{
    if (m_sgacl_id != 0 && m_sgacl_id != 1) {
        la_status status = m_device->release_security_group_acl_id(m_sgacl_id);
        return_on_error(status);
    }
    return clear();
}

la_status
la_acl_security_group::clear_tcam_line(la_slice_id_t slice, size_t tcam_line)
{
    npl_table_t::entry_pointer_type entry_ptr = nullptr;
    la_status status = m_device->m_tables.sgacl_table[slice]->get_entry(tcam_line, entry_ptr);
    if (status == LA_STATUS_ENOTFOUND) {
        return LA_STATUS_SUCCESS;
    }

    return_on_error(status);

    status = m_device->m_tables.sgacl_table[slice]->erase(tcam_line);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::copy_npl_to_field(const npl_table_t::key_type& npl_key,
                                         const npl_table_t::key_type& npl_mask,
                                         la_acl_field_def acl_field_def,
                                         la_acl_field& acl_field) const
{
    switch (acl_field_def.type) {
    // Base protocol header - the first protocol on the packet (IPv4)
    case la_acl_field_type_e::TOS:
        // TODO: Ask sajay to add TOS NPL field
        // [1..0] ECN
        // [7..2] DSCP
        acl_field.type = la_acl_field_type_e::TOS;
        // acl_field.val.tos.fields.dscp = npl_key.tos.dscp;
        // acl_field.mask.tos.fields.dscp = npl_mask.tos.dscp;
        // acl_field.val.tos.fields.ecn = npl_key.tos.ecn;
        // acl_field.mask.tos.fields.ecn = npl_mask.tos.ecn;
        acl_field.val.tos.fields.dscp = ((npl_key.tos >> 2) & 0x3f);
        acl_field.mask.tos.fields.dscp = ((npl_key.tos >> 2) & 0x3f);
        acl_field.val.tos.fields.ecn = ((npl_key.tos) & 0x03);
        acl_field.mask.tos.fields.ecn = ((npl_key.tos) & 0x03);
        break;
    case la_acl_field_type_e::PROTOCOL:
        acl_field.type = la_acl_field_type_e::PROTOCOL;
        acl_field.val.protocol = npl_key.protocol;
        acl_field.mask.protocol = npl_mask.protocol;
        break;
    case la_acl_field_type_e::TTL:
        acl_field.val.ttl = npl_key.ttl;
        acl_field.mask.ttl = npl_mask.ttl;
        break;
    case la_acl_field_type_e::SPORT:
        acl_field.type = la_acl_field_type_e::SPORT;
        acl_field.val.sport = npl_key.l4_ports.src_port;
        acl_field.mask.sport = npl_mask.l4_ports.src_port;
        break;
    case la_acl_field_type_e::MSG_CODE:
        acl_field.type = la_acl_field_type_e::MSG_CODE;
        acl_field.val.mcode = npl_key.l4_ports.src_port;
        acl_field.mask.mcode = npl_mask.l4_ports.src_port;
        break;
    case la_acl_field_type_e::MSG_TYPE:
        acl_field.type = la_acl_field_type_e::MSG_TYPE;
        acl_field.val.mtype = (npl_key.l4_ports.src_port >> 8);
        acl_field.mask.mtype = (npl_mask.l4_ports.src_port >> 8);
        break;
    case la_acl_field_type_e::DPORT:
        acl_field.type = la_acl_field_type_e::DPORT;
        acl_field.val.dport = npl_key.l4_ports.dst_port;
        acl_field.mask.dport = npl_mask.l4_ports.dst_port;
        break;
    case la_acl_field_type_e::SGACL_BINCODE:
        acl_field.type = la_acl_field_type_e::SGACL_BINCODE;
        acl_field.val.sgacl_bincode = npl_mask.sgacl_id;
        acl_field.mask.sgacl_bincode = npl_key.sgacl_id;
        break;
    case la_acl_field_type_e::TCP_FLAGS:
        acl_field.val.tcp_flags.flat = npl_key.tcp_flags;
        acl_field.mask.tcp_flags.flat = npl_mask.tcp_flags;
        break;
    case la_acl_field_type_e::IPV4_FLAGS:
        acl_field.val.ipv4_flags.fragment = ~npl_key.first_fragment;
        acl_field.mask.ipv4_flags.fragment = npl_mask.first_fragment;
        break;
    case la_acl_field_type_e::IPV6_FRAGMENT:
        acl_field.val.ipv6_fragment.fragment = ~npl_key.first_fragment;
        acl_field.mask.ipv6_fragment.fragment = npl_mask.first_fragment;
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::copy_npl_to_key_mask(const npl_table_t::key_type& npl_key,
                                            const npl_table_t::key_type& npl_mask,
                                            la_acl_key& out_key_mask) const
{
    la_acl_field acl_field;
    for (auto acl_field_def : LA_ACL_KEY_SECURITY_GROUP) {
        memset(&acl_field, 0, sizeof(acl_field));

        la_status status = copy_npl_to_field(npl_key, npl_mask, acl_field_def, acl_field);
        return_on_error(status);

        out_key_mask.push_back(acl_field);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::copy_field_to_npl(const la_acl_field acl_field,
                                         npl_table_t::key_type& npl_key,
                                         npl_table_t::key_type& npl_mask) const
{
    switch (acl_field.type) {
    // Base protocol header - the first protocol on the packet (IPv4)
    case la_acl_field_type_e::TOS:
        // TODO: Ask sajay to add TOS NPL field
        // [1..0] ECN
        // [7..2] DSCP
        // npl_key.tos.dscp = acl_field.val.tos.fields.dscp;
        // npl_mask.tos.dscp = acl_field.mask.tos.fields.dscp;
        // npl_key.tos.ecn = acl_field.val.tos.fields.ecn;
        // npl_mask.tos.ecn = acl_field.mask.tos.fields.ecn;
        npl_key.tos = acl_field.val.tos.fields.dscp;
        npl_mask.tos = acl_field.mask.tos.fields.dscp;
        npl_key.tos = (npl_key.tos << 2);
        npl_key.tos |= ((acl_field.val.tos.fields.ecn) & 0x3);
        npl_mask.tos = (npl_mask.tos << 2);
        npl_mask.tos |= ((acl_field.mask.tos.fields.ecn) & 0x3);
        break;
    case la_acl_field_type_e::PROTOCOL:
        npl_key.protocol = acl_field.val.protocol;
        npl_mask.protocol = acl_field.mask.protocol;
        break;
    case la_acl_field_type_e::TTL:
        npl_key.ttl = acl_field.val.ttl;
        npl_mask.ttl = acl_field.mask.ttl;
        break;
    case la_acl_field_type_e::SPORT:
        npl_key.l4_ports.src_port = acl_field.val.sport;
        npl_mask.l4_ports.src_port = acl_field.mask.sport;
        break;
    case la_acl_field_type_e::MSG_CODE:
        npl_key.l4_ports.src_port = bit_utils::set_bits(npl_key.l4_ports.src_port, 7, 0, acl_field.val.mcode);
        npl_mask.l4_ports.src_port = bit_utils::set_bits(npl_mask.l4_ports.src_port, 7, 0, acl_field.mask.mcode);
        break;
    case la_acl_field_type_e::MSG_TYPE:
        npl_key.l4_ports.src_port = bit_utils::set_bits(npl_key.l4_ports.src_port, 15, 8, acl_field.val.mtype);
        npl_mask.l4_ports.src_port = bit_utils::set_bits(npl_mask.l4_ports.src_port, 15, 8, acl_field.mask.mtype);
        break;
    case la_acl_field_type_e::DPORT:
        npl_key.l4_ports.dst_port = acl_field.val.dport;
        npl_mask.l4_ports.dst_port = acl_field.mask.dport;
        break;
    case la_acl_field_type_e::IP_VERSION:
        npl_key.ip_version = (npl_ip_version_e)acl_field.val.ip_version;
        npl_mask.ip_version = (npl_ip_version_e)acl_field.mask.ip_version;
        break;
    case la_acl_field_type_e::SGACL_BINCODE:
        npl_key.sgacl_id = (m_sgacl_id << 24);
        npl_mask.sgacl_id = 0xff000000;
        if (m_sgacl_id == 0 || m_sgacl_id == 1) {
            npl_mask.sgacl_id = 0xffffffff;
        } else {
            npl_key.sgacl_id |= (acl_field.val.sgacl_bincode & 0x00ffffff);
            npl_mask.sgacl_id |= (acl_field.mask.sgacl_bincode & 0x00ffffff);
        }
        break;
    case la_acl_field_type_e::TCP_FLAGS:
        npl_key.tcp_flags = acl_field.val.tcp_flags.flat;
        npl_mask.tcp_flags = acl_field.mask.tcp_flags.flat;
        break;
    case la_acl_field_type_e::IPV4_FLAGS:
        npl_key.first_fragment = static_cast<npl_bool_e>(~acl_field.val.ipv4_flags.fragment);
        npl_mask.first_fragment = static_cast<npl_bool_e>(acl_field.mask.ipv4_flags.fragment);
        break;
    case la_acl_field_type_e::IPV6_FRAGMENT:
        npl_key.first_fragment = static_cast<npl_bool_e>(~acl_field.val.ipv6_fragment.fragment);
        npl_mask.first_fragment = static_cast<npl_bool_e>(acl_field.mask.ipv6_fragment.fragment);
        break;
    default:
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::copy_key_mask_to_npl(la_slice_id_t slice,
                                            const la_acl_key& key_mask,
                                            npl_table_t::key_type& npl_key,
                                            npl_table_t::key_type& npl_mask) const
{
    for (const auto acl_field : key_mask) {
        la_status status = copy_field_to_npl(acl_field, npl_key, npl_mask);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
la_acl_security_group::get_tcam_size(la_slice_id_t slice) const
{
    return m_device->m_tables.sgacl_table[slice]->max_size();
}

size_t
la_acl_security_group::get_tcam_fullness(la_slice_id_t slice) const
{
    return m_device->m_tables.sgacl_table[slice]->size();
}

la_status
la_acl_security_group::get_tcam_line(la_slice_id_t slice,
                                     size_t tcam_line,
                                     la_acl_key& out_key_val,
                                     la_acl_command_actions& out_cmd) const
{
    npl_table_t::entry_pointer_type entry = nullptr;

    la_status status = m_device->m_tables.sgacl_table[slice]->get_entry(tcam_line, entry);
    return_on_error(status);

    npl_table_t::key_type key = entry->key();
    npl_table_t::key_type mask = entry->mask();
    npl_table_t::value_type value = entry->value();

    status = copy_npl_to_key_mask(key, mask, out_key_val);
    return_on_error(status);
    copy_npl_to_security_group_acl_command(value.payloads.sgacl_payload, out_cmd);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::copy_entry_to_npl(la_slice_id_t slice,
                                         const la_acl_key& key_val,
                                         const la_acl_command_actions& cmd,
                                         npl_table_t::key_type& key,
                                         npl_table_t::key_type& mask,
                                         npl_table_t::value_type& value)
{
    la_status status = copy_key_mask_to_npl(slice, key_val, key, mask);
    return_on_error(status);

    status = copy_security_group_acl_command_to_npl(slice, cmd, value.payloads.sgacl_payload);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::set_tcam_line(la_slice_id_t slice,
                                     size_t tcam_line,
                                     bool is_push,
                                     const la_acl_key& key_val,
                                     const la_acl_command_actions& cmd)
{
    npl_table_t::key_type key{};
    npl_table_t::key_type mask{};
    npl_table_t::value_type value{};
    npl_table_t::entry_pointer_type entry = nullptr;

    la_status status = copy_entry_to_npl(slice, key_val, cmd, key, mask, value);
    return_on_error(status);

    if (is_push) {
        status = m_device->m_tables.sgacl_table[slice]->push(tcam_line, key, mask, value, entry);
    } else {
        status = m_device->m_tables.sgacl_table[slice]->set(tcam_line, key, mask, value, entry);
    }

    return status;
}

la_status
la_acl_security_group::push_tcam_lines(la_slice_id_t slice,
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

    la_status status = m_device->m_tables.sgacl_table[slice]->push_bulk(first_tcam_line, entries_num, entries_info);

    return status;
}

la_status
la_acl_security_group::locate_free_tcam_line_after_last_entry(la_slice_id_t slice, size_t& position) const
{
    return m_device->m_tables.sgacl_table[slice]->get_free_tcam_line_after_last_entry(position);
}

la_status
la_acl_security_group::is_tcam_line_contains_ace(la_slice_id_t slice, size_t tcam_line, bool& contains) const
{
    npl_table_t::entry_pointer_type entry = nullptr;
    la_status status = m_device->m_tables.sgacl_table[slice]->get_entry(tcam_line, entry);

    if (status == LA_STATUS_ENOTFOUND) {
        // Empty
        contains = false;
        return LA_STATUS_SUCCESS;
    }
    return_on_error(status);

    contains = ((entry->key().sgacl_id >> 24) == m_sgacl_id);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::erase_tcam_line(la_slice_id_t slice, size_t tcam_line)
{
    return m_device->m_tables.sgacl_table[slice]->pop(tcam_line);
}

la_status
la_acl_security_group::locate_free_tcam_entry(la_slice_id_t slice, size_t start, size_t& position) const
{
    return m_device->m_tables.sgacl_table[slice]->locate_free_entry(start, position);
}

la_status
la_acl_security_group::allocate_acl_id(la_slice_pair_id_t slice_pair)
{
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::release_acl_id(la_slice_pair_id_t slice_pair)
{
    return LA_STATUS_SUCCESS;
}

la_uint32_t
la_acl_security_group::get_sgacl_id()
{
    return m_sgacl_id;
}

la_status
la_acl_security_group::set_unknown_sgacl_id()
{
    la_status status = m_device->release_security_group_acl_id(m_sgacl_id);
    return_on_error(status);

    // unknown sgacl is attached to cell (0,0) and given label:1
    m_sgacl_id = 1;
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::set_default_sgacl_id()
{
    la_status status = m_device->release_security_group_acl_id(m_sgacl_id);
    return_on_error(status);

    // default sgacl is attached to cell (FFFF,FFFF) and given label:0
    m_sgacl_id = 0;
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_security_group::get_tcam_max_available_space(la_slice_id_t slice, size_t& out_space) const
{
    return m_device->m_tables.sgacl_table[slice]->get_available_entries(out_space);
}
}
