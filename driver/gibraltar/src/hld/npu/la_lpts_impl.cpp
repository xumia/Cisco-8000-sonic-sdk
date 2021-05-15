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

#include <algorithm>

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_destination.h"
#include "api_tracer.h"
#include "counter_utils.h"
#include "la_counter_set_impl.h"
#include "la_lpts_impl.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_types.h"
#include "npu/resolution_utils.h"
#include "qos/la_meter_set_impl.h"
#include "system/la_device_impl.h"
#include "system/la_l2_punt_destination_impl.h"
#include "system/la_punt_inject_port_base.h"
#include "system/la_system_port_base.h"

#include "common/defines.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "hld_utils.h"
#include "la_strings.h"
#include "nplapi/npl_table_types.h"

namespace silicon_one
{

la_lpts_impl::la_lpts_impl(const la_device_impl_wptr& device) : m_device(device), m_type(lpts_type_e::LAST)
{
}

la_lpts_impl::~la_lpts_impl()
{
}

la_status
la_lpts_impl::initialize(la_object_id_t oid, lpts_type_e lpts_type)
{
    m_oid = oid;
    m_type = lpts_type;

    auto status = m_device->m_profile_allocators.lpts_meters->reallocate(m_null_meter_profile, nullptr);
    return_on_error(status);

    // We dedicate one entry in the table for the nullptr meter (no metering), and we don't add it to `m_meter_to_use_count`.
    status = configure_lpts_meter_table(nullptr, m_null_meter_profile->id());
    return_on_error(status);
    m_null_allocations.resize(NUM_SLICE_PAIRS_PER_DEVICE);
    for (la_slice_pair_id_t pair_idx : m_device->get_used_slice_pairs()) {
        m_null_allocations[pair_idx] = make_unique<counter_allocation>();
    }
    for (la_slice_pair_id_t pair_idx : m_device->get_used_slice_pairs()) {
        la_status status = m_device->assign_lpts_counter_allocation(pair_idx, *m_null_allocations[pair_idx]);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::destroy()
{
    for (la_slice_pair_id_t pair_idx : m_device->get_used_slice_pairs()) {
        // Return the allocation back to the device.
        la_status status = m_device->release_lpts_counter_allocation(pair_idx, *m_null_allocations[pair_idx]);
        return_on_error(status);
        m_null_allocations[pair_idx].reset();
    }
    return clear();
}

// la_object API-s
la_object::object_type_e
la_lpts_impl::type() const
{
    return object_type_e::LPTS;
}

std::string
la_lpts_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_lpts_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_lpts_impl::oid() const
{
    return m_oid;
}

const la_device*
la_lpts_impl::get_device() const
{
    return m_device.get();
}

la_status
la_lpts_impl::get_lpts_type(lpts_type_e& out_type) const
{
    start_api_getter_call();

    out_type = m_type;

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::get_count(size_t& out_count) const
{
    start_api_getter_call();

    out_count = m_entries.size();

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::append(const la_lpts_key& key_val, const la_lpts_result& result)
{
    start_api_call("key_val=", key_val, "result=", result);

    return push(m_entries.size(), key_val, result);
}

la_status
la_lpts_impl::validate_lpts_result(const la_lpts_result& result)
{
    if (result.counter_or_meter == nullptr) {
        log_err(HLD, "counter_or_meter field should not be NULL");
        return LA_STATUS_EINVAL;
    }

    auto meter = m_device->get_sptr<const la_meter_set>(result.counter_or_meter);
    if (meter->get_type() != la_meter_set::type_e::PER_IFG_EXACT) {
        log_err(HLD, "counter_or_meter field should hold exact meter");
        return LA_STATUS_EINVAL;
    }

    // NOTE: currently we support 4b flow_type in HW
    if (result.flow_type > MAX_LPTS_FLOW_TYPE) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::push(size_t position, const la_lpts_key& key_val, const la_lpts_result& result)
{
    start_api_call("position=", position, "key_val=", key_val, "result=", result);

    transaction txn;

    if (key_val.type != m_type) {
        return LA_STATUS_EINVAL;
    }

    la_status status = validate_lpts_result(result);
    return_on_error(status);

    // If too long, then append per API doc
    if (position > m_entries.size()) {
        position = m_entries.size();
    }

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        size_t tcam_fullness = 0;
        status = get_tcam_fullness(slice, tcam_fullness);
        return_on_error(status);

        size_t tcam_size = 0;
        status = get_tcam_size(slice, tcam_size);
        return_on_error(status);

        if (tcam_fullness >= tcam_size) {
            log_err(HLD, "Insufficient TCAM space to push LPTS entry. Fullness: %ld/%ld", tcam_fullness, tcam_size);
            return LA_STATUS_ERESOURCE;
        }
    }

    // Program the TCAM entry

    lpts_em_profile lpts_em_ptr{};
    lpts_compressed_meter_profile meter_profile{};
    npl_ipv4_lpts_table_t::key_type v4_key;
    npl_ipv4_lpts_table_t::key_type v4_mask;
    npl_ipv4_lpts_table_t::value_type v4_value;
    npl_ipv6_lpts_table_t::key_type v6_key;
    npl_ipv6_lpts_table_t::key_type v6_mask;
    npl_ipv6_lpts_table_t::value_type v6_value;

    if (m_type == lpts_type_e::LPTS_TYPE_IPV4) {
        la_status status = validate_l4_protocol_mask(static_cast<uint16_t>(key_val.mask.ipv4.protocol));
        return_on_error(status);

        status = copy_v4_key_mask_to_npl(key_val.val.ipv4, v4_key, false /* is_mask */);
        return_on_error(status);

        status = copy_v4_key_mask_to_npl(key_val.mask.ipv4, v4_mask, true /* is_mask */);
        return_on_error(status);

        status = copy_v4_lpts_result_to_npl(result, v4_value.payloads.lpts_first_lookup_result, lpts_em_ptr, meter_profile);
        return_on_error(status);
    } else if (m_type == lpts_type_e::LPTS_TYPE_IPV6) {
        la_status status = validate_l4_protocol_mask(static_cast<uint16_t>(key_val.mask.ipv6.protocol));
        return_on_error(status);

        status = copy_v6_key_mask_to_npl(key_val.val.ipv6, v6_key, false /* is_mask */);
        return_on_error(status);

        status = copy_v6_key_mask_to_npl(key_val.mask.ipv6, v6_mask, true /* is_mask */);
        return_on_error(status);

        status = copy_v6_lpts_result_to_npl(result, v6_value.payloads.lpts_first_lookup_result, lpts_em_ptr, meter_profile);
        return_on_error(status);
    }
    txn.on_fail([=]() { rollback_lpts_2nd_lookup_table_and_meters(lpts_em_ptr, result); });

    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        // locate empty tcam line
        size_t index = 0;

        if (position > 0) {
            // Locate the last lpts entry before the required position
            txn.status = get_tcam_line_index(slice, position - 1, index);
            return_on_error(txn.status);

            index += 1;
        }

        if (m_type == lpts_type_e::LPTS_TYPE_IPV4) {
            txn.status = set_tcam_line_v4(slice, index, true /* push */, v4_key, v4_mask, v4_value, result, lpts_em_ptr);
            return_on_error(txn.status);

        } else if (m_type == lpts_type_e::LPTS_TYPE_IPV6) {
            txn.status = set_tcam_line_v6(slice, index, true /* push */, v6_key, v6_mask, v6_value, result, lpts_em_ptr);
            return_on_error(txn.status);
        }
        txn.on_fail([=]() { pop_lpts_tcam_table_entry(slice, index); });
    }

    auto entry = lpts_entry_data{lpts_entry_desc{key_val, result}, lpts_em_ptr, meter_profile};
    // Update shadow
    m_entries.insert(m_entries.begin() + position, entry);

    status = m_device->configure_rx_obm_punt_src_and_code(
        result.punt_code, NPL_PUNT_SRC_LPTS_FORWARDING, result.tc, 0, nullptr, nullptr, 0);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::set(size_t position, const la_lpts_key& key_val, const la_lpts_result& result)
{
    start_api_call("position=", position, "key_val=", key_val, "result=", result);

    // Check arguments
    if (position >= m_entries.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = pop(position);
    return_on_error(status);

    return push(position, key_val, result);
}

la_status
la_lpts_impl::pop(size_t position)
{
    start_api_call("position=", position);

    la_status status = LA_STATUS_SUCCESS;

    if (position >= m_entries.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        // locate the entry
        size_t index = 0;

        status = get_tcam_line_index(slice, position, index);
        return_on_error(status);

        status = pop_lpts_tcam_table_entry(slice, index);
        return_on_error(status);
    }

    // Erase only if last reference to the itcam entry
    if ((m_entries[position].em_sptr).use_count() == 1) {
        status = erase_lpts_2nd_lookup_table_entry((m_entries[position].em_sptr)->id());
        return_on_error(status);
    }

    lpts_entry_desc desc = m_entries[position].entry_desc;

    status = detach_all_meters(desc.result);
    return_on_error(status);

    m_entries.erase(m_entries.begin() + position);

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::clear()
{
    start_api_call("");

    // Pop entries from last to first for best performance.
    while (!m_entries.empty()) {
        la_status status = pop(m_entries.size() - 1);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::get(size_t position, lpts_entry_desc& out_lpts_entry_desc) const
{
    start_api_getter_call();

    if (position >= m_entries.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    out_lpts_entry_desc = m_entries[position].entry_desc;
    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::get_tcam_size(la_slice_id_t slice, size_t& size) const
{
    la_status status = LA_STATUS_SUCCESS;
    size = 0;

    if (m_type == lpts_type_e::LPTS_TYPE_IPV4) {
        size = m_device->m_tables.ipv4_lpts_table[slice]->max_size();
    } else if (m_type == lpts_type_e::LPTS_TYPE_IPV6) {
        size = m_device->m_tables.ipv6_lpts_table[slice]->max_size();
    } else {
        status = LA_STATUS_EINVAL;
    }

    return status;
}

la_status
la_lpts_impl::get_tcam_fullness(la_slice_id_t slice, size_t& size) const
{
    la_status status = LA_STATUS_SUCCESS;
    size = 0;

    if (m_type == lpts_type_e::LPTS_TYPE_IPV4) {
        size = m_device->m_tables.ipv4_lpts_table[slice]->size();
    } else if (m_type == lpts_type_e::LPTS_TYPE_IPV6) {
        size = m_device->m_tables.ipv6_lpts_table[slice]->size();
    } else {
        status = LA_STATUS_EINVAL;
    }

    return status;
}

la_status
la_lpts_impl::get_tcam_line_index(la_slice_id_t slice, size_t position, size_t& tcam_line_index) const
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
la_lpts_impl::is_tcam_line_contains_entry(la_slice_id_t slice, size_t tcam_line, bool& contains) const
{
    if (m_type == lpts_type_e::LPTS_TYPE_IPV4) {
        npl_ipv4_lpts_table_t::entry_wptr_type e1;
        la_status status = m_device->m_tables.ipv4_lpts_table[slice]->get_entry(tcam_line, e1);

        if (status == LA_STATUS_ENOTFOUND) {
            // Empty
            contains = false;
            return LA_STATUS_SUCCESS;
        }

        if (status != LA_STATUS_SUCCESS) {
            contains = false;
            return status;
        }

        contains = (e1 != nullptr);
        return LA_STATUS_SUCCESS;
    } else if (m_type == lpts_type_e::LPTS_TYPE_IPV6) {
        npl_ipv6_lpts_table_t::entry_wptr_type e1;
        la_status status = m_device->m_tables.ipv6_lpts_table[slice]->get_entry(tcam_line, e1);

        if (status == LA_STATUS_ENOTFOUND) {
            // Empty
            contains = false;
            return LA_STATUS_SUCCESS;
        }

        if (status != LA_STATUS_SUCCESS) {
            contains = false;
            return status;
        }

        contains = (e1 != nullptr);
        return LA_STATUS_SUCCESS;
    } else {
        return LA_STATUS_EINVAL;
    }
}

la_status
la_lpts_impl::set_tcam_line_v4(la_slice_id_t slice,
                               size_t tcam_line,
                               bool is_push,
                               npl_ipv4_lpts_table_t::key_type k1,
                               npl_ipv4_lpts_table_t::key_type m1,
                               npl_ipv4_lpts_table_t::value_type v1,
                               const la_lpts_result& result,
                               lpts_em_profile& lpts_em_ptr)
{
    npl_ipv4_lpts_table_t::entry_wptr_type e1;

    la_status status;
    if (result.counter_or_meter != nullptr) {
        const auto entry_meter = m_device->get_sptr<const la_meter_set>(result.counter_or_meter);
        v1.payloads.lpts_first_lookup_result.lpts_cntr_and_second_lookup_index.lpts_counter_ptr
            = populate_counter_ptr_slice(entry_meter, slice, COUNTER_DIRECTION_INGRESS);
    }

    if (is_push) {
        status = m_device->m_tables.ipv4_lpts_table[slice]->push(tcam_line, k1, m1, v1, e1);
    } else {
        status = m_device->m_tables.ipv4_lpts_table[slice]->insert(tcam_line, k1, m1, v1, e1);
    }

    return status;
}

la_status
la_lpts_impl::set_tcam_line_v6(la_slice_id_t slice,
                               size_t tcam_line,
                               bool is_push,
                               npl_ipv6_lpts_table_t::key_type k1,
                               npl_ipv6_lpts_table_t::key_type m1,
                               npl_ipv6_lpts_table_t::value_type v1,
                               const la_lpts_result& result,
                               lpts_em_profile& lpts_em_ptr)
{
    npl_ipv6_lpts_table_t::entry_wptr_type e1;

    la_status status;
    if (result.counter_or_meter != nullptr) {
        const auto entry_meter = m_device->get_sptr<const la_meter_set>(result.counter_or_meter);
        v1.payloads.lpts_first_lookup_result.lpts_cntr_and_second_lookup_index.lpts_counter_ptr
            = populate_counter_ptr_slice(entry_meter, slice, COUNTER_DIRECTION_INGRESS);
    }

    if (is_push) {
        status = m_device->m_tables.ipv6_lpts_table[slice]->push(tcam_line, k1, m1, v1, e1);
    } else {
        status = m_device->m_tables.ipv6_lpts_table[slice]->insert(tcam_line, k1, m1, v1, e1);
    }

    return status;
}

la_status
la_lpts_impl::copy_v4_key_mask_to_npl(const la_lpts_key_ipv4& key_mask,
                                      npl_ipv4_lpts_table_t::key_type& npl_key_mask,
                                      bool is_mask) const
{
    npl_key_mask.app_id = key_mask.app_id;
    npl_key_mask.sip = key_mask.sip.s_addr;
    npl_key_mask.og_codes.src_code.id = key_mask.src_og_compression_code;
    npl_key_mask.og_codes.dest_code.id = key_mask.dst_og_compression_code & 0x1fff;
    if (is_mask) {
        if (key_mask.protocol == la_l4_protocol_e::RESERVED) {
            npl_key_mask.l4_protocol = 0xff;
        } else {
            npl_key_mask.l4_protocol = 0x00;
        }
    } else {
        npl_key_mask.l4_protocol = static_cast<uint64_t>(key_mask.protocol);
    }
    npl_key_mask.l4_ports.src_port = key_mask.ports.sport;
    npl_key_mask.l4_ports.dst_port = key_mask.ports.dport;
    npl_key_mask.l3_relay_id.id = static_cast<la_uint64_t>(key_mask.relay_id);
    npl_key_mask.fragmented = key_mask.fragment;
    npl_key_mask.v4_frag = key_mask.fragment_info.flat;
    npl_key_mask.ip_length = key_mask.ip_length;
    npl_key_mask.established = static_cast<npl_bool_e>(key_mask.established);
    npl_key_mask.ttl_255 = static_cast<npl_bool_e>(key_mask.ttl_255);
    npl_key_mask.is_mc = static_cast<npl_bool_e>(key_mask.is_mc);

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::copy_v6_key_mask_to_npl(const la_lpts_key_ipv6& key_mask,
                                      npl_ipv6_lpts_table_t::key_type& npl_key_mask,
                                      bool is_mask) const
{
    npl_key_mask.app_id = key_mask.app_id;
    npl_key_mask.sip[0] = key_mask.sip.q_addr[0];
    npl_key_mask.sip[1] = key_mask.sip.q_addr[1];
    npl_key_mask.og_codes.src_code.id = key_mask.src_og_compression_code;
    npl_key_mask.og_codes.dest_code.id = key_mask.dst_og_compression_code & 0x1fff;
    if (is_mask) {
        if (key_mask.protocol == la_l4_protocol_e::RESERVED) {
            npl_key_mask.l4_protocol = 0xff;
        } else {
            npl_key_mask.l4_protocol = 0x00;
        }
    } else {
        npl_key_mask.l4_protocol = static_cast<uint64_t>(key_mask.protocol);
    }
    npl_key_mask.src_port = key_mask.ports.sport;
    npl_key_mask.dst_port = key_mask.ports.dport;
    npl_key_mask.l3_relay_id.id = key_mask.relay_id;
    npl_key_mask.ip_length = key_mask.ip_length;
    npl_key_mask.established = static_cast<npl_bool_e>(key_mask.established);
    npl_key_mask.ttl_255 = static_cast<npl_bool_e>(key_mask.ttl_255);
    npl_key_mask.is_mc = static_cast<npl_bool_e>(key_mask.is_mc);

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::copy_v4_lpts_result_to_npl(const la_lpts_result& result,
                                         npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t& first_lookup_result,
                                         lpts_em_profile& lpts_em_ptr,
                                         lpts_compressed_meter_profile& meter_profile)
{
    first_lookup_result.lpts_first_result_encap_data_msb.ingress_punt_src = NPL_PUNT_SRC_LPTS_FORWARDING;
    first_lookup_result.lpts_first_result_encap_data_msb.encap_punt_code.lpts_reason
        = static_cast<npl_lpts_reason_code_e>(result.punt_code);
    first_lookup_result.lpts_first_result_encap_data_msb.punt_sub_code.sub_code.lpts_flow_type.lpts_flow = result.flow_type & 0xf;

    const la_l2_punt_destination_impl* punt_dest_impl = nullptr;
    uint8_t encap_ptr = 0xFF;
    la_status status;

    if (result.dest != nullptr) {
        punt_dest_impl = static_cast<const la_l2_punt_destination_impl*>(result.dest);
        if (punt_dest_impl == nullptr) {
            return LA_STATUS_EINVAL;
        }
        encap_ptr = punt_dest_impl->get_gid();
    }
    first_lookup_result.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_ETH_ENCAP_TYPE;
    first_lookup_result.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = encap_ptr;

    const auto& meter_sptr = m_device->get_sptr(result.meter);
    status = m_device->m_profile_allocators.lpts_meters->reallocate(meter_profile, meter_sptr);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "Out of lpts meters.");
        return status;
    }
    uint64_t meter_index = meter_profile->id();

    first_lookup_result.punt_encap_data_lsb.extra.lpts_meter_index_msb = meter_index >> la_device_impl::LPTS_METER_INDEX_LSB;
    first_lookup_result.lpts_cntr_and_second_lookup_index.meter_index_lsb = meter_index;

    status = attach_meter(m_device->get_sptr(result.meter), false);
    return_on_error(status);

    if (result.meter != nullptr) {
        status = configure_lpts_meter_table(m_device->get_sptr(result.meter), meter_index);
        return_on_error(status);
    }

    la_meter_set_scptr entry_meter = m_device->get_sptr<const la_meter_set>(result.counter_or_meter);
    status = attach_meter(entry_meter, true);
    return_on_error(status);

    status = allocate_lpts_em_id(result, lpts_em_ptr);
    return_on_error(status);

    first_lookup_result.lpts_cntr_and_second_lookup_index.lpts_second_lookup_index = lpts_em_ptr->id();
    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::copy_v6_lpts_result_to_npl(const la_lpts_result& result,
                                         npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t& first_lookup_result,
                                         lpts_em_profile& lpts_em_ptr,
                                         lpts_compressed_meter_profile& meter_profile)
{
    first_lookup_result.lpts_first_result_encap_data_msb.ingress_punt_src = NPL_PUNT_SRC_LPTS_FORWARDING;
    first_lookup_result.lpts_first_result_encap_data_msb.encap_punt_code.lpts_reason
        = static_cast<npl_lpts_reason_code_e>(result.punt_code);
    first_lookup_result.lpts_first_result_encap_data_msb.punt_sub_code.sub_code.lpts_flow_type.lpts_flow = result.flow_type & 0xf;

    const la_l2_punt_destination_impl* punt_dest_impl = nullptr;
    uint8_t encap_ptr = 0xFF;
    la_status status;

    if (result.dest != nullptr) {
        punt_dest_impl = static_cast<const la_l2_punt_destination_impl*>(result.dest);
        if (punt_dest_impl == nullptr) {
            return LA_STATUS_EINVAL;
        }
        encap_ptr = punt_dest_impl->get_gid();
    }
    first_lookup_result.punt_encap_data_lsb.punt_nw_encap_type = NPL_PUNT_NW_ETH_ENCAP_TYPE;
    first_lookup_result.punt_encap_data_lsb.punt_nw_encap_ptr.ptr = encap_ptr;

    const auto& meter_sptr = m_device->get_sptr(result.meter);
    status = m_device->m_profile_allocators.lpts_meters->reallocate(meter_profile, meter_sptr);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "Out of lpts meters.");
        return status;
    }
    uint64_t meter_index = meter_profile->id();

    first_lookup_result.punt_encap_data_lsb.extra.lpts_meter_index_msb = meter_index >> la_device_impl::LPTS_METER_INDEX_LSB;
    first_lookup_result.lpts_cntr_and_second_lookup_index.meter_index_lsb = meter_index;

    status = attach_meter(m_device->get_sptr(result.meter), false);
    return_on_error(status);

    if (result.meter != nullptr) {
        status = configure_lpts_meter_table(m_device->get_sptr(result.meter), meter_index);
        return_on_error(status);
    }

    la_meter_set_scptr entry_meter = m_device->get_sptr<const la_meter_set>(result.counter_or_meter);
    status = attach_meter(entry_meter, true);
    return_on_error(status);

    status = allocate_lpts_em_id(result, lpts_em_ptr);
    return_on_error(status);

    first_lookup_result.lpts_cntr_and_second_lookup_index.lpts_second_lookup_index = lpts_em_ptr->id();
    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::detach_meter(const la_meter_set_wcptr& meter)
{
    if (meter == nullptr) {
        // Nothing to do
        return LA_STATUS_SUCCESS;
    }

    auto it = m_meter_to_use_count.find(meter);
    if (it == m_meter_to_use_count.end()) {
        log_err(HLD, "la_lpts_impl::%s: meter not found in map", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    dassert_crit(it->second > 0);
    it->second--;
    if (it->second > 0) {
        return LA_STATUS_SUCCESS;
    }

    auto meter_impl = meter.weak_ptr_static_cast<const la_meter_set_impl>().weak_ptr_const_cast<la_meter_set_impl>();
    la_status status = meter_impl->detach_user(m_device->get_sptr(this));
    return_on_error(status);

    m_meter_to_use_count.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::configure_lpts_meter_table(const la_meter_set_wcptr& meter, uint64_t meter_index)
{
    for (la_slice_id_t slice : m_device->get_used_slices()) {
        const auto& t(m_device->m_tables.lpts_meter_table[slice]);
        npl_lpts_meter_table_t::key_type k;
        npl_lpts_meter_table_t::value_type v;
        npl_lpts_meter_table_t::entry_wptr_type e;

        k.meter_index_msb = meter_index >> la_device_impl::LPTS_METER_INDEX_LSB;
        k.meter_index_lsb = meter_index;
        v.payloads.counter_ptr = populate_counter_ptr_slice(meter, slice, COUNTER_DIRECTION_INGRESS);

        la_status status = t->set(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::attach_meter(const la_meter_set_wcptr& meter, bool is_lpts_entry_meter)
{
    if (meter == nullptr) {
        return LA_STATUS_SUCCESS;
    }

    auto it = m_meter_to_use_count.find(meter);
    if (it != m_meter_to_use_count.end()) {
        it->second++;
        return LA_STATUS_SUCCESS;
    }

    la_meter_set_impl_wptr meter_impl
        = meter.weak_ptr_static_cast<const la_meter_set_impl>().weak_ptr_const_cast<la_meter_set_impl>();
    la_status status = meter_impl->attach_user(m_device->get_sptr(this), true /*is_aggregate*/, is_lpts_entry_meter);
    return_on_error(status);
    m_meter_to_use_count[meter] = 1;

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::allocate_lpts_em_id(const la_lpts_result& result, lpts_em_profile& lpts_em_ptr)
{
    la_l2_punt_destination_impl_scptr punt_dest_impl;
    destination_id sp_dest_id = m_device->get_actual_destination_id(m_device->RX_NOT_CNT_DROP_DSP);
    la_mac_addr_t da = {.flat = 0};
    la_mac_addr_t sa = {.flat = 0};
    la_vlan_tag_tci_t vlan_tag = {.raw = 0};
    la_status status;
    uint8_t encap_ptr = 0xFF;

    if (result.dest != nullptr) {
        punt_dest_impl = m_device->get_sptr<const la_l2_punt_destination_impl>(result.dest);
        if (punt_dest_impl == nullptr) {
            return LA_STATUS_EINVAL;
        }

        status = punt_dest_impl->get_mac(da);
        return_on_error(status);

        status = punt_dest_impl->get_vlan_tag(vlan_tag);
        return_on_error(status);

        status = punt_dest_impl->get_punt_port_mac(sa);
        return_on_error(status);

        encap_ptr = punt_dest_impl->get_gid();

        sp_dest_id = get_destination_id(punt_dest_impl, RESOLUTION_STEP_FIRST);
    }

    const la_system_port_gid_t sp_gid = sp_dest_id.val;

    // update table with ID and key type
    npl_lpts_2nd_lookup_table_t::key_type k;
    npl_lpts_2nd_lookup_table_t::entry_pointer_type e = nullptr;
    npl_lpts_2nd_lookup_table_t::value_type v;

    v.payloads.lpts_payload.phb.tc = result.tc;
    v.payloads.lpts_payload.phb.dp = 0;
    v.payloads.lpts_payload.destination = sp_gid;

    lpts_em_entry_data entry_data = v.payloads.lpts_payload;
    status = m_device->m_profile_allocators.lpts_em_entries->reallocate(lpts_em_ptr, entry_data);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "Out of lpts em profiles");
        return status;
    }

    k.lpts_second_lookup_key = lpts_em_ptr->id();
    // If this is not the first reference, all the below code is not relevant
    if (lpts_em_ptr.use_count() > 1) {
        return LA_STATUS_SUCCESS;
    }

    status = m_device->configure_redirect_eth_encap(encap_ptr, da, sa, vlan_tag);
    return_on_error(status);

    for (size_t slice_id : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice_id)) {
            continue;
        }
        status = m_device->m_tables.lpts_2nd_lookup_table[slice_id]->insert(k, v, e);
        return_on_error(status);
    }

    m_device->add_object_dependency(result.dest, m_device->get_sptr<const la_lpts>(this));

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::pop_lpts_tcam_table_entry(la_slice_id_t slice, size_t tcam_line)
{
    la_status status;

    if (m_type == lpts_type_e::LPTS_TYPE_IPV4) {
        status = m_device->m_tables.ipv4_lpts_table[slice]->pop(tcam_line);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to pop ipv4_lpts_table entry, status = %s", la_status2str(status).c_str());
            return status;
        }
    } else if (m_type == lpts_type_e::LPTS_TYPE_IPV6) {
        status = m_device->m_tables.ipv6_lpts_table[slice]->pop(tcam_line);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to pop ipv6_lpts_table entry, status = %s", la_status2str(status).c_str());
            return status;
        }
    } else {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::detach_all_meters(const la_lpts_result& result)
{
    la_status status;
    const auto result_meter = m_device->get_sptr<const la_meter_set>(result.meter);
    status = detach_meter(result_meter);
    return_on_error(status);

    const auto entry_meter = m_device->get_sptr<const la_meter_set>(result.counter_or_meter);
    status = detach_meter(entry_meter);
    return_on_error(status);

    m_device->remove_object_dependency(result.dest, m_device->get_sptr<const la_lpts>(this));

    return LA_STATUS_SUCCESS;
}

la_status
la_lpts_impl::erase_lpts_2nd_lookup_table_entry(size_t lpts_em_id)
{
    la_status status;
    npl_lpts_2nd_lookup_table_t::key_type k;
    k.lpts_second_lookup_key = lpts_em_id;

    for (size_t slice_id : m_device->get_used_slices()) {
        if (!m_device->is_network_slice(slice_id)) {
            continue;
        }
        status = m_device->m_tables.lpts_2nd_lookup_table[slice_id]->erase(k);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to erase lpts em entry, status = %s", la_status2str(status).c_str());
        }
    }
    return status;
}

la_status
la_lpts_impl::rollback_lpts_2nd_lookup_table_and_meters(const lpts_em_profile& lpts_em_ptr, const la_lpts_result& result)
{
    la_status status;

    if (lpts_em_ptr.use_count() == 1) {
        // Best effort delete, don't return status as meters won't be detached
        erase_lpts_2nd_lookup_table_entry(lpts_em_ptr->id());
    }
    status = detach_all_meters(result);
    return status;
}

slice_ifg_vec_t
la_lpts_impl::get_ifgs() const
{
    return get_all_network_ifgs(m_device);
}

la_status
la_lpts_impl::get_max_available_space(size_t& out_available_space) const
{
    size_t min_space = (size_t)-1;
    size_t remaining_space_per_current_slice = 0;
    la_status status;

    slice_ifg_vec_t slice_ifgs = get_ifgs();
    for (auto slice : get_slices_from_ifgs(slice_ifgs)) {
        if (m_type == lpts_type_e::LPTS_TYPE_IPV4) {
            status = m_device->m_tables.ipv4_lpts_table[slice]->get_available_entries(remaining_space_per_current_slice);
        } else if (m_type == lpts_type_e::LPTS_TYPE_IPV6) {
            status = m_device->m_tables.ipv6_lpts_table[slice]->get_available_entries(remaining_space_per_current_slice);
        }

        min_space = std::min(min_space, remaining_space_per_current_slice);
    }

    out_available_space = min_space;

    return status;
}

} // namespace silicon_one
