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

#include "la_flow_cache_handler_impl.h"
#include "la_device_impl.h"
#include "lld/gibraltar_mem_structs.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"

#include "api_tracer.h"

namespace silicon_one
{

la_flow_cache_handler_impl::la_flow_cache_handler_impl(const la_device_impl_wptr& device)
    : m_device(device), m_flow_cache_enabled(false)
{
}

la_flow_cache_handler_impl::~la_flow_cache_handler_impl()
{
}

la_status
la_flow_cache_handler_impl::initialize(la_object_id_t oid)
{
    // Update object dependencies
    m_oid = oid;
    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_flow_cache_handler_impl::type() const
{
    return object_type_e::FLOW_CACHE_HANDLER;
}

const la_device*
la_flow_cache_handler_impl::get_device() const
{
    return m_device.get();
}

std::string
la_flow_cache_handler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_flow_cache_handler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_flow_cache_handler_impl::oid() const
{
    return m_oid;
}

la_status
la_flow_cache_handler_impl::get_flow_cache_enabled(bool& out_enabled) const
{
    start_api_getter_call();

    out_enabled = m_flow_cache_enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::set_flow_cache_enabled(bool enabled)
{
    start_api_call("enabled=", enabled);

    if (enabled == m_flow_cache_enabled) {
        return LA_STATUS_SUCCESS;
    }

    la_status status;

    if (enabled) {
        status = configure_flc_db();
        return_on_error(status);
    } else {
        status = clear_all_flc_tables();
        return_on_error(status);
    }

    m_flow_cache_enabled = enabled;

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::get_flow_cache_counters(la_flow_cache_handler::flow_cache_counters& out_flow_cache_counters) const
{
    start_api_getter_call();
    gibraltar::flc_db_status_hit_miss_ratio_register status_hit_miss_ratio_reg;
    la_status status;

    out_flow_cache_counters.hit_counter = 0;
    out_flow_cache_counters.miss_counter = 0;
    out_flow_cache_counters.dont_use_cache_counter = 0;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        status = m_device->m_ll_device->read_register(
            m_device->m_gb_tree->slice[slice_id]->npu->rxpp_term->flc_db->status_hit_miss_ratio, status_hit_miss_ratio_reg);
        return_on_error(status);

        out_flow_cache_counters.hit_counter += status_hit_miss_ratio_reg.fields.hit_counter;
        out_flow_cache_counters.miss_counter += status_hit_miss_ratio_reg.fields.miss_counter;
        out_flow_cache_counters.dont_use_cache_counter += status_hit_miss_ratio_reg.fields.dont_use_cache_counter;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::configure_flc_db()
{
    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        la_status status = configure_flc_db_header_types(slice_id);
        return_on_error(status);
        status = configure_header_types_to_mask_id(slice_id);
        return_on_error(status);
        status = configure_flc_db_masks(slice_id);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::configure_flc_db_header_types(la_slice_id_t slice_num)
{
    la_status status;
    npl_flc_header_types_array_table_key_t flc_ht_tbl_k;
    npl_flc_header_types_array_table_key_t flc_ht_tbl_m;
    npl_flc_header_types_array_table_value_t flc_ht_tbl_v;

    constexpr size_t HEADER_TYPE_MASK = 0x1F;
    constexpr size_t VLAN_MASK = 0x1C;
    constexpr size_t NUM_OF_HEADER_TYPES_PER_ARRAY = 5;

    const auto& flc_ht_tbl(m_device->m_tables.flc_header_types_array_table[slice_num]);
    npl_flc_header_types_array_table_entry_t* e = nullptr;
    size_t num_of_entries = flc_ht_tbl->max_size();

    auto vector_sequences = get_cached_protocol_sequences();
    // Assert if there is enough space in TCAM.
    dassert_crit(vector_sequences.size() < num_of_entries / 2);
    size_t index = 0;

    for (const auto protocol_sequence : vector_sequences) {
        size_t sequence_size = protocol_sequence.size();
        size_t protocol_size_in_bits = 8;

        bit_vector k_fi_hdr_4to0(0, NUM_OF_HEADER_TYPES_PER_ARRAY * protocol_size_in_bits);
        bit_vector m_fi_hdr_4to0(0, NUM_OF_HEADER_TYPES_PER_ARRAY * protocol_size_in_bits);

        for (size_t protocol_index = 0; protocol_index < std::min(sequence_size, NUM_OF_HEADER_TYPES_PER_ARRAY); protocol_index++) {
            size_t lsb_position = protocol_index * protocol_size_in_bits;
            size_t msb_position = lsb_position + protocol_size_in_bits - 1;
            k_fi_hdr_4to0.set_bits(msb_position, lsb_position, protocol_sequence[protocol_index]);

            if (protocol_sequence[protocol_index] == NPL_PROTOCOL_TYPE_VLAN_0) {
                m_fi_hdr_4to0.set_bits(msb_position, lsb_position, VLAN_MASK);
            } else {
                m_fi_hdr_4to0.set_bits(msb_position, lsb_position, HEADER_TYPE_MASK);
            }
        }

        flc_ht_tbl_k.flc_header_types_array_key.fi_hdr_4to0 = k_fi_hdr_4to0.get_value();
        flc_ht_tbl_m.flc_header_types_array_key.fi_hdr_4to0 = m_fi_hdr_4to0.get_value();

        if (sequence_size > NUM_OF_HEADER_TYPES_PER_ARRAY) {
            protocol_size_in_bits = 5;
            bit_vector k_fi_hdr_5to9(0, NUM_OF_HEADER_TYPES_PER_ARRAY * protocol_size_in_bits);
            bit_vector m_fi_hdr_5to9(0, NUM_OF_HEADER_TYPES_PER_ARRAY * protocol_size_in_bits);

            for (size_t protocol_index = NUM_OF_HEADER_TYPES_PER_ARRAY; protocol_index < sequence_size; protocol_index++) {
                size_t lsb_position = (protocol_index - NUM_OF_HEADER_TYPES_PER_ARRAY) * protocol_size_in_bits;
                size_t msb_position = lsb_position + protocol_size_in_bits - 1;
                k_fi_hdr_5to9.set_bits(msb_position, lsb_position, protocol_sequence[protocol_index]);

                if (protocol_sequence[protocol_index] == NPL_PROTOCOL_TYPE_VLAN_0) {
                    m_fi_hdr_5to9.set_bits(msb_position, lsb_position, VLAN_MASK);
                } else {
                    m_fi_hdr_5to9.set_bits(msb_position, lsb_position, HEADER_TYPE_MASK);
                }
            }

            flc_ht_tbl_k.flc_header_types_array_key.fi_hdr_5to9 = k_fi_hdr_5to9.get_value();
            flc_ht_tbl_m.flc_header_types_array_key.fi_hdr_5to9 = m_fi_hdr_5to9.get_value();
        }

        flc_ht_tbl_v.payloads.flc_header_types_array_data.use_cache = 1;

        status = flc_ht_tbl->set(index, flc_ht_tbl_k, flc_ht_tbl_m, flc_ht_tbl_v, e);
        return_on_error(status);
        status = flc_ht_tbl->set(index + num_of_entries / 2, flc_ht_tbl_k, flc_ht_tbl_m, flc_ht_tbl_v, e);
        return_on_error(status);

        index++;
    }

    // Write zeros in the rest of the table
    while (index < num_of_entries / 2) {
        flc_ht_tbl_k.flc_header_types_array_key.fi_hdr_4to0 = 0;
        flc_ht_tbl_m.flc_header_types_array_key.fi_hdr_4to0 = 0;
        flc_ht_tbl_k.flc_header_types_array_key.fi_hdr_5to9 = 0;
        flc_ht_tbl_m.flc_header_types_array_key.fi_hdr_5to9 = 0;
        flc_ht_tbl_v.payloads.flc_header_types_array_data.use_cache = 0;
        status = flc_ht_tbl->set(index, flc_ht_tbl_k, flc_ht_tbl_m, flc_ht_tbl_v, e);
        return_on_error(status);
        status = flc_ht_tbl->set(index + num_of_entries / 2, flc_ht_tbl_k, flc_ht_tbl_m, flc_ht_tbl_v, e);
        return_on_error(status);
        index++;
    }

    return LA_STATUS_SUCCESS;
}

std::vector<std::vector<npl_protocol_type_e> >
la_flow_cache_handler_impl::get_cached_protocol_sequences() const
{
    return {{NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV4, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN, NPL_PROTOCOL_TYPE_VLAN_0, NPL_PROTOCOL_TYPE_IPV4, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV4_L4, NPL_PROTOCOL_TYPE_UDP, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV4_L4, NPL_PROTOCOL_TYPE_TCP, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV4_L4, NPL_PROTOCOL_TYPE_ICMP, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
             NPL_PROTOCOL_TYPE_VLAN_0,
             NPL_PROTOCOL_TYPE_IPV4_L4,
             NPL_PROTOCOL_TYPE_UDP,
             NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
             NPL_PROTOCOL_TYPE_VLAN_0,
             NPL_PROTOCOL_TYPE_IPV4_L4,
             NPL_PROTOCOL_TYPE_TCP,
             NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
             NPL_PROTOCOL_TYPE_VLAN_0,
             NPL_PROTOCOL_TYPE_IPV4_L4,
             NPL_PROTOCOL_TYPE_ICMP,
             NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV6, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN, NPL_PROTOCOL_TYPE_VLAN_0, NPL_PROTOCOL_TYPE_IPV6, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV6_L4, NPL_PROTOCOL_TYPE_UDP, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV6_L4, NPL_PROTOCOL_TYPE_TCP, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET, NPL_PROTOCOL_TYPE_IPV6_L4, NPL_PROTOCOL_TYPE_ICMP, NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
             NPL_PROTOCOL_TYPE_VLAN_0,
             NPL_PROTOCOL_TYPE_IPV6_L4,
             NPL_PROTOCOL_TYPE_UDP,
             NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
             NPL_PROTOCOL_TYPE_VLAN_0,
             NPL_PROTOCOL_TYPE_IPV6_L4,
             NPL_PROTOCOL_TYPE_TCP,
             NPL_PROTOCOL_TYPE_UNKNOWN},
            {NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
             NPL_PROTOCOL_TYPE_VLAN_0,
             NPL_PROTOCOL_TYPE_IPV6_L4,
             NPL_PROTOCOL_TYPE_ICMP,
             NPL_PROTOCOL_TYPE_UNKNOWN}};
}

la_status
la_flow_cache_handler_impl::configure_header_types_to_mask_id(la_slice_id_t slice_num)
{
    // We map header type to mask id
    // large masks (320 bits), mask_id 0..7
    // medium masks (160 bits), mask_id 8..15
    // small masks (80 bits), mask_id 16..31

    la_status status;
    npl_flc_map_header_type_mask_id_table_key_t flc_maskid_tbl_k;
    npl_flc_map_header_type_mask_id_table_value_t flc_maskid_tbl_v;
    npl_flc_map_header_type_mask_id_table_entry_t* dummy_entry = nullptr;
    const auto& flc_maskid_tbl(m_device->m_tables.flc_map_header_type_mask_id_table[slice_num]);

    // Prepare the header lists
    constexpr static npl_protocol_type_e LARGE_MASK_HEADERS[] = {NPL_PROTOCOL_TYPE_IPV6, NPL_PROTOCOL_TYPE_IPV6_L4};
    constexpr static npl_protocol_type_e MEDIUM_MASK_HEADERS[] = {NPL_PROTOCOL_TYPE_ETHERNET,
                                                                  NPL_PROTOCOL_TYPE_ETHERNET_VLAN,
                                                                  NPL_PROTOCOL_TYPE_IPV4,
                                                                  NPL_PROTOCOL_TYPE_IPV4_L4,
                                                                  NPL_PROTOCOL_TYPE_TCP};
    constexpr static npl_protocol_type_e SMALL_MASK_HEADERS[]
        = {NPL_PROTOCOL_TYPE_VLAN_0, NPL_PROTOCOL_TYPE_UDP, NPL_PROTOCOL_TYPE_ICMP};

    // Sanity check for header lists
    constexpr static size_t MAX_NUM_LARGE_MASKS = 8;
    constexpr static size_t MAX_NUM_MEDIUM_MASKS = 8;
    constexpr static size_t MAX_NUM_SMALL_MASKS = 16;
    static_assert(array_size(LARGE_MASK_HEADERS) < MAX_NUM_LARGE_MASKS, "Too many large mask headers.");
    static_assert(array_size(MEDIUM_MASK_HEADERS) < MAX_NUM_MEDIUM_MASKS, "Too many medium mask headers.");
    static_assert(array_size(SMALL_MASK_HEADERS) < MAX_NUM_SMALL_MASKS, "Too many small mask headers.");

    // Configure long-mask headers
    size_t large_mask_id = 1; // Because of the HW bug we don't configure mask with id 0.
    for (const auto large_mask_header : LARGE_MASK_HEADERS) {
        flc_maskid_tbl_k.flc_map_header_type_mask_id_key.sel = large_mask_header;
        flc_maskid_tbl_v.payloads.flc_map_header_type_mask_id_data.mask_id = large_mask_id;
        status = flc_maskid_tbl->insert(flc_maskid_tbl_k, flc_maskid_tbl_v, dummy_entry);
        return_on_error(status);
        large_mask_id++;
    }

    // Configure medium-mask headers
    size_t medium_mask_id = MAX_NUM_LARGE_MASKS; // start from first mask after last large
    for (const auto medium_mask_header : MEDIUM_MASK_HEADERS) {
        flc_maskid_tbl_k.flc_map_header_type_mask_id_key.sel = medium_mask_header;
        flc_maskid_tbl_v.payloads.flc_map_header_type_mask_id_data.mask_id = medium_mask_id;
        status = flc_maskid_tbl->insert(flc_maskid_tbl_k, flc_maskid_tbl_v, dummy_entry);
        return_on_error(status);
        medium_mask_id++;
    }

    // Configure small-mask headers
    size_t small_mask_id = MAX_NUM_LARGE_MASKS + MAX_NUM_MEDIUM_MASKS; // start from first mask after last medium
    for (const auto small_mask_header : SMALL_MASK_HEADERS) {
        flc_maskid_tbl_k.flc_map_header_type_mask_id_key.sel = small_mask_header;
        flc_maskid_tbl_v.payloads.flc_map_header_type_mask_id_data.mask_id = small_mask_id;
        status = flc_maskid_tbl->insert(flc_maskid_tbl_k, flc_maskid_tbl_v, dummy_entry);
        return_on_error(status);
        small_mask_id++;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::configure_flc_db_masks(la_slice_id_t slice_num)
{
    la_status status;

    npl_flc_map_header_type_mask_l_table_key_t flc_mask_l_tbl_k;
    npl_flc_map_header_type_mask_l_table_value_t flc_mask_l_tbl_v;
    npl_flc_map_header_type_mask_l_table_entry_t* dummy_l_entry = nullptr;
    const auto& flc_mask_l_tbl(m_device->m_tables.flc_map_header_type_mask_l_table[slice_num]);

    npl_flc_map_header_type_mask_m_table_key_t flc_mask_m_tbl_k;
    npl_flc_map_header_type_mask_m_table_value_t flc_mask_m_tbl_v;
    npl_flc_map_header_type_mask_m_table_entry_t* dummy_m_entry = nullptr;
    const auto& flc_mask_m_tbl(m_device->m_tables.flc_map_header_type_mask_m_table[slice_num]);

    npl_flc_map_header_type_mask_s_table_key_t flc_mask_s_tbl_k;
    npl_flc_map_header_type_mask_s_table_value_t flc_mask_s_tbl_v;
    npl_flc_map_header_type_mask_s_table_entry_t* dummy_s_entry = nullptr;
    const auto& flc_mask_s_tbl(m_device->m_tables.flc_map_header_type_mask_s_table[slice_num]);

    // Configuring cache and queue masks, both are same.

    // For IPv6 we mask all bits in header except payload length (don't care).
    bit_vector cache_and_queue_mask_ipv6(bit_vector::ones(640));
    cache_and_queue_mask_ipv6.set_bits(287, 272, 0);
    cache_and_queue_mask_ipv6.set_bits(607, 592, 0);

    // For Ethernet we mask destination and source MAC address.
    bit_vector cache_and_queue_mask_eth(bit_vector::ones(320));
    cache_and_queue_mask_eth.set_bits(63, 0, 0);
    cache_and_queue_mask_eth.set_bits(223, 160, 0);

    // For IPv4 we mask all bits in header except total length, header checksum and ID (don't care).
    bit_vector cache_and_queue_mask_ipv4(bit_vector::ones(320));
    cache_and_queue_mask_ipv4.set_bits(79, 64, 0);
    cache_and_queue_mask_ipv4.set_bits(143, 96, 0);
    cache_and_queue_mask_ipv4.set_bits(239, 224, 0);
    cache_and_queue_mask_ipv4.set_bits(303, 256, 0);

    // For TCP we we mask source and destination port and TCP options.
    bit_vector cache_and_queue_mask_tcp(bit_vector::ones(320));
    cache_and_queue_mask_tcp.set_bits(47, 0, 0);
    cache_and_queue_mask_tcp.set_bits(127, 57, 0);
    cache_and_queue_mask_tcp.set_bits(207, 160, 0);
    cache_and_queue_mask_tcp.set_bits(287, 217, 0);

    // For VLAN we mask MSB 4B.
    bit_vector cache_and_queue_mask_vlan(bit_vector::ones(160));
    cache_and_queue_mask_vlan.set_bits(47, 0, 0);
    cache_and_queue_mask_vlan.set_bits(127, 80, 0);

    // For UDP we we mask source and destination port.
    bit_vector cache_and_queue_mask_udp(bit_vector::ones(160));
    cache_and_queue_mask_udp.set_bits(47, 0, 0);
    cache_and_queue_mask_udp.set_bits(127, 80, 0);

    // For ICMP we we mask type and code.
    bit_vector cache_and_queue_mask_icmp(bit_vector::ones(160));
    cache_and_queue_mask_icmp.set_bits(63, 0, 0);
    cache_and_queue_mask_icmp.set_bits(143, 80, 0);

    // IPV6
    flc_mask_l_tbl_k.flc_map_header_type_mask_l_key.sel = 1; // this is mask id 1
    flc_mask_l_tbl_v.payloads.flc_map_header_type_mask_l_data.unpack(cache_and_queue_mask_ipv6);
    status = flc_mask_l_tbl->set(flc_mask_l_tbl_k, flc_mask_l_tbl_v, dummy_l_entry);
    return_on_error(status);

    // Same value for IPV6_L4
    flc_mask_l_tbl_k.flc_map_header_type_mask_l_key.sel = 2; // this is mask id 2
    flc_mask_l_tbl_v.payloads.flc_map_header_type_mask_l_data.unpack(cache_and_queue_mask_ipv6);
    status = flc_mask_l_tbl->set(flc_mask_l_tbl_k, flc_mask_l_tbl_v, dummy_l_entry);
    return_on_error(status);

    // ETH
    flc_mask_m_tbl_k.flc_map_header_type_mask_m_key.sel = 0; // this is mask_id 8
    flc_mask_m_tbl_v.payloads.flc_map_header_type_mask_m_data.unpack(cache_and_queue_mask_eth);
    status = flc_mask_m_tbl->set(flc_mask_m_tbl_k, flc_mask_m_tbl_v, dummy_m_entry);
    return_on_error(status);

    // Same value for EHT_VLAN
    flc_mask_m_tbl_k.flc_map_header_type_mask_m_key.sel = 1; // this is mask_id 9
    status = flc_mask_m_tbl->set(flc_mask_m_tbl_k, flc_mask_m_tbl_v, dummy_m_entry);
    return_on_error(status);

    // IPV4
    flc_mask_m_tbl_k.flc_map_header_type_mask_m_key.sel = 2; // this is mask_id 10
    flc_mask_m_tbl_v.payloads.flc_map_header_type_mask_m_data.unpack(cache_and_queue_mask_ipv4);
    status = flc_mask_m_tbl->set(flc_mask_m_tbl_k, flc_mask_m_tbl_v, dummy_m_entry);
    return_on_error(status);

    // Same value for IPV4_L4
    flc_mask_m_tbl_k.flc_map_header_type_mask_m_key.sel = 3; // this is mask_id 11
    status = flc_mask_m_tbl->set(flc_mask_m_tbl_k, flc_mask_m_tbl_v, dummy_m_entry);
    return_on_error(status);

    // TCP
    flc_mask_m_tbl_k.flc_map_header_type_mask_m_key.sel = 4; // this is mask_id 11
    flc_mask_m_tbl_v.payloads.flc_map_header_type_mask_m_data.unpack(cache_and_queue_mask_tcp);
    status = flc_mask_m_tbl->set(flc_mask_m_tbl_k, flc_mask_m_tbl_v, dummy_m_entry);
    return_on_error(status);

    // VLAN
    flc_mask_s_tbl_k.flc_map_header_type_mask_s_key.sel = 0; // this is mask_id 16
    flc_mask_s_tbl_v.payloads.flc_map_header_type_mask_s_data.unpack(cache_and_queue_mask_vlan);
    status = flc_mask_s_tbl->set(flc_mask_s_tbl_k, flc_mask_s_tbl_v, dummy_s_entry);
    return_on_error(status);

    // UDP
    flc_mask_s_tbl_k.flc_map_header_type_mask_s_key.sel = 1; // this is mask_id 17
    flc_mask_s_tbl_v.payloads.flc_map_header_type_mask_s_data.unpack(cache_and_queue_mask_udp);
    status = flc_mask_s_tbl->set(flc_mask_s_tbl_k, flc_mask_s_tbl_v, dummy_s_entry);
    return_on_error(status);

    // ICMP
    flc_mask_s_tbl_k.flc_map_header_type_mask_s_key.sel = 2; // this is mask_id 18
    flc_mask_s_tbl_v.payloads.flc_map_header_type_mask_s_data.unpack(cache_and_queue_mask_icmp);
    status = flc_mask_s_tbl->set(flc_mask_s_tbl_k, flc_mask_s_tbl_v, dummy_s_entry);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::clear_all_flc_tables()
{
    la_status status = clear_header_types_array_table();
    return_on_error(status);

    status = clear_header_type_mask_id_table();
    return_on_error(status);

    status = clear_header_type_large_mask_table();
    return_on_error(status);

    status = clear_header_type_medium_mask_table();
    return_on_error(status);

    status = clear_header_type_small_mask_table();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::clear_header_types_array_table()
{
    la_status status;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        const auto& flc_ht_tbl(m_device->m_tables.flc_header_types_array_table[slice_id]);
        size_t num_of_entries = flc_ht_tbl->max_size();

        for (size_t index = 0; index < num_of_entries; index++) {
            status = flc_ht_tbl->erase(index);
            if (status == LA_STATUS_ENOTFOUND) {
                continue;
            }
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::clear_header_type_mask_id_table()
{
    la_status status;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        const auto& flc_maskid_tbl(m_device->m_tables.flc_map_header_type_mask_id_table[slice_id]);

        size_t entries_total = flc_maskid_tbl->size();
        vector_alloc<npl_flc_map_header_type_mask_id_table_entry_t*> entries(entries_total, nullptr);
        size_t entries_num = flc_maskid_tbl->get_entries(&entries[0], entries_total);

        for (size_t i = 0; i < entries_num; i++) {
            npl_flc_map_header_type_mask_id_table_key_t key(entries[i]->key());
            status = flc_maskid_tbl->erase(key);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::clear_header_type_large_mask_table()
{
    la_status status;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        const auto& flc_mask_l_tbl(m_device->m_tables.flc_map_header_type_mask_l_table[slice_id]);

        size_t entries_total = flc_mask_l_tbl->size();
        vector_alloc<npl_flc_map_header_type_mask_l_table_entry_t*> entries(entries_total, nullptr);
        size_t entries_num = flc_mask_l_tbl->get_entries(&entries[0], entries_total);

        for (size_t i = 0; i < entries_num; i++) {
            npl_flc_map_header_type_mask_l_table_key_t key(entries[i]->key());
            status = flc_mask_l_tbl->erase(key);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::clear_header_type_medium_mask_table()
{
    la_status status;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        const auto& flc_mask_m_tbl(m_device->m_tables.flc_map_header_type_mask_m_table[slice_id]);

        size_t entries_total = flc_mask_m_tbl->size();
        vector_alloc<npl_flc_map_header_type_mask_m_table_entry_t*> entries(entries_total, nullptr);
        size_t entries_num = flc_mask_m_tbl->get_entries(&entries[0], entries_total);

        for (size_t i = 0; i < entries_num; i++) {
            npl_flc_map_header_type_mask_m_table_key_t key(entries[i]->key());
            status = flc_mask_m_tbl->erase(key);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_flow_cache_handler_impl::clear_header_type_small_mask_table()
{
    la_status status;

    la_slice_id_vec_t nw_slices = get_slices(m_device, {la_slice_mode_e::NETWORK, la_slice_mode_e::UDC});
    for (auto slice_id : nw_slices) {
        const auto& flc_mask_s_tbl(m_device->m_tables.flc_map_header_type_mask_s_table[slice_id]);

        size_t entries_total = flc_mask_s_tbl->size();
        vector_alloc<npl_flc_map_header_type_mask_s_table_entry_t*> entries(entries_total, nullptr);
        size_t entries_num = flc_mask_s_tbl->get_entries(&entries[0], entries_total);

        for (size_t i = 0; i < entries_num; i++) {
            npl_flc_map_header_type_mask_s_table_key_t key(entries[i]->key());
            status = flc_mask_s_tbl->erase(key);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
