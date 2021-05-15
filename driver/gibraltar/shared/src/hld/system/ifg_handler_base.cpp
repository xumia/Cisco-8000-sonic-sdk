// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "system/ifg_handler_base.h"
#include "common/bit_utils.h"
#include "common/bit_vector.h"
#include "common/defines.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "hld_utils.h"
#include "hw_tables/memory_tcam.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"

#include <cmath>
#include <iterator>

namespace silicon_one
{

ifg_handler_base::ifg_handler_base(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : m_device(device), m_slice_id(slice_id), m_ifg_id(ifg_id), m_slice_mode(la_slice_mode_e::INVALID)
{
    m_device_revision = m_device->m_ll_device->get_device_revision();
}

ifg_handler_base::~ifg_handler_base()
{
}

void
ifg_handler_base::pre_initialize()
{
}

la_status
ifg_handler_base::configure_port(la_uint_t mac_lane_base_id,
                                 size_t mac_lanes_reserved_count,
                                 la_mac_port::port_speed_e speed,
                                 size_t mac_lanes_count,
                                 la_mac_port::mlp_mode_e mlp_mode,
                                 la_mac_port::fc_mode_e fc_mode)
{
    la_status stat;
    stat = configure_tx_fifo_lines_value(speed);
    return_on_error(stat);

    stat = configure_mlp_mode(mac_lane_base_id, speed, mac_lanes_count, mlp_mode);
    return_on_error(stat);

    stat = configure_lanes(mac_lane_base_id, mac_lanes_count, speed);
    return_on_error(stat);

    stat = allocate_fifo_memory(mac_lane_base_id, speed);
    return_on_error(stat);

    stat = configure_read_schedule_weight(mac_lane_base_id, mac_lanes_reserved_count, mlp_mode, speed);
    return_on_error(stat);

    stat = set_fc_mode(mac_lane_base_id, mac_lanes_reserved_count, speed, fc_mode);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::clear_port(la_uint_t mac_lane_base_id,
                             size_t mac_lanes_reserved_count,
                             la_mac_port::port_speed_e speed,
                             size_t mac_lanes_count)
{
    la_status stat = configure_tx_fifo_lines_value(speed);
    return_on_error(stat);

    stat = reset_fifo_memory_allocation(mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    stat = reset_read_schedule_weight(mac_lane_base_id, mac_lanes_reserved_count);
    return_on_error(stat);

    stat = set_fc_mode(mac_lane_base_id, mac_lanes_reserved_count, speed, la_mac_port::fc_mode_e::NONE);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::reset_fifo_memory_allocation()
{
    la_status stat = reset_rx_fifo_memory_allocation();
    return_on_error(stat);

    stat = reset_tx_fifo_memory_allocation();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::reset_fifo_memory_allocation(size_t mac_lane_base, size_t mac_lanes_reserved_count)
{
    // Reset to single port mode
    for (size_t mac_lane = 0; mac_lane < mac_lanes_reserved_count; mac_lane++) {
        la_status stat = allocate_rx_fifo_memory(mac_lane_base + mac_lane, 1 /* mac_lanes_reserved_count */);
        return_on_error(stat);

        stat = allocate_tx_fifo_memory(mac_lane_base + mac_lane, 1 /* mac_lanes_reserved_count */);
        return_on_error(stat);
    }
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::allocate_fifo_memory(size_t mac_lane_base, la_mac_port::port_speed_e speed)
{
    size_t port_speed = la_2_port_speed(speed);
    size_t buffer_units = div_round_up(port_speed, FIFO_BUFFER_MAX_SPEED);

    la_status stat = allocate_rx_fifo_memory(mac_lane_base, buffer_units);
    return_on_error(stat);

    stat = configure_rx_cgm(mac_lane_base, buffer_units, speed);
    return_on_error(stat);

    stat = allocate_tx_fifo_memory(mac_lane_base, buffer_units);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::configure_tx_fifo_lines_value(la_mac_port::port_speed_e speed)
{
    m_ifg_handler_common.m_tx_fifo_lines_main_pif = TX_FIFO_LINES_MAIN_PIF;
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::set_fc_mode_fabric_extraction(la_uint_t mac_lane_base_id, bool enable)
{
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::set_fc_mode(la_uint_t mac_lane_base_id,
                              size_t mac_lanes_reserved_count,
                              la_mac_port::port_speed_e speed,
                              la_mac_port::fc_mode_e fc_mode)
{
    if (m_slice_mode == la_slice_mode_e::CARRIER_FABRIC && m_device->m_fabric_ports_initialized) {
        if (fc_mode != m_device->m_fabric_fc_mode) {
            return LA_STATUS_EINVAL;
        }
    }

    /* Don't enable periodic message sending except for CFFC and PFC mode. Need to consider adding an API to enable it. */
    bool enable_periodic_send = false;
    if (fc_mode == la_mac_port::fc_mode_e::CFFC) {
        enable_periodic_send = true;
    }
    if (fc_mode == la_mac_port::fc_mode_e::PFC) {
        // Can be either enabled or disabled based on whether we are using HW PFC or SW PFC
        enable_periodic_send = m_pfc_pif_en_periodic_send_map[mac_lane_base_id];
    }

    la_status stat = set_fc_mode_periodic(mac_lane_base_id, mac_lanes_reserved_count, enable_periodic_send);
    return_on_error(stat);

    stat = set_fc_mode_port(mac_lane_base_id, mac_lanes_reserved_count, speed, fc_mode);
    return_on_error(stat);

    stat = set_fc_mode_fabric_extraction(mac_lane_base_id, m_slice_mode == la_slice_mode_e::CARRIER_FABRIC);
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::init_pfc_port_values()
{
    for (size_t pif = 0; pif < NUM_PIF_PER_IFG; pif++) {
        m_pfc_pif_periodic_timer_map[pif] = s_fc_mode_periodic_config[(size_t)la_mac_port::fc_mode_e::PFC].port_periodic_timer;
        m_pfc_pif_en_periodic_send_map[pif] = false;
    }
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::reset_port_tc_custom_protocol_configuration(la_uint_t mac_lane_base_id, la_uint_t idx)
{
    // Init protocol's setting
    for (size_t i = 0; i <= TC_NUM_TPIDS; i++) {
        la_status stat = set_port_tc_for_custom_protocol(mac_lane_base_id, i, idx, MAX_OSTC, MAX_ITC);
        return_on_error(stat);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::get_port_tc_fixed_protocol_selector(la_mac_port::tc_protocol_e protocol, la_uint8_t& out_mux_selector) const
{
    switch (protocol) {
    case la_mac_port::tc_protocol_e::IPV4:
        out_mux_selector = PORT_TC_DSCP_SELECTOR;
        break;
    case la_mac_port::tc_protocol_e::IPV6:
        out_mux_selector = PORT_TC_IPV6_TC_SELECTOR;
        break;
    case la_mac_port::tc_protocol_e::MPLS:
        out_mux_selector = PORT_TC_MPLS_TC_SELECTOR;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::get_port_tc_for_fixed_protocol(la_uint_t mac_lane_base_id,
                                                 la_mac_port::tc_protocol_e protocol,
                                                 la_uint8_t priority,
                                                 la_over_subscription_tc_t& out_ostc,
                                                 la_initial_tc_t& out_itc) const
{
    la_uint_t mem_idx = mac_lane_base_id / 2;

    // Key to the TCAM is {protocol's opcode, port, protocol priority}
    la_uint32_t opcode, num_bits;
    get_port_tc_tcam_key_opcode(mac_lane_base_id, protocol, opcode, num_bits);

    la_uint_t key = opcode | priority;
    for (size_t i = 0; i < NUM_PORT_TC_TCAM_ENTRIES; i++) {
        bit_vector bv_key, bv_mask, bv_value;
        bool is_valid;
        la_status status = m_port_tc_tcam[mem_idx].get()->read(i, bv_key, bv_mask, bv_value, is_valid);
        return_on_error(status);

        if (!is_valid) {
            continue;
        }

        la_uint_t flat_key = bv_key.get_value();
        la_uint_t flat_mask = bv_mask.get_value();
        if (((key ^ flat_key) & flat_mask) == 0) {
            split_value_to_ostc_and_itc(bv_value.get_value(), out_ostc, out_itc);
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

void
ifg_handler_base::merge_entry(range_entries_set& merged_entries, la_uint_t min_edge, la_uint_t max_edge, la_uint_t value)
{
    range_entry entry_to_merge(min_edge, max_edge, value);
    if (merged_entries.size() == 0) {
        merged_entries.insert(entry_to_merge);
        return;
    }

    auto upper_bound = merged_entries.upper_bound(entry_to_merge);
    if (upper_bound != merged_entries.begin()) {
        auto tmp = std::prev(upper_bound);
        if (tmp->high + 1 >= entry_to_merge.low) {
            if (tmp->val == value) {
                entry_to_merge.low = tmp->low;
                entry_to_merge.high = std::max(entry_to_merge.high, tmp->high);
                merged_entries.erase(tmp);
            } else {
                entry_to_merge.low = tmp->high + 1;
            }
        }
    }

    while (upper_bound != merged_entries.end() && entry_to_merge.high + 1 >= upper_bound->low) {
        if (upper_bound->val == value) {
            entry_to_merge.high = std::max(entry_to_merge.high, upper_bound->high);
            merged_entries.erase(upper_bound++);
        } else {
            merged_entries.insert(range_entry(entry_to_merge.low, upper_bound->low - 1, entry_to_merge.val));
            entry_to_merge.low = upper_bound->high + 1;
            upper_bound++;
        }
    }

    if (entry_to_merge.low <= entry_to_merge.high) {
        merged_entries.insert(entry_to_merge);
    }
}

la_mac_port::tc_protocol_e
ifg_handler_base::get_tc_tcam_entry_protocol(la_uint_t entry_key)
{
    la_mac_port::tc_protocol_e protocols[] = {la_mac_port::tc_protocol_e::IPV4,
                                              la_mac_port::tc_protocol_e::IPV6,
                                              la_mac_port::tc_protocol_e::MPLS,
                                              la_mac_port::tc_protocol_e::ETHERNET};

    la_mac_port::tc_protocol_e ret_val = la_mac_port::tc_protocol_e::ETHERNET;

    for (la_mac_port::tc_protocol_e protocol : protocols) {
        la_uint32_t opcode, num_bits;
        get_port_tc_tcam_key_opcode(0, protocol, opcode, num_bits);
        la_uint32_t protocol_code_offset = num_bits + 1;
        if ((entry_key >> protocol_code_offset) == (opcode >> protocol_code_offset)) {
            ret_val = protocol;
            break;
        }
    }
    return ret_val;
}

size_t
ifg_handler_base::get_tc_tcam_entry_port(la_uint_t entry_key, la_mac_port::tc_protocol_e protocol)
{
    la_uint32_t opcode, num_bits;
    get_port_tc_tcam_key_opcode(0, protocol, opcode, num_bits);

    return (entry_key >> num_bits) & 0x1;
}

la_uint_t
ifg_handler_base::get_tc_tcam_entry_port_bit_index(la_uint_t entry_key)
{
    la_uint_t custom_protocol_with_offset_opcode = 3;
    la_uint_t custom_protocol_with_offset_opcode_num_bits = 2;
    la_uint_t port_bit_idx_in_custom_protocol_with_offset_key = 8;
    if (entry_key >> (m_ifg_handler_common.m_tc_tcam_key_width[0] - custom_protocol_with_offset_opcode_num_bits)
        == custom_protocol_with_offset_opcode) {
        return port_bit_idx_in_custom_protocol_with_offset_key; // custom protocol with offset
    }
    la_mac_port::tc_protocol_e protocol = get_tc_tcam_entry_protocol(entry_key);
    la_uint32_t opcode, num_bits;
    get_port_tc_tcam_key_opcode(0, protocol, opcode, num_bits);
    return num_bits;
}

la_status
ifg_handler_base::allocate_tx_fifo_memory(size_t mac_lane_base, size_t buffer_units)
{
    if (mac_lane_base < m_ifg_handler_common.m_total_main_mac_lanes_reserved_count) {
        return allocate_tx_fifo_memory_main_ports(mac_lane_base, buffer_units);
    } else {
        return allocate_tx_fifo_memory_extra_ports(mac_lane_base, buffer_units);
    }
}

la_status
ifg_handler_base::reset_tx_fifo_memory_allocation()
{
    log_debug(HLD, "ifg_handler::reset_tx_fifo_memory_allocation()");

    la_status status = LA_STATUS_SUCCESS;

    for (size_t mac_lane = 0; mac_lane < m_ifg_handler_common.m_mac_lanes_reserved_count; mac_lane++) {
        status = allocate_tx_fifo_memory(mac_lane, 1);
        return_on_error(status);
    }

    status = allocate_tx_fifo_memory(HOST_PIF_ID, 2);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::set_port_tc_layer(la_uint_t mac_lane_base_id,
                                    la_uint_t tpid_idx,
                                    la_mac_port::tc_protocol_e protocol,
                                    la_layer_e layer)
{
    // Choose table
    const auto& table(m_device->m_tables.ifgb_tc_lut_table[m_slice_id]);

    // Prepare arguments
    npl_ifgb_tc_lut_table_t::key_type k;
    npl_ifgb_tc_lut_table_t::value_type v;
    npl_ifgb_tc_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.ifg = m_ifg_id;
    k.serdes_pair = mac_lane_base_id / 2;
    k.port = mac_lane_base_id & 1; // This table is per 2 ports
    k.tpid = tpid_idx;
    la_uint8_t protocol_idx;
    la_status status = get_port_tc_fixed_protocol_idx(protocol, protocol_idx);
    return_on_error(status);
    k.protocol = protocol_idx;
    v.action = NPL_IFGB_TC_LUT_TABLE_ACTION_WRITE;
    v.payloads.ifgb_tc_lut_results.use_lut = 0;

    if (layer == la_layer_e::L2) {
        v.payloads.ifgb_tc_lut_results.data = PORT_TC_PCPDEI_SELECTOR;
    } else {
        la_uint8_t mux_selector;
        la_status status = get_port_tc_fixed_protocol_selector(protocol, mux_selector);
        return_on_error(status);

        v.payloads.ifgb_tc_lut_results.data = mux_selector;
    }

    // Update table
    // Same configutation for the both ports
    npl_ifgb_tc_lut_table_t::key_type second_port_in_pair_key = k;
    second_port_in_pair_key.port = k.port ^ 1;
    status = table->set(second_port_in_pair_key, v, entry_ptr);
    return_on_error(status);

    return table->set(k, v, entry_ptr);
}

la_status
ifg_handler_base::get_port_tc_layer(la_uint_t mac_lane_base_id,
                                    la_uint_t tpid_idx,
                                    la_mac_port::tc_protocol_e protocol,
                                    la_layer_e& out_layer) const
{
    // Choose table
    const auto& table(m_device->m_tables.ifgb_tc_lut_table[m_slice_id]);

    // Prepare arguments
    npl_ifgb_tc_lut_table_t::key_type k;
    npl_ifgb_tc_lut_table_t::value_type v;
    npl_ifgb_tc_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.ifg = m_ifg_id;
    k.serdes_pair = mac_lane_base_id / 2;
    k.port = mac_lane_base_id & 1; // This table is per 2 ports
    k.tpid = tpid_idx;
    la_uint8_t protocol_idx;
    la_status status = get_port_tc_fixed_protocol_idx(protocol, protocol_idx);
    return_on_error(status);
    k.protocol = protocol_idx;

    // Read current value
    status = table->lookup(k, entry_ptr);
    return_on_error(status);

    v = entry_ptr->value();
    if (v.payloads.ifgb_tc_lut_results.data == PORT_TC_PCPDEI_SELECTOR) {
        out_layer = la_layer_e::L2;
    } else {
        out_layer = la_layer_e::L3;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::set_port_tc_for_custom_protocol(la_uint_t mac_lane_base_id,
                                                  la_tpid_t tpid,
                                                  la_uint_t idx,
                                                  la_over_subscription_tc_t ostc,
                                                  la_initial_tc_t itc)
{
    // Choose table
    const auto& table(m_device->m_tables.ifgb_tc_lut_table[m_slice_id]);

    // Prepare arguments
    npl_ifgb_tc_lut_table_t::key_type k;
    npl_ifgb_tc_lut_table_t::value_type v;
    npl_ifgb_tc_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.ifg = m_ifg_id;
    k.serdes_pair = mac_lane_base_id / 2;
    k.port = mac_lane_base_id & 1;
    k.tpid = tpid;
    k.protocol = idx + NUM_OF_PORT_TC_FIXED_PROTOCOLS;

    v.action = NPL_IFGB_TC_LUT_TABLE_ACTION_WRITE;
    v.payloads.ifgb_tc_lut_results.use_lut = 1;
    v.payloads.ifgb_tc_lut_results.data = combine_ostc_and_itc(ostc, itc);

    // Update table
    // Same configutation for the both ports
    npl_ifgb_tc_lut_table_t::key_type second_port_in_pair_key = k;
    second_port_in_pair_key.port = k.port ^ 1;
    la_status status = table->set(second_port_in_pair_key, v, entry_ptr);
    return_on_error(status);

    return table->set(k, v, entry_ptr);
}

la_status
ifg_handler_base::get_port_tc_fixed_protocol_idx(la_mac_port::tc_protocol_e protocol, la_uint8_t& out_protocol_idx) const
{
    switch (protocol) {
    case la_mac_port::tc_protocol_e::ETHERNET:
        out_protocol_idx = 7;
        break;
    case la_mac_port::tc_protocol_e::IPV4:
        out_protocol_idx = 0;
        break;
    case la_mac_port::tc_protocol_e::IPV6:
        out_protocol_idx = 1;
        break;
    case la_mac_port::tc_protocol_e::MPLS:
        out_protocol_idx = 2;
        break;
    default:
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::get_port_tc_for_custom_protocol(la_uint_t mac_lane_base_id,
                                                  la_tpid_t tpid,
                                                  la_uint_t idx,
                                                  la_over_subscription_tc_t& out_ostc,
                                                  la_initial_tc_t& out_itc) const
{
    // Choose table
    const auto& table(m_device->m_tables.ifgb_tc_lut_table[m_slice_id]);

    // Prepare arguments
    npl_ifgb_tc_lut_table_t::key_type k;
    npl_ifgb_tc_lut_table_t::value_type v;
    npl_ifgb_tc_lut_table_t::entry_pointer_type entry_ptr = nullptr;

    k.ifg = m_ifg_id;
    k.serdes_pair = mac_lane_base_id / 2;
    k.port = mac_lane_base_id & 1;
    k.tpid = tpid;
    k.protocol = idx + NUM_OF_PORT_TC_FIXED_PROTOCOLS;

    // Read current value
    la_status status = table->lookup(k, entry_ptr);
    return_on_error(status);

    split_value_to_ostc_and_itc(v.payloads.ifgb_tc_lut_results.data, out_ostc, out_itc);
    return LA_STATUS_SUCCESS;
}

size_t
ifg_handler_base::get_serdes_count() const
{
    return m_ifg_handler_common.m_serdes_count;
}

size_t
ifg_handler_base::get_num_total_existing_serdes() const
{
    size_t SERDICES_BY_POOL[serdes_pool_type_e::NUM] = {16, 18, 24, 36};
    return SERDICES_BY_POOL[(size_t)m_ifg_handler_common.m_pool_type];
}

serdes_pool_type_e
ifg_handler_base::get_serdes_pool_type() const
{
    return m_ifg_handler_common.m_pool_type;
}

size_t
ifg_handler_base::get_pif_count() const
{
    return m_ifg_handler_common.m_pif_count;
}

la_uint_t
ifg_handler_base::combine_ostc_and_itc(la_over_subscription_tc_t ostc, la_initial_tc_t itc) const
{
    la_uint_t result = 0;
    result = bit_utils::set_bits(result, OSTC_PART_MSB, OSTC_PART_LSB, ostc);
    result = bit_utils::set_bits(result, ITC_PART_MSB, ITC_PART_LSB, itc);
    return result;
}

void
ifg_handler_base::split_value_to_ostc_and_itc(la_uint_t value, la_over_subscription_tc_t& out_ostc, la_initial_tc_t& out_itc) const
{
    out_ostc = bit_utils::get_bits(value, OSTC_PART_MSB, OSTC_PART_LSB);
    out_itc = bit_utils::get_bits(value, ITC_PART_MSB, ITC_PART_LSB);
}

la_status
ifg_handler_base::clear_tc_tcam_mem(size_t mem_idx)
{
    // Choose table
    for (size_t i = 0; i < NUM_PORT_TC_TCAM_ENTRIES; i++) {
        la_status status = m_port_tc_tcam[mem_idx]->invalidate(i);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::reset_oob_packet_counters()
{
    if (m_slice_mode != la_slice_mode_e::CARRIER_FABRIC) {
        return LA_STATUS_SUCCESS;
    }

    la_status stat = configure_oob_inject_packet_counters();
    return_on_error(stat);

    stat = configure_oob_extract_packet_counters();
    return_on_error(stat);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::check_synce_attached(la_device::synce_clock_sel_e prim_sec_clock, bool& synce_attached) const
{
    if ((uint32_t)prim_sec_clock >= SYNCE_REF_CLOCK_PER_GROUP) {
        log_err(HLD, "Recovered clock selected: %d out of range.", (uint32_t)prim_sec_clock);
        return LA_STATUS_EINVAL;
    }
    synce_attached = m_synce_attached[(size_t)prim_sec_clock];

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::reset_oob_inj_credits(size_t mac_lane_base_id, int val)
{
    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_base::set_block_ingress_data(size_t mac_lane_base, size_t mac_lanes_reserved_count, bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}
}
