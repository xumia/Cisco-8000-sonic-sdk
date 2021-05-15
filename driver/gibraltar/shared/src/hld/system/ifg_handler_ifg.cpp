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

#include "system/ifg_handler_ifg.h"
#include "system/la_device_impl.h"
#include "system/la_mac_port_base.h"

namespace silicon_one
{

ifg_handler_ifg::ifg_handler_ifg(const la_device_impl_wptr& device, la_slice_id_t slice_id, la_ifg_id_t ifg_id)
    : ifg_handler_base(device, slice_id, ifg_id)
{
}

ifg_handler_ifg::~ifg_handler_ifg()
{
}

// this function is a temp fix to force a sync of shadow and hardware registers
la_status
ifg_handler_ifg::read_fifo_soft_reset_config()
{
    la_status status;
    bit_vector rx_rstn_reg;
    bit_vector tx_rstn_reg;

    status = m_device->m_ll_device->read_register(*m_ifgb_registers.rx_rstn_reg, rx_rstn_reg);
    return_on_error(status);

    status = m_device->m_ll_device->read_register(*m_ifgb_registers.tx_rstn_reg, tx_rstn_reg);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_ifg::write_tc_extract_cfg(const bit_vector& reg_value, la_uint_t mac_lane_base_id, size_t mac_lanes_reserved_count)
{
    // Write register
    size_t first_line = mac_lane_base_id / 2;
    size_t last_line = (mac_lane_base_id + mac_lanes_reserved_count - 1) / 2;

    for (size_t reg_line = first_line; reg_line <= last_line; reg_line++) {
        la_status status = m_device->m_ll_device->write_register((*m_ifgb_registers.tc_extract_cfg_reg)[reg_line], reg_value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_ifg::merge_tcam_entries(size_t mem_idx, la_uint_t min_edge, la_uint_t max_edge, la_uint_t value)
{
    range_entries_set merged_entries;
    la_status status;
    merge_entry(merged_entries, min_edge, max_edge, value);

    la_uint_t key_width_mask = bit_utils::get_lsb_mask(m_ifg_handler_common.m_tc_tcam_key_width[0]);

    // Trying to merge entries:
    // Go over all entries and look for overlapped entries or ranges we can merge.
    for (size_t i = 0; i < NUM_PORT_TC_TCAM_ENTRIES; i++) {
        bit_vector key, mask, value;
        bool is_valid;
        status = m_port_tc_tcam[mem_idx]->read(i, key, mask, value, is_valid);
        return_on_error(status);

        if (!is_valid) {
            break;
        }

        la_uint_t entry_key = key.get_value();
        la_uint_t entry_mask = mask.get_value();

        // unmask port bit so that range will be according to priority.
        la_uint_t port_bit_idx = get_tc_tcam_entry_port_bit_index(entry_key);
        entry_mask |= (1 << port_bit_idx);

        la_uint_t entry_val = value.get_value();
        la_uint_t min_key = entry_key & entry_mask;
        la_uint_t max_key = entry_key | ((~entry_mask) & key_width_mask);

        merge_entry(merged_entries, min_key, max_key, entry_val);
    }

    std::vector<tcam_entry> tcam_entries;
    for (range_entry merged_entry : merged_entries) {
        la_uint_t lower_edge = merged_entry.low;
        la_uint_t higher_edge = merged_entry.high;
        std::vector<std::pair<uint64_t, uint64_t> > ranged_tcam_entries
            = tcam_expand_range(lower_edge, higher_edge, m_ifg_handler_common.m_tc_tcam_key_width[0]);
        for (auto key_mask : ranged_tcam_entries) {
            la_uint_t key, mask, val;
            key = key_mask.first;
            mask = key_mask.second;

            // mask port bit
            la_uint_t port_bit_idx = get_tc_tcam_entry_port_bit_index(key);
            la_uint_t port_mask = key_width_mask ^ (1 << port_bit_idx);
            mask &= port_mask;

            val = merged_entry.val;
            tcam_entries.push_back(tcam_entry(key, mask, val));
        }
    }

    if (tcam_entries.size() > NUM_PORT_TC_TCAM_ENTRIES) {
        log_err(HLD,
                "ifg_handler::merge_tcam_entries: No resources. Table size=%d, needed entries=%zu",
                NUM_PORT_TC_TCAM_ENTRIES,
                tcam_entries.size());
        return LA_STATUS_ERESOURCE;
    }

    status = clear_tc_tcam_mem(mem_idx);
    return_on_error(status);

    status = insert_port_tc_tcam(mem_idx, tcam_entries);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_ifg::insert_port_tc_tcam(size_t mem_idx, const std::vector<tcam_entry>& entries)
{
    memory_tcam* tcam = m_port_tc_tcam[mem_idx].get();

    for (size_t i = 0; i < m_ifgb_registers.tc_tcam_mem.size(); i++) {
        for (size_t j = 0; j < entries.size(); j++) {
            tcam_entry entry = entries[j];
            bit_vector key(entry.key, m_ifg_handler_common.m_tc_tcam_key_width[i]);
            bit_vector mask(entry.mask, m_ifg_handler_common.m_tc_tcam_key_width[i]);
            bit_vector value(entry.val, m_ifg_handler_common.m_tc_ext_default_tc_width);
            la_status status = tcam->write(j, key, mask, value);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ifg_handler_ifg::clear_port_tc_for_fixed_protocol(size_t mac_lane_base_id)
{
    size_t mem_idx = mac_lane_base_id / 2;
    return clear_tc_tcam_mem(mem_idx);
}

la_status
ifg_handler_ifg::init_tcam_memories()
{
    for (size_t i = 0; i < m_ifg_handler_common.m_num_port_tc_tcam_memories; i++) {
        tcam_section section;

        physical_tcam pt;
        physical_sram ps;

        pt.start_line = 0;
        ps.start_line = 0;
        for (size_t j = 0; j < m_ifgb_registers.tc_tcam.size(); j++) {
            pt.width = m_ifg_handler_common.m_tc_tcam_key_width[j];
            pt.memories.push_back(((*(m_ifgb_registers.tc_tcam[j]))[i]));

            ps.width = m_ifg_handler_common.m_tc_ext_default_tc_width;
            ps.memories.push_back(((*(m_ifgb_registers.tc_tcam_mem[j]))[i]));
        }

        ps.offset = 0;

        section.size = NUM_PORT_TC_TCAM_ENTRIES;
        section.srams.push_back(ps);
        section.tcams.push_back(pt);

        std::vector<tcam_section> sections(1, section);

        m_port_tc_tcam[i] = make_unique<memory_tcam>(m_device->m_ll_device, pt.width, ps.width, sections);
    }

    return LA_STATUS_SUCCESS;
}

void
ifg_handler_ifg::populate_link_error_info(la_uint_t mac_lane_base_id,
                                          size_t mac_lanes_reserved_count,
                                          lld_register_scptr interrupt_reg,
                                          size_t bit_i,
                                          link_error_interrupt_info& val_out) const
{
    bool matching_reg = (interrupt_reg == m_ifgb_registers.tx_tsf_ovf_interrupt_reg);
    bool matching_range = (bit_i >= mac_lane_base_id && bit_i < mac_lane_base_id + mac_lanes_reserved_count);

    val_out.ptp_time_stamp_error = matching_reg && matching_range;
}

la_status
ifg_handler_ifg::set_mac_link_error_interrupt_mask(la_uint_t mac_lane_base_id,
                                                   size_t mac_lanes_reserved_count,
                                                   bool enable_interrupt) const
{
    bit_vector bv(0, m_ifgb_registers.tx_tsf_ovf_interrupt_reg->get_desc()->width_in_bits);

    // Select bits that corresponds to our mac_lane range
    size_t msb = mac_lane_base_id + mac_lanes_reserved_count - 1;
    size_t lsb = mac_lane_base_id;
    bv.set_bits(msb, lsb, bit_vector::ones(mac_lanes_reserved_count));

    const auto& interrupt_tree = m_device->get_notificator()->get_interrupt_tree();
    la_status rc
        = interrupt_tree->set_interrupt_enabled(m_ifgb_registers.tx_tsf_ovf_interrupt_reg, bv, enable_interrupt, false /* clear */);

    return rc;
}

la_status
ifg_handler_ifg::set_port_tc_for_custom_protocol_with_offset(la_uint_t mac_lane_base_id,
                                                             size_t mac_lanes_reserved_count,
                                                             la_ethertype_t protocol,
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
    k.port = mac_lane_base_id & 1; // This table is per 2 ports
    k.tpid = TC_TPID_IDX_NO_MATCH;
    k.protocol = TC_PROTOCOL_IDX_NO_MATCH;
    v.action = NPL_IFGB_TC_LUT_TABLE_ACTION_WRITE;
    v.payloads.ifgb_tc_lut_results.use_lut = 0;
    v.payloads.ifgb_tc_lut_results.data = PORT_TC_CUSTOM_WITH_OFFSET_SELECTOR;

    // Update table
    // Same configutation for the both ports
    npl_ifgb_tc_lut_table_t::key_type second_port_in_pair_key = k;
    second_port_in_pair_key.port = k.port ^ 1;
    la_status status = table->set(second_port_in_pair_key, v, entry_ptr);
    return_on_error(status);

    status = table->set(k, v, entry_ptr);
    return_on_error(status);

    // Key to the TCAM is {2'b3, port, protocol byte EtherType}
    if (protocol >= (1 << 8)) {
        // one byte is extracted.
        return LA_STATUS_EINVAL;
    }
    la_uint_t custom_opcode = 3;
    la_uint_t port = 0; // We only set TC configurations through ports with even PIF ID.
    la_uint32_t tcam_key = (custom_opcode << 9) | (port << 8) | protocol;

    size_t mem_ids = mac_lane_base_id / 2;
    la_uint_t value = combine_ostc_and_itc(ostc, itc);
    return merge_tcam_entries(mem_ids, tcam_key, tcam_key, value);
}

la_status
ifg_handler_ifg::set_port_tc_for_fixed_protocol(la_uint_t mac_lane_base_id,
                                                la_mac_port::tc_protocol_e protocol,
                                                la_uint8_t lower_bound,
                                                la_uint8_t higher_bound,
                                                la_over_subscription_tc_t ostc,
                                                la_initial_tc_t itc)
{
    // Key to the TCAM is {protocol's opcode, port, protocol priority}
    la_uint32_t opcode, num_bits;
    get_port_tc_tcam_key_opcode(mac_lane_base_id, protocol, opcode, num_bits);
    if (higher_bound >= (1 << num_bits)) {
        return LA_STATUS_EINVAL;
    }

    uint64_t min_val = opcode | lower_bound;
    uint64_t max_val = opcode | higher_bound;
    size_t mem_ids = mac_lane_base_id / 2;
    la_uint_t value = combine_ostc_and_itc(ostc, itc);
    return merge_tcam_entries(mem_ids, min_val, max_val, value);
}
}
