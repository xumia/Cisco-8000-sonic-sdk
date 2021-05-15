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

#include "lpm_core_hw_writer_akpg.h"
#include "common/defines.h"
#include "lld/device_reg_structs.h"
#include "lld/interrupt_tree.h"
#include "lld/ll_device.h"
#include "lpm_core_tcam_utils_base.h"

namespace silicon_one
{

lpm_core_hw_writer_akpg::lpm_core_hw_writer_akpg(const ll_device_sptr& ldevice,
                                                 lpm_core_id_t core_id,
                                                 uint8_t tcam_num_banksets,
                                                 size_t num_cells_per_bankset,
                                                 size_t tcam_bank_size,
                                                 size_t tcam_size,
                                                 size_t num_tcams_per_bank,
                                                 size_t tcam_payload_field_id_width,
                                                 size_t tcam_payload_field_length_width)
    : lpm_core_hw_writer(ldevice, core_id, tcam_num_banksets, num_cells_per_bankset, tcam_bank_size),
      m_core_tcam_utils(),
      m_ipv6_lsb_patterns{{bit_vector(0x1 /* value */, 2 /* width */),
                           bit_vector(0x3 /* value */, 3 /* width */),
                           bit_vector(0x3 /* value */, 2 /* width */),
                           bit_vector(0x7 /* value */, 3 /* width */)}},
      m_tcam_size(tcam_size),
      m_tcams_per_bank(num_tcams_per_bank),
      m_tcam_payload_l1_address_width(tcam_payload_field_id_width),
      m_tcam_payload_key_width(tcam_payload_field_length_width),
      m_tcam_payload_width(tcam_payload_field_id_width + tcam_payload_field_length_width)
{
    dassert_crit(tcam_num_banksets == 1);
}

lpm_core_hw_writer_akpg::lpm_core_hw_writer_akpg()
    : m_tcam_size(), m_tcams_per_bank(), m_tcam_payload_l1_address_width(), m_tcam_payload_key_width(), m_tcam_payload_width()
{
}

la_status
lpm_core_hw_writer_akpg::update_tcam_over_40_reg(size_t reg_idx, size_t bit_idx, size_t value) const
{
    dassert_crit(reg_idx < LAST_TCAM_BANK_IDX);

    bit_idx = bit_idx + m_over_40_field_offset;

    for (size_t cdb_idx = 0; cdb_idx < m_cdb_core_akpg.size(); cdb_idx++) {
        la_status status = m_ll_device->read_modify_write_register(
            *(*m_cdb_core_akpg[cdb_idx].tcam_over_40_reg)[reg_idx], bit_idx, bit_idx, bit_vector(value, 1 /* width */));
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_akpg::write_tcam(const tcam_cell_location& location,
                                    const lpm_key_t& key,
                                    lpm_payload_t payload,
                                    bool only_update_payload) const
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    // Need to be at least one bit
    if (key.get_width() < 1) {
        return LA_STATUS_EINVAL;
    }

    size_t row = tcam_location_to_row(location);

    size_t key_width = key.get_width() - 1;

    // Payload is:
    // [m_tcam_payload_l1_address_width - 1:0] - L1 address
    // [m_tcam_payload_key_width - 1:m_tcam_payload_l1_address_width] - key width
    bit_vector tcam_payload = generate_tcam_payload_data(payload, key_width);

    log_debug(TABLES,
              "lpm::write_tcam(core: %d, location: %s, key: %s, len: %zd, payload: 0x%s, line: %d, bucket_idx: %d)",
              m_core_id,
              location.to_string().c_str(),
              key.to_string().c_str(),
              key_width,
              tcam_payload.to_string().c_str(),
              payload / 2,
              payload % 2);

    logical_tcam_type_e key_type = m_core_tcam_utils.get_logical_tcam_type_of_key(key);
    size_t num_banks_for_key = lpm_core_tcam_utils_base::get_num_cells_in_block_type(key_type);
    la_status status = LA_STATUS_SUCCESS;

    // payload is written in the last tcam bank.
    size_t payload_line = row + (num_banks_for_key - 1) * m_tcam_bank_size;
    for (size_t cdb_idx = 0; cdb_idx < m_cdb_core_akpg.size(); cdb_idx++) {
        status = m_ll_device->write_memory(*(m_cdb_core_akpg[cdb_idx].trie_mem), payload_line, tcam_payload);
        return_on_error(status);
    }

    if (only_update_payload) {
        return LA_STATUS_SUCCESS;
    }

    bool is_ipv6 = key.bit_from_msb(0);

    if (is_ipv6) {
        status = write_tcam_v6_key(location, key);
    } else {
        // TO DO - Support 80b IPv4 keys.
        status = write_tcam_v4_key(location, key);
    }

    return status;
}

la_status
lpm_core_hw_writer_akpg::write_tcam_v6_key(const tcam_cell_location& location, const lpm_key_t& node_key) const
{
    logical_tcam_type_e key_type = m_core_tcam_utils.get_logical_tcam_type_of_key(node_key);
    size_t num_banks_for_key = lpm_core_tcam_utils_base::get_num_cells_in_block_type(key_type);
    size_t row = tcam_location_to_row(location);
    size_t tcam_line = row % m_tcam_size;
    size_t start_tcam_idx = row / m_tcam_size;
    size_t last_tcam_idx = start_tcam_idx + m_tcams_per_bank * (num_banks_for_key - 1);
    size_t key_width = node_key.get_width();

    size_t full_hit_bit_idx = location.cell;
    size_t remaining_width = key_width - 1;
    size_t lsb_pattern_idx = 0;

    // Write TCAM entries from the tcam0.
    // Key in the TCAM is msb aligned. IPv6 key encoding:
    // Tcam0 - key[141:104] 1'b0      is_ipv6 bit
    // Tcam1 - key[103:67]  2'b01     is_ipv6 bit
    // Tcam2 - key[66:29]   1'b1      is_ipv6 bit
    // Tcam3 - key[28:0]  8'b0  2'b11 is_ipv6 bit
    for (size_t tcam_idx = start_tcam_idx; tcam_idx <= last_tcam_idx; tcam_idx += m_tcams_per_bank) {
        bit_vector key_to_write(0, TCAM_ROW_WIDTH);
        bit_vector mask_to_write(0, TCAM_ROW_WIDTH);

        size_t msb_offset = key_width - remaining_width;
        const bit_vector& lsb_pattern = m_ipv6_lsb_patterns[lsb_pattern_idx];
        size_t lsb_pattern_width = lsb_pattern.get_width();
        size_t max_key_entry_width = TCAM_ROW_WIDTH - lsb_pattern_width;
        size_t width_to_write = std::min(remaining_width, max_key_entry_width);

        key_to_write.set_bits_from_msb(0, width_to_write, node_key.bits_from_msb(msb_offset, width_to_write));
        mask_to_write.set_bits_from_msb(0, width_to_write, bit_vector::ones(width_to_write));

        mask_to_write.set_bits_from_lsb(0, lsb_pattern_width, bit_vector::ones(lsb_pattern_width));
        key_to_write.set_bits_from_lsb(0, lsb_pattern_width, lsb_pattern.bits_from_lsb(0, lsb_pattern_width));

        size_t reg_idx = tcam_idx / m_tcams_per_bank;
        if (reg_idx < LAST_TCAM_BANK_IDX) {
            size_t value = (tcam_idx == last_tcam_idx) ? 0 : 1;
            la_status status = update_tcam_over_40_reg(reg_idx, full_hit_bit_idx, value);
            return_on_error(status);
        }

        for (size_t cdb_idx = 0; cdb_idx < m_cdb_core_akpg.size(); cdb_idx++) {
            la_status status = m_ll_device->write_tcam(
                *(m_cdb_core_akpg[cdb_idx].cdb_core.lpm_tcam[tcam_idx]), tcam_line, key_to_write, mask_to_write);
            return_on_error(status);
        }

        remaining_width -= width_to_write;
        lsb_pattern_idx++;
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_akpg::write_tcam_v4_key(const tcam_cell_location& location, const lpm_key_t& node_key) const
{
    size_t key_width = node_key.get_width() - 1;

    // Lsb bit of TCAM entry is table type bit and should be exposed in the mask.
    bit_vector key(0, TCAM_ROW_WIDTH);
    key.set_bits_from_msb(0, key_width, node_key);

    bit_vector mask(1 /* value */, TCAM_ROW_WIDTH);
    mask.set_bits_from_msb(0, key_width, bit_vector::ones(key_width));

    size_t row = tcam_location_to_row(location);
    size_t reg_idx = row / m_tcam_bank_size;
    size_t full_hit_bit_idx = location.cell;
    if (reg_idx < LAST_TCAM_BANK_IDX) {
        la_status status = update_tcam_over_40_reg(reg_idx, full_hit_bit_idx, 0 /* value */);
        return_on_error(status);
    }

    size_t tcam_idx = row / m_tcam_size;
    size_t tcam_line = row % m_tcam_size;
    for (size_t cdb_idx = 0; cdb_idx < m_cdb_core_akpg.size(); cdb_idx++) {
        la_status status = m_ll_device->write_tcam(*(m_cdb_core_akpg[cdb_idx].cdb_core.lpm_tcam[tcam_idx]), tcam_line, key, mask);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_akpg::invalidate_tcam(const tcam_cell_location& location, const lpm_key_t& key)
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    log_debug(TABLES, "lpm::invalidate_tcam(core: %d, location: %s)", m_core_id, location.to_string().c_str());

    size_t row = tcam_location_to_row(location);
    logical_tcam_type_e key_type = m_core_tcam_utils.get_logical_tcam_type_of_key(key);
    size_t num_banks_for_key = lpm_core_tcam_utils_base::get_num_cells_in_block_type(key_type);
    size_t start_tcam_idx = row / m_tcam_size;
    size_t last_tcam_idx = start_tcam_idx + m_tcams_per_bank * (num_banks_for_key - 1);
    size_t tcam_line = row % m_tcam_size;
    for (size_t tcam_idx = start_tcam_idx; tcam_idx <= last_tcam_idx; tcam_idx += m_tcams_per_bank) {
        for (size_t cdb_idx = 0; cdb_idx < m_cdb_core_akpg.size(); cdb_idx++) {
            la_status status = m_ll_device->invalidate_tcam(*(m_cdb_core_akpg[cdb_idx].cdb_core.lpm_tcam[tcam_idx]), tcam_line);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

lpm_entry
lpm_core_hw_writer_akpg::read_tcam(const tcam_cell_location& location) const
{
    lpm_entry ret;

    size_t row = tcam_location_to_row(location);
    size_t tcam_idx = row / m_tcam_size;
    size_t tcam_line = row % m_tcam_size;

    bit_vector key;
    bit_vector mask;
    bool is_valid;
    la_status status = m_ll_device->read_tcam(*(m_cdb_core_akpg[0].cdb_core.lpm_tcam[tcam_idx]), tcam_line, key, mask, is_valid);
    if (status != LA_STATUS_SUCCESS || !is_valid || !mask.bit(0)) {
        return ret;
    }

    size_t reg_idx = location.bank;
    bit_vector full_hit_bits;
    size_t full_hit_bit_idx = location.cell + m_over_40_field_offset;
    if (reg_idx < LAST_TCAM_BANK_IDX) {
        status = m_ll_device->read_register(*(*m_cdb_core_akpg[0].tcam_over_40_reg)[reg_idx], full_hit_bits);
        if (status != LA_STATUS_SUCCESS) {
            return ret;
        }
    }

    size_t payload_line = 0;
    bit_vector tcam_key = bit_vector();

    // If entry is part of the wide key read other TCAM entries.
    if (full_hit_bits.bit(full_hit_bit_idx)) {
        if ((row / m_tcam_bank_size) % 2 != 0) {
            return ret;
        }

        size_t key_width_in_entry = TCAM_ROW_WIDTH - m_ipv6_lsb_patterns[0].get_width();
        tcam_key = (tcam_key << key_width_in_entry) | key.bits_from_msb(0, key_width_in_entry);

        ret.is_wide_entry = true;
        size_t start_tcam_idx = tcam_idx;
        size_t lsb_pattern_idx = 1;
        for (size_t tcam_idx = start_tcam_idx + m_tcams_per_bank; tcam_idx < m_num_tcams; tcam_idx += m_tcams_per_bank) {
            const bit_vector& lsb_pattern = m_ipv6_lsb_patterns[lsb_pattern_idx];
            key_width_in_entry = TCAM_ROW_WIDTH - lsb_pattern.get_width();

            status = m_ll_device->read_tcam(*(m_cdb_core_akpg[0].cdb_core.lpm_tcam[tcam_idx]), tcam_line, key, mask, is_valid);
            if (status != LA_STATUS_SUCCESS || !is_valid) {
                return ret;
            }

            tcam_key = (tcam_key << key_width_in_entry) | key.bits_from_msb(0, key_width_in_entry);

            size_t bank_idx = tcam_idx / m_tcams_per_bank;
            if (bank_idx < LAST_TCAM_BANK_IDX) {
                status = m_ll_device->read_register(*(*m_cdb_core_akpg[0].tcam_over_40_reg)[bank_idx], full_hit_bits);
                if (status != LA_STATUS_SUCCESS) {
                    return ret;
                }
            }

            if (bank_idx == LAST_TCAM_BANK_IDX || !full_hit_bits.bit(full_hit_bit_idx)) {
                // Last TCAM entry of the key is mapped to the payload line.
                payload_line = tcam_idx * m_tcam_size + tcam_line;
                break;
            }

            lsb_pattern_idx++;
        }
    } else {
        payload_line = row;
        tcam_key = key;
    }

    bit_vector payload;
    status = m_ll_device->read_memory(*(m_cdb_core_akpg[0].trie_mem), payload_line, payload);
    if (status != LA_STATUS_SUCCESS) {
        return ret;
    }

    // payload is:
    // [m_tcam_payload_l1_address_width - 1:0] - payload
    // [m_tcam_payload_key_width - 1:m_tcam_payload_l1_address_width] - key width
    ret.index = row;
    ret.prefix_width
        = payload.bits(m_tcam_payload_key_width + m_tcam_payload_l1_address_width - 1, m_tcam_payload_l1_address_width).get_value();
    ret.payload = payload.bits(m_tcam_payload_l1_address_width - 1, 0).get_value();
    ret.is_ipv6 = key.bit(0);

    ret.prefix.resize(ret.prefix_width + 1);
    ret.prefix.set_bits_from_msb(1, ret.prefix_width, tcam_key.bits_from_msb(0, ret.prefix_width));
    ret.prefix.set_bit(ret.prefix_width, ret.is_ipv6);
    ret.prefix_width++; // count the MSB
    ret.valid = true;

    return ret;
}

la_status
lpm_core_hw_writer_akpg::write_tcam_default_row() const
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    bit_vector default_values[2];
    default_values[0] = bit_vector(0 /* value */, TCAM_ROW_WIDTH);
    default_values[1] = bit_vector(1 /*value */, TCAM_ROW_WIDTH);

    bit_vector masks[2];
    masks[0] = bit_vector(1 /* value */, TCAM_ROW_WIDTH);
    masks[1] = bit_vector(3 /* value */, TCAM_ROW_WIDTH);

    bit_vector payload(0, m_tcam_payload_width);

    size_t last_line = m_num_tcams * m_tcam_size - 1;
    size_t tcam_idx = last_line / m_tcam_size;

    for (size_t tcam_line : {last_line, last_line - 1}) {
        size_t val_idx = last_line - tcam_line;

        for (size_t cdb_idx = 0; cdb_idx < m_cdb_core_akpg.size(); cdb_idx++) {
            la_status status = m_ll_device->write_memory(*(m_cdb_core_akpg[cdb_idx].trie_mem), tcam_line, payload);
            return_on_error(status);

            status = m_ll_device->write_tcam(*(m_cdb_core_akpg[cdb_idx].cdb_core.lpm_tcam[tcam_idx]),
                                             tcam_line % m_tcam_size,
                                             default_values[val_idx],
                                             masks[val_idx]);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

void
lpm_core_hw_writer_akpg::generate_group_from_single_l2_entries(const lpm_node* node0,
                                                               const lpm_node* node1,
                                                               size_t root_width,
                                                               l2_group_data& out_group) const
{
    dassert_crit(node0 != nullptr);

    // Initialize all fields to zero:
    // single_entries.is_wide_prefix.
    // all the entries' fields: prefix/payload/is_leaf.
    std::memset(&out_group, 0, sizeof(l2_group_data));

    const lpm_key_t& node0_key = node0->get_key();
    out_group.single_entries.prefix0 = encode_prefix(node0_key, root_width, ENTRY_ENC_PREFIX_WIDTH).get_value();
    const lpm_bucketing_data& node0_data = node0->data();
    out_group.single_entries.payload0 = node0_data.payload;
    out_group.single_entries.is_leaf0 = is_mark_as_leaf(node0, false /* is_hbm */);
    if (node1) {
        const lpm_key_t& node1_key = node1->get_key();
        out_group.single_entries.prefix1 = encode_prefix(node1_key, root_width, ENTRY_ENC_PREFIX_WIDTH).get_value();
        const lpm_bucketing_data& node1_data = node1->data();
        out_group.single_entries.payload1 = node1_data.payload;
        out_group.single_entries.is_leaf1 = is_mark_as_leaf(node1, false /* is_hbm */);
    }
}

void
lpm_core_hw_writer_akpg::generate_group_from_wide_l2_entry(const lpm_node* node,
                                                           size_t root_width,
                                                           bool is_leaf,
                                                           l2_group_data& out_group) const
{
    // Extracting prefix.
    const lpm_key_t& node_key = node->get_key();
    const lpm_key_t& wide_prefix = encode_prefix(node_key, root_width, L2_WIDE_ENC_PREFIX_WIDTH);

    // Initialize all fields to zero:
    // wide_entry.is_wide_prefix.
    // all the entries' fields: prefix/prefix_valid/payload/is_leaf.
    std::memset(&out_group, 0, sizeof(l2_group_data));

    // Encoding of 60b prefix:
    // 16 msbs of prefix, length bit-> prefix2, prefix2_valid.
    // 16 middle bits of prefix, length bit -> prefix1, prefix1_valid.
    // 28 lsbs of prefix, length bit -> prefix0;
    out_group.wide_entry.prefix2_valid = true;
    size_t lsb = L2_ENTRY_MERGED_PAYLOAD_WIDTH + ENTRY_PREFIX_WIDTH;
    size_t msb = lsb + ENTRY_PREFIX_WIDTH - 1;
    out_group.wide_entry.prefix2 = wide_prefix.bits(msb, lsb).get_value();
    msb -= ENTRY_PREFIX_WIDTH;
    lsb = msb - ENTRY_PREFIX_WIDTH + 1;
    out_group.wide_entry.prefix1 = wide_prefix.bits(msb, lsb).get_value();
    size_t prefix_width = node->get_width() - root_width;
    if (prefix_width >= 2 * ENTRY_PREFIX_WIDTH) {
        out_group.wide_entry.prefix1_valid = true;
        if (prefix_width > 2 * ENTRY_PREFIX_WIDTH) {
            msb -= ENTRY_PREFIX_WIDTH;
            lsb = msb - L2_ENTRY_MERGED_PAYLOAD_WIDTH + 1;
            out_group.wide_entry.prefix0 = wide_prefix.bits(msb, lsb).get_value();
        }
    }

    out_group.wide_entry.payload = node->data().payload;
    out_group.wide_entry.is_leaf = is_leaf;
    out_group.wide_entry.is_wide_prefix = true;
}

bool
lpm_core_hw_writer_akpg::is_mark_as_leaf(const lpm_node* node, bool is_hbm) const
{
    if (!m_key_to_force_is_leaf.empty()) {
        auto it = m_key_to_force_is_leaf.find(node->get_key());
        if (it != m_key_to_force_is_leaf.end()) {
            return it->second;
        }
    }

    return node->is_leaf();
}

} // namespace silicon_one
