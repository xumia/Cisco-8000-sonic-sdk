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

#include "lpm_core_hw_writer_pacific_gb.h"

#include "lld/interrupt_tree.h"
#include "lld/ll_device.h"

#include "common/logger.h"

namespace silicon_one
{

lpm_core_hw_writer_pacific_gb::lpm_core_hw_writer_pacific_gb(const ll_device_sptr& ldevice,
                                                             lpm_core_id_t core_id,
                                                             uint8_t num_tcam_banksets)
    : lpm_core_hw_writer(ldevice, core_id, num_tcam_banksets, NUM_CELLS_PER_BANKSET, TCAM_BANK_SIZE)
{
}

la_status
lpm_core_hw_writer_pacific_gb::write_tcam(const tcam_cell_location& location,
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

    // MSB defines whether key is representing single or multiple rows entry
    bool is_ipv6 = key.bit_from_msb(0);

    // Key at TCAM node also contains an additional bit for table type (MSB).
    // It should not be written as prefix.
    size_t key_width = key.get_width() - 1;
    size_t max_key_width;
    if (is_ipv6) {
        if (row < TCAM_MAX_NUM_OF_QUAD_LENGTH_ENTRIES) {
            max_key_width = (TCAM_ROW_WIDTH - 1) * 4;
        } else {
            max_key_width = (TCAM_ROW_WIDTH - 1) * 2;
        }
    } else {
        max_key_width = TCAM_ROW_WIDTH - 1;
    }

    if (key_width > max_key_width) {
        return LA_STATUS_EINVAL;
    }

    // Payload is:
    // 12:0 - payload
    // 19:13 - key width
    bit_vector tcam_payload(payload);
    tcam_payload.resize(TCAM_PAYLOAD_WIDTH);
    size_t payload_width_indication = std::min((size_t)TCAM_PAYLOAD_FIELD_LENGTH_MAX_VALUE, key_width);
    tcam_payload.set_bits_from_msb(0, TCAM_PAYLOAD_FIELD_LENGTH_WIDTH, payload_width_indication);

    log_debug(TABLES,
              "lpm::write_tcam(core: %d, location: %s, key: %s, len: %zd, payload: 0x%s, line: %d, bucket_idx: %d)",
              m_core_id,
              location.to_string().c_str(),
              key.to_string().c_str(),
              key_width,
              tcam_payload.to_string().c_str(),
              payload / 2,
              payload % 2);

    size_t trie_mem_idx = (row < m_cdb_core_pa_gb.trie_mem[0]->get_desc()->entries) ? 0 : 1;
    size_t trie_mem_start_offset = (trie_mem_idx == 0) ? 0 : m_cdb_core_pa_gb.trie_mem[0]->get_desc()->entries;
    la_status status
        = m_ll_device->write_memory(*(m_cdb_core_pa_gb.trie_mem[trie_mem_idx]), row - trie_mem_start_offset, tcam_payload);
    return_on_error(status);

    if (only_update_payload) {
        return LA_STATUS_SUCCESS;
    }

    if (is_ipv6) {
        status = write_tcam_multiple_rows_key(location, key);
    } else {
        status = write_tcam_single_row_key(location, key);
    }
    return status;
}

lpm_entry
lpm_core_hw_writer_pacific_gb::read_tcam(const tcam_cell_location& location) const
{
    lpm_entry ret;

    size_t row = tcam_location_to_row(location);
    size_t tcam_idx = row / TCAM_SIZE;
    size_t tcam_line = row % TCAM_SIZE;

    bit_vector key;
    bit_vector mask;
    bool is_valid;
    la_status status = m_ll_device->read_tcam(*(m_cdb_core_pa_gb.cdb_core.lpm_tcam[tcam_idx]), tcam_line, key, mask, is_valid);
    if (status != LA_STATUS_SUCCESS || !is_valid || !mask.bit(0)) {
        return ret;
    }

    bit_vector payload;

    size_t trie_mem_idx = (row < m_cdb_core_pa_gb.trie_mem[0]->get_desc()->entries) ? 0 : 1;
    size_t trie_mem_start_offset = (trie_mem_idx == 0) ? 0 : m_cdb_core_pa_gb.trie_mem[0]->get_desc()->entries;

    status = m_ll_device->read_memory(*(m_cdb_core_pa_gb.trie_mem[trie_mem_idx]), row - trie_mem_start_offset, payload);
    if (status != LA_STATUS_SUCCESS) {
        return ret;
    }

    // payload is:
    // 12:0 - payload
    // 19:13 - key width
    ret.index = row;
    ret.prefix_width
        = payload.bits(TCAM_PAYLOAD_FIELD_LENGTH_WIDTH + TCAM_PAYLOAD_FIELD_ID_WIDTH - 1, TCAM_PAYLOAD_FIELD_ID_WIDTH).get_value();
    ret.payload = payload.bits(TCAM_PAYLOAD_FIELD_ID_WIDTH - 1, 0).get_value();
    ret.is_ipv6 = key.bit(0);

    if (!ret.is_ipv6) {
        // ipv4
        ret.prefix.resize(ret.prefix_width + 1);
        ret.prefix.set_bits_from_msb(1, ret.prefix_width, key.bits(TCAM_ROW_WIDTH - 1, TCAM_ROW_WIDTH - ret.prefix_width));
    } else {
        if (tcam_idx % 2 != 0) {
            return ret;
        }
        // ipv6
        ret.prefix.resize(ret.prefix_width + 1);
        size_t msb_offset = 1;
        size_t remaining_width = ret.prefix_width;

        size_t start_tcam_idx = (row < TCAM_MAX_NUM_OF_QUAD_LENGTH_ENTRIES) ? 0 : row / TCAM_SIZE;

        for (size_t tcam_idx = start_tcam_idx; tcam_idx < start_tcam_idx + NUM_TCAMS_PER_BANKSET; tcam_idx++) {
            for (int bank_idx = NUM_BANKS_PER_TCAM - 1; bank_idx >= 0; bank_idx--) {
                size_t tcam_line = static_cast<size_t>(bank_idx) * TCAM_BANK_SIZE + (row % TCAM_BANK_SIZE);
                size_t width_to_read = std::min(remaining_width, (size_t)TCAM_ROW_WIDTH - 1);

                status = m_ll_device->read_tcam(*(m_cdb_core_pa_gb.cdb_core.lpm_tcam[tcam_idx]), tcam_line, key, mask, is_valid);
                if (status != LA_STATUS_SUCCESS || !is_valid) {
                    return ret;
                }

                ret.prefix.set_bits_from_msb(
                    msb_offset, width_to_read, key.bits(TCAM_ROW_WIDTH - 1 /*msb*/, TCAM_ROW_WIDTH - width_to_read /*lsb*/));

                msb_offset += width_to_read;
                remaining_width -= width_to_read;
            }
        }
    }

    ret.prefix.set_bit(ret.prefix_width, ret.is_ipv6);
    ret.prefix_width++; // count the MSB

    ret.valid = true;
    return ret;
}

// Default values are written as following
// 1. Each bank has to have ipv6 "catch all" line:
//      - 0-mask, except LSB
//      - key lsb = 1
// 2. Second TCAM has to have ipv4/ipv6 "catch all" line:
//      - 0-mask
//      - key
la_status
lpm_core_hw_writer_pacific_gb::write_tcam_default_row() const
{
    la_status status = LA_STATUS_SUCCESS;
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    bit_vector tcam_values[4];
    if (m_tcam_num_banksets == 1) {
        tcam_values[0] = bit_vector(1 /* value */, TCAM_ROW_WIDTH);
        tcam_values[1] = bit_vector(1 /* value */, TCAM_ROW_WIDTH);
        tcam_values[3] = bit_vector(0 /* value */, TCAM_ROW_WIDTH);
    } else {
        tcam_values[2] = bit_vector(1 /* value */, TCAM_ROW_WIDTH);
        tcam_values[3] = bit_vector(0 /* value */, TCAM_ROW_WIDTH);
    }

    bit_vector payload(0, TCAM_PAYLOAD_WIDTH);

    size_t start_tcam_idx = (m_tcam_num_banksets - 1) * NUM_TCAMS_PER_BANKSET;

    for (size_t tcam_idx = start_tcam_idx; tcam_idx < start_tcam_idx + NUM_TCAMS_PER_BANKSET; tcam_idx++) {
        for (size_t bank_idx = 0; bank_idx < NUM_BANKS_PER_TCAM; bank_idx++) {

            size_t val_idx = (tcam_idx - start_tcam_idx) * NUM_BANKS_PER_TCAM + bank_idx;

            if (tcam_values[val_idx] == bit_vector()) {
                continue;
            }

            size_t row = tcam_idx * TCAM_SIZE + bank_idx * TCAM_BANK_SIZE + (TCAM_BANK_SIZE - 1);

            size_t trie_mem_idx = (row < m_cdb_core_pa_gb.trie_mem[0]->get_desc()->entries) ? 0 : 1;
            size_t trie_mem_start_offset = (trie_mem_idx == 0) ? 0 : m_cdb_core_pa_gb.trie_mem[0]->get_desc()->entries;

            status = m_ll_device->write_memory(*(m_cdb_core_pa_gb.trie_mem[trie_mem_idx]), row - trie_mem_start_offset, payload);
            return_on_error(status);

            status = m_ll_device->write_tcam(*(m_cdb_core_pa_gb.cdb_core.lpm_tcam[tcam_idx]),
                                             row % TCAM_SIZE,
                                             tcam_values[val_idx] /*key*/,
                                             tcam_values[val_idx] /*mask*/);
            return_on_error(status);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_pacific_gb::write_tcam_single_row_key(const tcam_cell_location& location, const lpm_key_t& node_key) const
{
    constexpr size_t BROKEN_BIT_IN_TCAM = 16;
    constexpr bool is_wide_key = false;

    // Key at TCAM node also contains an additional bit for table type (MSB).
    // It should not be written as prefix.
    size_t key_width = node_key.get_width() - 1;

    // Key is msb aligned
    // MSB of the key defines whether ipv4 (0) or ipv6 (1).
    // It should be written at TCAM LSB and exposed in mask
    bit_vector key(0, TCAM_ROW_WIDTH);
    key.set_bits_from_msb(0, key_width, node_key);
    key.set_bit(0, is_wide_key);

    bit_vector mask(0 /*value*/, key_width);
    mask.negate();
    mask = mask << TCAM_ROW_WIDTH - key_width;
    // enable table type bit
    mask.set_bit(0, true);

    // issue #693 - in Pacific the IPv6 indication bit is in bit number 16 in the last tcam block and in the LSB in the
    // first 3 tcam blocks. in GB in all tcam blocks the indication bit is in the LSB,We keep bit 16 set in IPv4 entries in order to
    // differ IPv6 and IPv4 in Pacific. In GB it was fixed.
    if (is_pacific_revision(m_ll_device)) {
        mask.set_bit(BROKEN_BIT_IN_TCAM, 1);
    }

    size_t row = tcam_location_to_row(location);
    size_t tcam_idx = row / TCAM_SIZE;
    size_t tcam_line = row % TCAM_SIZE;
    la_status status = m_ll_device->write_tcam(*(m_cdb_core_pa_gb.cdb_core.lpm_tcam[tcam_idx]), tcam_line, key, mask);

    return status;
}

la_status
lpm_core_hw_writer_pacific_gb::write_tcam_multiple_rows_key(const tcam_cell_location& location, const lpm_key_t& node_key) const
{
    constexpr bool is_wide_key = true;

    size_t row = tcam_location_to_row(location);

    // Key is msb aligned, written into 4 tcam banks.
    //
    // Below is the order (!!!!!!) based on the full key.
    // If key is reduced, LSB is masked.
    // tcam0, line X + BANK_SIZE (512)  - bits[139:101] (39 bits)
    // tcam0, line X                    - bits[100:62]  (39 bits)
    // tcam1, line X + BANK_SIZE (512)  - bits[61:23]   (39 bits)
    // tcam1, line X                    - bits[22:0]    (22 bits)
    //
    // MSB (bit[140]) defines whether ipv4 (0) or ipv6 (1).
    // It should be written at TCAM LSB for each one of the quads and exposed in mask.
    // (!!!!) except the last quad, where 1 should be written at bit 16 (HW bug)

    // We decrement TCAM width and increment max entry key width to account for ipv4/6 indications.
    size_t node_key_width = node_key.get_width();

    bool is_quad = (row < TCAM_MAX_NUM_OF_QUAD_LENGTH_ENTRIES); // for now, we assume first TCAM_MAX_NUM_OF_QUAD_LENGTH_ENTRIES rows
                                                                // are always QUAD if they are wide.
    LA_UNUSED constexpr size_t MAX_DOUBLE_ENTRY_KEY_WIDTH = NUM_BANKS_PER_TCAM * (TCAM_ROW_WIDTH - 1) + 1;
    dassert_crit(is_quad || (node_key_width <= MAX_DOUBLE_ENTRY_KEY_WIDTH));

    size_t start_tcam_idx = is_quad ? 0 : row / TCAM_SIZE;

    size_t num_tcams_to_write = is_quad ? NUM_TCAMS_PER_BANKSET : NUM_TCAMS_PER_BANKSET / 2;
    size_t msb_offset = 1;
    size_t remaining_width = node_key_width - 1;

    for (size_t tcam_idx = start_tcam_idx; tcam_idx < start_tcam_idx + num_tcams_to_write; tcam_idx++) {
        for (int bank_idx = NUM_BANKS_PER_TCAM - 1; bank_idx >= 0; bank_idx--) {

            // enable table type bit
            size_t enable_bit_position = 0;
            if (is_pacific_revision(m_ll_device)) {
                if ((tcam_idx == 1) && (bank_idx == 0)) {
                    dassert_crit(is_quad);
                    enable_bit_position = 16; // HW bug
                }
            }

            bit_vector key(0, TCAM_ROW_WIDTH);
            size_t width_to_write = std::min(remaining_width, (size_t)TCAM_ROW_WIDTH - 1);
            key.set_bits_from_msb(0, width_to_write, node_key.bits_from_msb(msb_offset, width_to_write));
            key.set_bit(enable_bit_position, is_wide_key);

            bit_vector mask(0 /*value*/, width_to_write);
            mask.negate();
            mask = mask << (TCAM_ROW_WIDTH - width_to_write);
            mask.set_bit(enable_bit_position, true);

            size_t tcam_line = static_cast<size_t>(bank_idx) * TCAM_BANK_SIZE + (row % TCAM_BANK_SIZE);
            la_status status = m_ll_device->write_tcam(*(m_cdb_core_pa_gb.cdb_core.lpm_tcam[tcam_idx]), tcam_line, key, mask);
            return_on_error(status);

            msb_offset += width_to_write;
            remaining_width -= width_to_write;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_pacific_gb::invalidate_tcam(const tcam_cell_location& location, const lpm_key_t& key)
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    log_debug(TABLES, "lpm::invalidate_tcam(core: %d, location: %s)", m_core_id, location.to_string().c_str());

    size_t row = tcam_location_to_row(location);
    size_t tcam_idx = row / TCAM_SIZE;
    size_t tcam_line = row % TCAM_SIZE;
    la_status status = m_ll_device->invalidate_tcam(*(m_cdb_core_pa_gb.cdb_core.lpm_tcam[tcam_idx]), tcam_line);
    return status;
}

la_status
lpm_core_hw_writer_pacific_gb::set_l2_sram_ecc_regs_interrupts_enabled(bool enable) const
{
    interrupt_tree* tree = m_ll_device->get_interrupt_tree();

    la_status status = tree->set_interrupt_enabled(m_cdb_core_pa_gb.cdb_core.ecc_1b_int_reg, 0, enable, true /* clear */);
    return_on_error(status);

    tree->set_interrupt_enabled(m_cdb_core_pa_gb.cdb_core.ecc_2b_int_reg, 0, enable, true /* clear */);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
