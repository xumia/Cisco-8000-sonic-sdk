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

#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/math_utils.h"

#include "lld/device_reg_structs.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"

#include "lpm_bucket.h"
#include "lpm_buckets_bucket.h"
#include "lpm_core_hw_writer_pacific.h"
#include "lpm_core_tcam.h"
#include "lpm_nodes_bucket.h"

namespace silicon_one
{

lpm_core_hw_writer_pacific::lpm_core_hw_writer_pacific(const ll_device_sptr& ldevice,
                                                       lpm_core_id_t core_id,
                                                       size_t l2_double_bucket_size,
                                                       uint8_t tcam_num_banksets,
                                                       lpm_payload_t trap_destination,
                                                       size_t hbm_address_offset)
    : lpm_core_hw_writer_pacific_gb(ldevice, core_id, tcam_num_banksets),
      m_l1_trap_hw_bucket(0 /* value */, L1_BUCKET_WIDTH /* width */),
      m_revision(ldevice->get_pacific_tree()->get_revision()),
      m_hbm_address_offset(hbm_address_offset)
{
    if (!m_ll_device) {
        // This is an empty object to mimic HW writes.
        // It should not be initialized and will not be used.
        return;
    }

    m_l1_trap_hw_bucket.set_bits(L1_COUNTER_WIDTH + L1_DEFAULT_WIDTH - 1, L1_COUNTER_WIDTH, trap_destination);
    const pacific_tree* tree = m_ll_device->get_pacific_tree();

    // LPM cores are mapped as following
    // cores 0, 1 -   reduced core 0 / cores 2, 3 -   full core 0
    // cores 4, 5 -   reduced core 1 / cores 6, 7 -   full core 1
    // cores 8, 9 -   reduced core 2 / cores 10, 11 - full core 2
    // cores 12, 13 - reduced core 3 / cores 14, 15 - full core 3

    const lpm_core_id_t is_core_full_mask = 1 << 1; // second bit
    lpm_core_id_t lpm_core_idx = core_id & 0x1;     // first bit
    lpm_core_id_t cdb_core_idx = core_id >> 2;      // idx in cdb core array
    m_is_full_core = core_id & is_core_full_mask;

    const size_t TOTAL_NUM_TCAMS = m_tcam_num_banksets * NUM_TCAMS_PER_BANKSET;
    m_cdb_core_pa_gb.cdb_core.lpm_tcam.resize(TOTAL_NUM_TCAMS);

    if (m_is_full_core) {
        // full core

        // TCAM
        lpm_core_id_t tcam_idx = TCAMS_IN_FULL_CDB_CORE * lpm_core_idx;
        for (size_t i = 0; i < TOTAL_NUM_TCAMS; i++) {
            m_cdb_core_pa_gb.cdb_core.lpm_tcam[i] = (*tree->cdb->core[cdb_core_idx]->lpm_tcam)[tcam_idx + i];
        }
        m_cdb_core_pa_gb.trie_mem[0] = (*tree->cdb->core[cdb_core_idx]->trie_mem)[lpm_core_idx];
        m_cdb_core_pa_gb.trie_mem[1] = (*tree->cdb->core[cdb_core_idx]->extnd_trie_mem)[lpm_core_idx];

        // L1
        m_cdb_core_pa_gb.cdb_core.subtrie_mem = (*tree->cdb->core[cdb_core_idx]->subtrie_mem)[lpm_core_idx];
        m_cdb_core_pa_gb.subtrie_extended_mem = (*tree->cdb->core[cdb_core_idx]->extnd_subtrie_mem)[lpm_core_idx];

        // L2
        m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_valid_reg = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_address_reg
            = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_address_reg)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_non_entry_data_reg
            = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_non_entry_data_reg)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.srams_group
            = (lpm_core_idx == 0) ? tree->cdb->core[cdb_core_idx]->srams_group0 : tree->cdb->core[cdb_core_idx]->srams_group1;
        m_cdb_core_pacific.lpm_last_shared_sram_ptr_reg
            = (*tree->cdb->core[cdb_core_idx]->lpm_last_shared_sram_ptr_reg)[lpm_core_idx];

        // only pacific relevant registers
        m_cdb_core_pacific.lpm_rd_mod_wr_entry_regs = (lpm_core_idx == 0)
                                                          ? tree->cdb->core[cdb_core_idx]->lpm0_rd_mod_wr_entry_data_reg
                                                          : tree->cdb->core[cdb_core_idx]->lpm1_rd_mod_wr_entry_data_reg;

        m_cdb_core_pacific.lpm_rd_mod_wr_entry_0_1_reg
            = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_entry0_entry1_data_reg)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.ecc_1b_int_reg = (*tree->cdb->core[cdb_core_idx]->lpm_shared_sram_1b_err_int_reg)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.ecc_2b_int_reg = (*tree->cdb->core[cdb_core_idx]->lpm_shared_sram_2b_err_int_reg)[lpm_core_idx];
    } else {
        // reduced core

        // TCAM
        lpm_core_id_t tcam_idx = TCAMS_IN_REDUCED_CDB_CORE * lpm_core_idx;
        for (size_t i = 0; i < TOTAL_NUM_TCAMS; i++) {
            m_cdb_core_pa_gb.cdb_core.lpm_tcam[i] = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_tcam)[tcam_idx + i];
        }
        m_cdb_core_pa_gb.trie_mem[0] = (*tree->cdb->core_reduced[cdb_core_idx]->trie_mem)[lpm_core_idx];
        m_cdb_core_pa_gb.trie_mem[1] = (*tree->cdb->core_reduced[cdb_core_idx]->extnd_trie_mem)[lpm_core_idx];

        // L1
        m_cdb_core_pa_gb.cdb_core.subtrie_mem = (*tree->cdb->core_reduced[cdb_core_idx]->subtrie_mem)[lpm_core_idx];
        m_cdb_core_pa_gb.subtrie_extended_mem = (*tree->cdb->core_reduced[cdb_core_idx]->extnd_subtrie_mem)[lpm_core_idx];

        // L2
        m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_valid_reg = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_address_reg
            = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr_address_reg)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_non_entry_data_reg
            = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr_non_entry_data_reg)[lpm_core_idx];
        m_cdb_core_pacific.lpm_rd_mod_wr_entry_0_1_reg
            = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_rd_mod_wr_entry0_entry1_data_reg)[lpm_core_idx];
        m_cdb_core_pacific.lpm_rd_mod_wr_entry_regs = (lpm_core_idx == 0)
                                                          ? tree->cdb->core_reduced[cdb_core_idx]->lpm0_rd_mod_wr_entry_data_reg
                                                          : tree->cdb->core_reduced[cdb_core_idx]->lpm1_rd_mod_wr_entry_data_reg;
        m_cdb_core_pa_gb.cdb_core.srams_group = (lpm_core_idx == 0) ? tree->cdb->core_reduced[cdb_core_idx]->srams_group0
                                                                    : tree->cdb->core_reduced[cdb_core_idx]->srams_group1;
        m_cdb_core_pacific.lpm_last_shared_sram_ptr_reg
            = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_last_shared_sram_ptr_reg)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.ecc_1b_int_reg
            = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_shared_sram_1b_err_int_reg)[lpm_core_idx];
        m_cdb_core_pa_gb.cdb_core.ecc_2b_int_reg
            = (*tree->cdb->core_reduced[cdb_core_idx]->lpm_shared_sram_2b_err_int_reg)[lpm_core_idx];
    }

    size_t num_instances = m_cdb_core_pacific.lpm_rd_mod_wr_entry_regs->get_desc()->instances;
    for (size_t idx = 0; idx < num_instances; idx++) {
        const lld_register_array_container& rd_md_wr_entry_ref = *m_cdb_core_pacific.lpm_rd_mod_wr_entry_regs;
        ldevice->write_register(*rd_md_wr_entry_ref[idx], bit_vector(0));
    }

    m_l2_bucket_width = L2_NON_ENTRY_DATA_WIDTH + l2_double_bucket_size * L2_ENTRY_WIDTH;
    m_l2_num_fixed_entries = (l2_double_bucket_size - L2_NUM_OF_SHARED_ENTRIES) / 2;

    // write L1 trap line, don't collect status because there is no much to do with that
    m_ll_device->write_memory(*m_cdb_core_pa_gb.cdb_core.subtrie_mem, L1_TRAP_LINE, m_l1_trap_hw_bucket);
}

la_status
lpm_core_hw_writer_pacific::write_l1_line(const lpm_bucket* bucket, const lpm_bucket* neighbor_bucket) const
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }
    dassert_crit(bucket);

    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    lpm_bucket_index_t hw_row = hw_index / 2;

    const lpm_bucket* bucket0 = (hw_index % 2 == 0) ? bucket : neighbor_bucket;
    const lpm_bucket* bucket1 = (hw_index % 2 == 1) ? bucket : neighbor_bucket;

    bit_vector hw_bucket = generate_l1_bucket(bucket0, bucket1);

    log_double_bucket(hw_row, bucket0, bucket1, hw_bucket, false /* l2 */);

    // Write L1 bucket
    dassert_crit(hw_bucket.get_width() == m_cdb_core_pa_gb.cdb_core.subtrie_mem->get_desc()->width_bits);
    size_t l1_subtrie_mem_rows = m_cdb_core_pa_gb.cdb_core.subtrie_mem->get_desc()->entries;
    const lld_memory* subtrie_mem;
    if (hw_row < (int)l1_subtrie_mem_rows) {
        subtrie_mem = m_cdb_core_pa_gb.cdb_core.subtrie_mem.get();
    } else {
        subtrie_mem = m_cdb_core_pa_gb.subtrie_extended_mem.get();
        hw_row -= l1_subtrie_mem_rows;
    }

    la_status status = m_ll_device->write_memory(*subtrie_mem, hw_row /* line */, hw_bucket);
    return status;
}

std::vector<lpm_entry>
lpm_core_hw_writer_pacific::read_l1_bucket(size_t hw_index, size_t& out_default_payload) const
{
    std::vector<lpm_entry> ret;
    size_t hw_line = hw_index / 2;
    size_t bucket_idx = hw_index % 2;

    bit_vector l1_line_bv;
    size_t l1_subtrie_mem_rows = m_cdb_core_pa_gb.cdb_core.subtrie_mem->get_desc()->entries;

    if (hw_line < l1_subtrie_mem_rows) {
        la_status status = m_ll_device->read_memory(*m_cdb_core_pa_gb.cdb_core.subtrie_mem, hw_line, l1_line_bv);
        if (status != LA_STATUS_SUCCESS) {
            return ret;
        }
    } else {
        la_status status
            = m_ll_device->read_memory(*m_cdb_core_pa_gb.subtrie_extended_mem, hw_line - l1_subtrie_mem_rows, l1_line_bv);
        if (status != LA_STATUS_SUCCESS) {
            return ret;
        }
    }

    size_t shared_entries_to_1 = l1_line_bv.bits(L1_COUNTER_WIDTH - 1, 0).get_value();
    dassert_crit(shared_entries_to_1 <= L1_NUM_OF_SHARED_ENTRIES);
    // In the shared segment, first entries go to bucket 1; last entries go to bucket 0
    // Encoding represent the splitting.
    size_t shared_start = (bucket_idx == 0) ? shared_entries_to_1 * L1_ENTRY_WIDTH : 0;
    size_t shared_end = (bucket_idx == 0) ? L1_NUM_OF_SHARED_ENTRIES * L1_ENTRY_WIDTH : shared_entries_to_1 * L1_ENTRY_WIDTH;

    // Shared entries
    std::vector<size_t> positions;
    for (size_t pos = shared_start + L1_NON_ENTRY_DATA_WIDTH; pos < shared_end + L1_NON_ENTRY_DATA_WIDTH; pos += L1_ENTRY_WIDTH) {
        positions.push_back(pos);
    }

    // Fixed entries
    size_t fixed_pos = (bucket_idx == 0) ? L1_BUCKET_SHARED_ENTRIES_END : L1_BUCKET_SHARED_ENTRIES_END + 2 * L1_ENTRY_WIDTH;
    for (size_t i = 0; i < L1_NUM_OF_FIXED_ENTRIES; ++i, fixed_pos += L1_ENTRY_WIDTH) {
        positions.push_back(fixed_pos);
    }

    // Extract all entries
    for (size_t pos : positions) {
        bit_vector entry_bv = l1_line_bv.bits(pos + L1_ENTRY_WIDTH - 1, pos);

        lpm_entry entry;
        entry.prefix = entry_bv.bits_from_msb(0, ENTRY_ENC_PREFIX_WIDTH);
        if (entry.prefix.get_value()) {
            // only if prefix is not 0
            entry.prefix = decode_prefix(entry.prefix);
            entry.prefix_width = entry.prefix.get_width();
            entry.payload = entry_bv.bits(L1_ENTRY_PREFIX_START - 1, L1_ENTRY_ID_START).get_value();
            entry.valid = true;
            entry.index = (pos - L1_NON_ENTRY_DATA_WIDTH) / L1_ENTRY_WIDTH;
        }

        ret.push_back(entry);
    }

    size_t default_pos = (bucket_idx == 0) ? L1_COUNTER_WIDTH : L1_COUNTER_WIDTH + L1_DEFAULT_WIDTH;
    out_default_payload = l1_line_bv.bits(default_pos + L1_DEFAULT_WIDTH - 1, default_pos).get_value();

    return ret;
}

void
lpm_core_hw_writer_pacific::log_double_bucket(lpm_bucket_index_t hw_row,
                                              const lpm_bucket* bucket0,
                                              const lpm_bucket* bucket1,
                                              const bit_vector& hw_bucket,
                                              bool l2) const
{
    if (!logger::instance().is_logging(m_ll_device->get_device_id(), la_logger_component_e::TABLES, la_logger_level_e::DEBUG)) {
        return;
    }

    // Encoding represents allocation of non-shared entries between the buckets
    const size_t encoding_width = l2 ? L2_COUNTER_WIDTH : L1_COUNTER_WIDTH;
    const size_t num_of_shared_entries = l2 ? L2_NUM_OF_SHARED_ENTRIES : L1_NUM_OF_SHARED_ENTRIES;
    const size_t non_entry_data_width = l2 ? L2_NON_ENTRY_DATA_WIDTH : L1_NON_ENTRY_DATA_WIDTH;
    const size_t default_width = l2 ? L2_DEFAULT_WIDTH : L1_DEFAULT_WIDTH;
    const size_t entry_width = l2 ? L2_ENTRY_WIDTH : L1_ENTRY_WIDTH;
    const size_t prefix_start = l2 ? L2_ENTRY_PREFIX_START : L1_ENTRY_PREFIX_START;
    const size_t prefix_width = ENTRY_ENC_PREFIX_WIDTH;
    const size_t payload_start = l2 ? L2_ENTRY_PAYLOAD_START : L1_ENTRY_ID_START;
    const size_t payload_width = l2 ? L2_ENTRY_PAYLOAD_WIDTH : L1_ENTRY_ID_WIDTH;

    size_t shared_entries_to_1 = hw_bucket.bits(encoding_width - 1, 0).get_value();
    size_t shared_entries_to_0 = num_of_shared_entries - shared_entries_to_1;
    log_debug(
        TABLES,
        "lpm::write_l%d_line(core: %d, hw_row: %d, shared_entries [0]: %zu, [1]: %zu, default [0]: 0x%s, [1]: 0x%s, sw_index "
        "[0]: %d, [1]: %d)",
        l2 ? 2 : 1,
        m_core_id,
        hw_row,
        shared_entries_to_0,
        shared_entries_to_1,
        hw_bucket.bits(non_entry_data_width - default_width - 1, non_entry_data_width - 2 * default_width).to_string().c_str(),
        hw_bucket.bits(non_entry_data_width - 1, non_entry_data_width - default_width).to_string().c_str(),
        bucket0 ? (int)bucket0->get_sw_index() : -1,
        bucket1 ? (int)bucket1->get_sw_index() : -1);

    for (size_t entry = non_entry_data_width; entry < hw_bucket.get_width(); entry += entry_width) {
        bit_vector entry_bv = hw_bucket.bits(entry + entry_width - 1, entry);
        size_t prefix = entry_bv.bits(prefix_start + prefix_width - 1, prefix_start).get_value();
        if (prefix) {
            log_spam(TABLES,
                     "lpm::write_l%d_line(idx: %zd, prefix: 0x%s, payload: 0x%s)",
                     l2 ? 2 : 1,
                     (entry - non_entry_data_width) / entry_width,
                     entry_bv.bits(prefix_start + prefix_width - 1, prefix_start).to_string().c_str(),
                     entry_bv.bits(payload_start + payload_width - 1, payload_start).to_string().c_str());
        }
    }
}

la_status
lpm_core_hw_writer_pacific::write_l2_sram_buckets(const lpm_bucket* bucket, const lpm_bucket* neighbor_bucket) const
{
    dassert_crit(bucket);

    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    lpm_bucket_index_t hw_row = hw_index / 2;

    const l2_sram_line hw_bucket_st = generate_l2_sram_line(bucket, neighbor_bucket);

    la_status status = write_l2_sram_line(hw_row, hw_bucket_st);
    return status;
}

la_status
lpm_core_hw_writer_pacific::write_l2_hbm_bucket(const lpm_bucket* bucket) const
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    dassert_crit(bucket);

    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    bit_vector hw_bucket = generate_l2_hbm_bucket(bucket);
    la_status status = write_l2_hbm_line(hw_index, hw_bucket);
    return status;
}

la_status
lpm_core_hw_writer_pacific::write_l2_sram_line(lpm_bucket_index_t row, const l2_sram_line& hw_bucket_st) const
{
    // Memory address of bucket to write + full row flag
    bit_vector address_reg((row << 1) /* address */ | 1 /* write entire line */);

    la_status status = m_ll_device->wait_for_value(
        *m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_valid_reg, true /* equal */, 0 /* val */, 1 /* mask */);

    status = m_ll_device->write_register(*m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_address_reg, address_reg /* line index */);
    return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());

    // Non entry data of bucket to write

    uint64_t* non_entry_data_ptr = (uint64_t*)&hw_bucket_st.non_entry_data;
    bit_vector non_entry_data(non_entry_data_ptr, L2_NON_ENTRY_DATA_WIDTH);

    status = m_ll_device->write_register(*m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_non_entry_data_reg, non_entry_data);
    return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());

    // First entries of bucket0 and bucket1
    bit_vector entry0_entry1(hw_bucket_st.entry_data.bits(2 * L2_ENTRY_WIDTH - 1, 0));
    status = m_ll_device->write_register(*m_cdb_core_pacific.lpm_rd_mod_wr_entry_0_1_reg, entry0_entry1);
    return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());

    // Other entries of bucket to write.
    size_t reg_width_in_bits = m_cdb_core_pacific.lpm_rd_mod_wr_entry_regs->get_desc()->width_in_bits;
    size_t hw_bucket_lsb = 2 * L2_ENTRY_WIDTH;
    size_t reg_idx = 0;
    while (hw_bucket_lsb < hw_bucket_st.entry_data.get_width()) {
        size_t data_to_write_width = std::min(hw_bucket_st.entry_data.get_width() - hw_bucket_lsb, reg_width_in_bits);
        status = m_ll_device->write_register(*(*m_cdb_core_pacific.lpm_rd_mod_wr_entry_regs)[reg_idx],
                                             hw_bucket_st.entry_data.bits(hw_bucket_lsb + data_to_write_width - 1, hw_bucket_lsb));
        return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());
        reg_idx += 1;
        hw_bucket_lsb += data_to_write_width;
    }

    // Set read modify write valid bit
    bit_vector valid_bit(1);
    status = m_ll_device->write_register(*m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_valid_reg, valid_bit /* set valid bit */);
    return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());

    if (m_revision == la_device_revision_e::PACIFIC_B1) {
        status = m_ll_device->write_memory(*m_cdb_core_pa_gb.cdb_core.subtrie_mem, L1_TRAP_LINE, m_l1_trap_hw_bucket);
    }

    return status;
}

la_status
lpm_core_hw_writer_pacific::calculate_bucket_location_in_hbm(size_t hw_index,
                                                             size_t repl_idx,
                                                             hbm_physical_location& out_hbm_location) const
{
    // Destination HW index is total 19b:
    // [3:0] - core index
    // [18:4] - bucket index between 4k and <end of HBM>
    // Note: core index is not a part of the L1 payload.
    hbm_hw_index_data hbm_hw_index = {.flat = (hw_index << HBM_CORE_ID_WIDTH) + m_core_id};
    out_hbm_location.column = hbm_hw_index.fields.bucket_column;
    out_hbm_location.row = hbm_hw_index.fields.bucket_row + 128 * repl_idx;

    size_t bank_channel = hbm_hw_index.fields.bucket_bank_channel + 4 * repl_idx;
    hbm_bank_channel_data bank_channel_data = {.flat = bank_channel};

    out_hbm_location.bank
        = (bank_channel_data.fields.bank_msb << hbm_bank_channel_data::LSB_WIDTH) + bank_channel_data.fields.bank_lsb;
    out_hbm_location.channel = bank_channel_data.fields.channel;

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_pacific::write_l2_hbm_line(size_t hw_index, const bit_vector& hbm_line_data) const
{
    const bool is_tall_channel[HBM_NUM_CHANNELS] = {false, false, true, true, true, true, false, false};
    const pacific_tree* tree = m_ll_device->get_pacific_tree();

    hbm_chnl_4x_tall_cpu_mem_access_register data = {.u8 = {0}};
    data.fields.send_command = 1;
    data.fields.cpu_rd_wr = 0; // write
    const uint64_t* hbm_line_data_arr = (const uint64_t*)hbm_line_data.byte_array();
    data.fields.set_cpu_data(hbm_line_data_arr);

    for (size_t repl_idx = 0; repl_idx < HBM_NUM_REPLICATIONS; ++repl_idx) {
        hbm_physical_location hbm_location;
        la_status status = calculate_bucket_location_in_hbm(hw_index, repl_idx, hbm_location);
        channel_info channel = {.flat = hbm_location.channel};
        data.fields.cpu_channel = channel.fields.cpu;
        data.fields.cpu_bank = hbm_location.bank;
        data.fields.cpu_row_addr = hbm_location.row;
        data.fields.cpu_col_addr = hbm_location.column;
        if (is_tall_channel[channel.fields.index]) {
            status = m_ll_device->write_register(*tree->hbm->chnl[channel.fields.index]->tall->cpu_mem_access, data);
        } else {
            status = m_ll_device->write_register(*tree->hbm->chnl[channel.fields.index]->wide->cpu_mem_access, data);
        }
        return_on_error(status);
    }

    log_xdebug(TABLES, "Wrote L2 HBM Bucket (idx: %zu): data = 0x%s", hw_index, hbm_line_data.to_string().c_str());

    return LA_STATUS_SUCCESS;
}

std::vector<lpm_entry>
lpm_core_hw_writer_pacific::read_l2_bucket(size_t hw_index, size_t& out_default_payload) const
{
    std::vector<lpm_entry> ret;
    if (hw_index >= m_hbm_address_offset) {
        // TODO implement
        log_err(TABLES, "Reading HBM buckets not supported");
        return ret;
    }
    const size_t GLOBAL_ECC_WIDTH = 22; // HW is writing 22 bits ECC at the beginning of the bank
    size_t hw_line = hw_index / 2;
    size_t bucket_idx = hw_index % 2;

    const lld_memory_desc_t* desc = m_cdb_core_pa_gb.cdb_core.srams_group->get_desc();
    size_t bank_width = desc->width_bits;

    // Read L2 line
    bit_vector l2_line_bv(0, m_l2_bucket_width);
    size_t mem_idx = 0;
    int data_to_read_width = (int)m_l2_bucket_width;
    while (data_to_read_width > 0) {
        bit_vector bank_val;
        la_status status = m_ll_device->read_memory(*(*m_cdb_core_pa_gb.cdb_core.srams_group)[mem_idx], hw_line, bank_val);
        if (status != LA_STATUS_SUCCESS) {
            return ret;
        }
        size_t lsb = mem_idx * bank_width;
        l2_line_bv.set_bits(lsb + bank_width - 1, lsb, bank_val);

        mem_idx += 1;
        data_to_read_width -= bank_width;
    }

    size_t shared_entries_to_1 = l2_line_bv.bits(GLOBAL_ECC_WIDTH + L2_COUNTER_WIDTH - 1, GLOBAL_ECC_WIDTH).get_value();
    dassert_crit(shared_entries_to_1 <= L2_NUM_OF_SHARED_ENTRIES);
    // In the shared segment, first entries go to bucket 1; last entries go to bucket 0
    // Encoding represent the splitting.
    size_t shared_start = (bucket_idx == 0) ? shared_entries_to_1 * L2_ENTRY_WIDTH : 0;
    shared_start += L2_NON_ENTRY_DATA_WIDTH + GLOBAL_ECC_WIDTH;
    size_t shared_end = (bucket_idx == 0) ? L2_NUM_OF_SHARED_ENTRIES * L2_ENTRY_WIDTH : shared_entries_to_1 * L2_ENTRY_WIDTH;
    shared_end += L2_NON_ENTRY_DATA_WIDTH + GLOBAL_ECC_WIDTH;

    // Shared entries
    std::vector<size_t> positions;
    for (size_t pos = shared_start; pos < shared_end; pos += L2_ENTRY_WIDTH) {
        positions.push_back(pos);
    }

    // Fixed entries
    // In L2, fixed entries are interleaved (b0e0, b1e0, b0e1, b1e1...)
    size_t fixed_pos = (bucket_idx == 0) ? 0 : L2_ENTRY_WIDTH;
    fixed_pos += L2_BUCKET_SHARED_ENTRIES_END + GLOBAL_ECC_WIDTH;
    while (fixed_pos < m_l2_bucket_width) {
        positions.push_back(fixed_pos);
        fixed_pos += 2 * L2_ENTRY_WIDTH;
    }

    bool is_double_entry = false;
    for (size_t pos : positions) {
        bit_vector entry_bv = l2_line_bv.bits(pos + L2_ENTRY_WIDTH - 1, pos);
        if (!is_double_entry) {
            ret.push_back(lpm_entry());
        }

        bit_vector prefix = entry_bv.bits(L2_ENTRY_PREFIX_START + ENTRY_ENC_PREFIX_WIDTH - 1, L2_ENTRY_PREFIX_START);
        if (prefix.get_value()) {
            lpm_entry& entry = ret.back();
            // only if prefix is not 0
            entry.valid = true;
            prefix = decode_prefix(prefix);
            entry.payload = entry_bv.bits(L2_ENTRY_PAYLOAD_START + L2_ENTRY_PAYLOAD_WIDTH - 1, L2_ENTRY_PAYLOAD_START).get_value();
            entry.is_l2_leaf = !entry_bv.bit(L2_ENTRY_TYPE_START);
            if (is_double_entry) {
                entry.prefix = entry.prefix << prefix.get_width();
                entry.prefix |= prefix;
                entry.prefix_width += prefix.get_width();
                entry.is_wide_entry = true;
                is_double_entry = false;
            } else {
                entry.prefix = prefix;
                entry.prefix_width = prefix.get_width();
                entry.index = (pos - L2_NON_ENTRY_DATA_WIDTH - GLOBAL_ECC_WIDTH) / L2_ENTRY_WIDTH;
            }

            is_double_entry = (entry.payload == LPM_DOUBLE_ENTRY_PAYLOAD_ENCODING);
        }
    }

    size_t default_start = GLOBAL_ECC_WIDTH + L2_COUNTER_WIDTH + ((bucket_idx == 0) ? 0 : L2_DEFAULT_WIDTH);
    bit_vector default_payload_bv = l2_line_bv.bits(default_start + L2_DEFAULT_WIDTH - 1, default_start);
    out_default_payload = default_payload_bv.get_value();

    return ret;
}

bool
lpm_core_hw_writer_pacific::is_mark_as_leaf(const lpm_node* node, bool is_hbm) const
{
    const lpm_key_t& node_key = node->get_key();
    if (!m_key_to_force_is_leaf.empty()) {
        auto it = m_key_to_force_is_leaf.find(node_key);
        if (it != m_key_to_force_is_leaf.end()) {
            return it->second;
        }
    }

    switch (m_revision) {
    case la_device_revision_e::PACIFIC_A0:
        return node->is_leaf();
    case la_device_revision_e::PACIFIC_B0: {
        bool is_ipv6 = node_key.bit_from_msb(0);
        return (is_hbm || is_ipv6);
    }
    case la_device_revision_e::PACIFIC_B1: // B1 and further
        return is_hbm;
    default:
        dassert_crit(false);
        return false;
    }
}

bool
lpm_core_hw_writer_pacific::should_force_is_default(const lpm_node* l2_node) const
{
    if (m_revision != la_device_revision_e::PACIFIC_A0) {
        return false;
    }

    // in A0, due to a bug in EM cache, we want all non-leaves to avoid cache, hence we mark them as default
    // Also, I think I (Amir) am smarter than Yair, and as a proof I am going to smuggle this comment right under his nose.
    return !l2_node->is_leaf();
}

bit_vector64_t
lpm_core_hw_writer_pacific::generate_l1_entry(const lpm_key_payload& key_payload, size_t root_width) const
{
    bit_vector64_t entry(0 /* value */, L1_ENTRY_WIDTH /* width */);

    lpm_payload_t payload = key_payload.payload;
    const lpm_key_t& key = key_payload.key;

    lpm_key_t prefix = encode_prefix(key, root_width, ENTRY_ENC_PREFIX_WIDTH);

    entry.set_bits(L1_ENTRY_ID_START - 1, L1_ENTRY_FULLNESS_START, L1_ENTRY_FULLNESS_VALUE);
    entry.set_bits(L1_ENTRY_PREFIX_START - 1, L1_ENTRY_ID_START, payload);
    entry.set_bits(L1_ENTRY_WIDTH - 1, L1_ENTRY_PREFIX_START, prefix);

    return entry;
}

void
lpm_core_hw_writer_pacific::set_entry_in_l1_bucket(bit_vector& hw_bucket,
                                                   size_t offset,
                                                   const lpm_key_payload& key_payload,
                                                   size_t root_width) const
{
    bit_vector64_t entry(generate_l1_entry(key_payload, root_width));
    hw_bucket.set_bits(offset + L1_ENTRY_WIDTH - 1, offset, entry);
}

size_t
lpm_core_hw_writer_pacific::sort_nodes_for_l2_bucket_generation(vector_alloc<lpm_node*>& nodes, size_t root_width) const
{
    // Sort nodes vector to have all double entries in the beginning and single entries in the end.
    // Helps handle two HW demands: double entries should start in even indices, and last fixed entry can't be a double.
    size_t nodes_size = nodes.size();
    size_t first_single_index = 0;
    for (size_t i = 0; i < nodes_size; i++) {
        const lpm_key_t& node_key = nodes[i]->get_key();
        size_t node_key_width = node_key.get_width();
        if (node_key_width > (root_width + ENTRY_PREFIX_WIDTH)) {
            iter_swap(nodes.begin() + first_single_index, nodes.begin() + i);
            first_single_index++;
        }
    }

    return first_single_index;
}

lpm_core_hw_writer_pacific::l2_sram_line
lpm_core_hw_writer_pacific::generate_l2_sram_line(const lpm_bucket* bucket, const lpm_bucket* neighbor_bucket) const
{
    l2_sram_line hw_bucket_data;
    hw_bucket_data.non_entry_data.flat = 0;

    size_t double_bucket_entries_width = ((m_l2_num_fixed_entries * 2) + L2_NUM_OF_SHARED_ENTRIES) * L2_ENTRY_WIDTH;
    hw_bucket_data.entry_data = bit_vector(0, double_bucket_entries_width);
    uint64_t* line_entry_data = (uint64_t*)hw_bucket_data.entry_data.byte_array();
    bool has_double_entries = false;

    for (const lpm_bucket* current_bucket : {bucket, neighbor_bucket}) {
        if (current_bucket == nullptr) {
            continue;
        }

        const lpm_nodes_bucket* nodes_bucket = static_cast<const lpm_nodes_bucket*>(current_bucket);
        const lpm_payload_t default_payload = nodes_bucket->get_default_entry().payload;
        size_t root_width = nodes_bucket->get_root_width();
        size_t bucket_idx = nodes_bucket->get_hw_index() % 2;
        set_l2_sram_default(hw_bucket_data, bucket_idx, default_payload);

        size_t node_idx = 0;
        size_t shared_index = 0;
        for (const auto& node : nodes_bucket->get_nodes()) {
            const lpm_key_t& node_key = node->get_key();
            size_t prefix_width = node_key.get_width() - root_width;
            if (prefix_width == 0) {
                size_t bucket_size = nodes_bucket->size();
                bool is_leaf = is_mark_as_leaf(node, false /* is_hbm */);
                if (is_leaf && (bucket_size == 1)) {
                    handle_leaf_default_for_empty_sram_bucket(line_entry_data, bucket_idx, node);
                    break;
                } else {
                    const lpm_bucketing_data& node_data = node->data();
                    set_l2_sram_default(hw_bucket_data, bucket_idx, node_data.payload);
                }
            } else if (prefix_width <= ENTRY_PREFIX_WIDTH) {
                l2_sram_single_entry enc_entry = generate_single_sram_entry(node, prefix_width);
                set_l2_sram_line_entry(line_entry_data, node_idx, bucket_idx, enc_entry);
                node_idx++;
                if (bucket_idx == 1 && node_idx > m_l2_num_fixed_entries) {
                    shared_index++;
                }
            } else {
                has_double_entries = true;
                l2_sram_double_entry enc_entry = generate_double_entry(node, prefix_width);
                set_line_double_entry(line_entry_data, shared_index, bucket_idx, enc_entry);
                shared_index += 2;
            }
        }

        if (has_double_entries) {
            // HW limitation: when all shared entries are doubles we must write 0xfffff in the 20 first LSB-s of the entries part,
            // even if bucket1 is null or doesn't have shared entries.
            uint64_t double_payload_encoding = LPM_DOUBLE_ENTRY_PAYLOAD_ENCODING;
            bit_utils::set_bits(line_entry_data, L2_ENTRY_PAYLOAD_WIDTH - 1, 0, &double_payload_encoding);
        }

        if (bucket_idx == 1) {
            hw_bucket_data.non_entry_data.data_struct.bucket1_shared_entries = shared_index;
        }
    }

    return hw_bucket_data;
}

lpm_core_hw_writer_pacific::l2_sram_single_entry
lpm_core_hw_writer_pacific::generate_single_sram_entry(const lpm_node* node, size_t prefix_width) const
{
    l2_sram_single_entry entry;
    const lpm_key_t& node_key = node->get_key();
    size_t prefix_value = node_key.bits(prefix_width - 1, 0).get_value();
    bool leaf = is_mark_as_leaf(node, false /* is_hbm */);

    const lpm_bucketing_data& node_data = node->data();
    entry.payload = node_data.payload;
    entry.key = encode_key_length(prefix_value, prefix_width);
    entry.non_leaf = !leaf;

    return entry;
}

size_t
lpm_core_hw_writer_pacific::encode_key_length(size_t prefix_value, size_t length) const
{
    dassert_crit(bit_utils::get_msb(prefix_value) <= (int)length);
    return (prefix_value << (ENTRY_ENC_PREFIX_WIDTH - length)) | (1 << (ENTRY_ENC_PREFIX_WIDTH - length - 1));
}

lpm_core_hw_writer_pacific::l2_sram_double_entry
lpm_core_hw_writer_pacific::generate_double_entry(const lpm_node* node, size_t prefix_width) const
{
    dassert_crit(prefix_width > ENTRY_PREFIX_WIDTH);
    l2_sram_double_entry entry;

    const lpm_key_t& node_key = node->get_key();
    size_t prefix_value = node_key.bits(prefix_width - 1, 0).get_value();
    size_t lsb_width = prefix_width - ENTRY_PREFIX_WIDTH;
    size_t prefix_lsb = bit_utils::get_bits(prefix_value, lsb_width - 1, 0);
    size_t encoded_lsb = encode_key_length(prefix_lsb, lsb_width);

    bool leaf = is_mark_as_leaf(node, false /* is_hbm */);

    entry.double_entry_enc = 0x1fffff;
    entry.msb_key = prefix_value >> lsb_width;
    entry.non_leaf0 = !leaf;
    const lpm_bucketing_data& node_data = node->data();
    entry.payload = node_data.payload;
    entry.lsb_key = encoded_lsb;
    entry.non_leaf1 = !leaf;

    return entry;
}

void
lpm_core_hw_writer_pacific::handle_leaf_default_for_empty_sram_bucket(uint64_t* line_entry_data,
                                                                      size_t bucket_idx,
                                                                      const lpm_node* node) const
{
    // default_entry is hard(ware)-coded to be marked as is_node which is not always correct.
    // If bucket has only a default (and no more nodes) then it is a leaf
    // and we'll write it as a regular entry rather than the default.
    // Since regular entries cannot have a length of zero (hardware bug), we'll use
    // two entries with length /1 each.
    l2_sram_single_entry enc_entry;
    const lpm_bucketing_data& node_data = node->data();
    enc_entry.payload = node_data.payload;
    enc_entry.non_leaf = false;

    enc_entry.key = encode_key_length(0 /* prefix */, 1 /* length*/);
    set_l2_sram_line_entry(line_entry_data, 0, bucket_idx, enc_entry);
    enc_entry.key = encode_key_length(1 /* prefix */, 1 /* length*/);
    set_l2_sram_line_entry(line_entry_data, 1, bucket_idx, enc_entry);
    return;
}

void
lpm_core_hw_writer_pacific::set_l2_sram_default(l2_sram_line& hw_bucket_data,
                                                size_t bucket_idx,
                                                lpm_payload_t default_payload) const
{
    if (bucket_idx == 0) {
        hw_bucket_data.non_entry_data.data_struct.bucket0_default = default_payload;
    } else {
        hw_bucket_data.non_entry_data.data_struct.bucket1_default = default_payload;
    }
}

void
lpm_core_hw_writer_pacific::set_line_double_entry(uint64_t* line_entry_data,
                                                  size_t entry_idx,
                                                  size_t bucket_idx,
                                                  const l2_sram_double_entry& val) const
{
    // Must be shared entry
    // Within the shared entries bucket1 entries are the LSBs.
    // Below is the layout of a line with the entries indexes:
    //
    //  F(ixed), S(hared), D(ouble)
    //  +-----------------------------------------------------------+
    //   F0 ...  F0  F1 ...  F1 S13 ... ... ... ...  S0
    //  +-----------------------------+---------+---------+---------
    //                                   D6       ...      D0
    //                                +-----------------------------+

    dassert_crit(bucket_idx < 2);
    dassert_crit(entry_idx % 2 == 0);
    dassert_crit(entry_idx < L2_NUM_OF_SHARED_ENTRIES);

    size_t physical_entry_idx_in_row = (bucket_idx == 0) ? (L2_NUM_OF_SHARED_ENTRIES - entry_idx) - 2 : entry_idx;

    size_t lsb = physical_entry_idx_in_row * L2_ENTRY_WIDTH;
    size_t msb = lsb + (2 * L2_ENTRY_WIDTH) - 1;

    dassert_slow(verify_no_overrides(line_entry_data, msb, lsb));

    bit_utils::set_bits(line_entry_data, msb, lsb, (uint64_t*)&val);
}

void
lpm_core_hw_writer_pacific::set_l2_sram_line_entry(uint64_t* line_entry_data,
                                                   size_t entry_idx,
                                                   size_t bucket_idx,
                                                   const l2_sram_single_entry& val) const
{
    // entry_data is array of entries where the MSBs are the interleaved and the LSB are the shared.
    // Within the shared entries bucket1 entries are the LSBs.
    // Below is the layout of a line with the entries indexes:
    //
    // b1-F | b0-F | b1-F | b0-F | ... | b1-F | b0-F | b0-S | b0-S | ... | b0-S | b1-S | ... | b1-S | b1-S
    //  e7     e6     e5     e4    ...    e1     e0   e_last  .........   e11     e10   ...    e9     e8

    dassert_crit(bucket_idx < 2);
    size_t physical_entry_idx_in_row;
    if (entry_idx >= m_l2_num_fixed_entries) {
        // Shared
        size_t shared_idx = entry_idx - m_l2_num_fixed_entries;
        physical_entry_idx_in_row = (bucket_idx == 0) ? (L2_NUM_OF_SHARED_ENTRIES - 1 - shared_idx) : shared_idx;
    } else {
        // Fixed
        physical_entry_idx_in_row = L2_NUM_OF_SHARED_ENTRIES + (2 * entry_idx) + bucket_idx;
    }

    size_t lsb = physical_entry_idx_in_row * L2_ENTRY_WIDTH;
    size_t msb = lsb + L2_ENTRY_WIDTH - 1;

    dassert_slow(verify_no_overrides(line_entry_data, msb, lsb));

    bit_utils::set_bits(line_entry_data, msb, lsb, (uint64_t*)&val);
}

bit_vector
lpm_core_hw_writer_pacific::generate_l2_hbm_bucket(const lpm_bucket* bucket) const
{
    dassert_crit(bucket->size() <= HBM_NUM_ENTRIES);

    bit_vector hw_bucket(0 /* value */, HBM_LINE_WIDTH /* width */);
    uint64_t* line_entry_data = (uint64_t*)hw_bucket.byte_array();

    const lpm_nodes_bucket* nodes_bucket = static_cast<const lpm_nodes_bucket*>(bucket);
    lpm_payload_t default_payload = nodes_bucket->get_default_entry().payload;
    size_t root_width = nodes_bucket->get_root_width();

    size_t node_idx = 0;
    for (const auto& node : nodes_bucket->get_nodes()) {
        size_t prefix_width = node->get_width() - root_width;
        if (prefix_width == 0) {
            size_t bucket_size = nodes_bucket->size();
            bool is_leaf = is_mark_as_leaf(node, true /* is_hbm */);
            const lpm_bucketing_data& node_data = node->data();
            default_payload = node_data.payload;
            if (is_leaf && (bucket_size == 1)) {
                handle_leaf_default_for_empty_hbm_bucket(line_entry_data, node);
                break;
            }
        } else {
            l2_hbm_entry enc_entry = generate_hbm_entry(node, prefix_width);
            set_l2_hbm_line_entry(line_entry_data, node_idx, enc_entry);
            node_idx++;
        }
    }

    set_hbm_default(line_entry_data, default_payload);

    return hw_bucket;
}

void
lpm_core_hw_writer_pacific::handle_leaf_default_for_empty_hbm_bucket(uint64_t* line_entry_data, const lpm_node* node) const
{
    // default_entry is hard(ware)-coded to be marked as is_node which is not always correct.
    // If bucket has only a default (and no more nodes) then it is a leaf
    // and we'll write it as a regular entry rather than the default.
    // Since regular entries cannot have a length of zero (hardware bug), we'll use
    // two entries with length /1 each.
    l2_hbm_entry enc_entry;
    const lpm_bucketing_data& node_data = node->data();
    enc_entry.payload = node_data.payload;
    enc_entry.non_leaf = false;

    enc_entry.key = encode_key_length(0 /* prefix */, 1 /* length*/);
    set_l2_hbm_line_entry(line_entry_data, 0, enc_entry);
    enc_entry.key = encode_key_length(1 /* prefix */, 1 /* length*/);
    set_l2_hbm_line_entry(line_entry_data, 1, enc_entry);
    return;
}

void
lpm_core_hw_writer_pacific::set_hbm_default(uint64_t* line_entry_data, lpm_payload_t default_payload) const
{
    for (size_t section_idx = 0; section_idx < HBM_NUM_SECTIONS; ++section_idx) {
        size_t lsb = section_idx * HBM_SECTION_WIDTH;
        size_t msb = lsb + L2_DEFAULT_WIDTH - 1;

        dassert_slow(verify_no_overrides(line_entry_data, msb, lsb));
        uint64_t payload = default_payload;
        bit_utils::set_bits(line_entry_data, msb, lsb, &payload);
    }
}

lpm_core_hw_writer_pacific::l2_hbm_entry
lpm_core_hw_writer_pacific::generate_hbm_entry(const lpm_node* node, size_t prefix_width) const
{
    l2_hbm_entry entry;
    const lpm_key_t& node_key = node->get_key();
    size_t prefix_value = node_key.bits(prefix_width - 1, 0).get_value();
    bool leaf = is_mark_as_leaf(node, true /* is_hbm */);

    entry.key = encode_key_length(prefix_value, prefix_width);
    const lpm_bucketing_data& node_data = node->data();
    entry.payload = node_data.payload;
    entry.non_leaf = !leaf;

    return entry;
}

void
lpm_core_hw_writer_pacific::set_l2_hbm_line_entry(uint64_t* line_entry_data, size_t entry_idx, const l2_hbm_entry& val) const
{
    size_t section_idx = entry_idx / HBM_NUM_ENTRIES_IN_SECTION;
    size_t section_entries_lsb = (section_idx * HBM_SECTION_WIDTH) + L2_DEFAULT_WIDTH;

    size_t idx_within_section = entry_idx % HBM_NUM_ENTRIES_IN_SECTION;
    size_t prefix_lsb = section_entries_lsb + (idx_within_section * L2_ENTRY_WIDTH);
    size_t prefix_msb = prefix_lsb + L2_ENTRY_WIDTH - 1;

    dassert_slow(verify_no_overrides(line_entry_data, prefix_msb, prefix_lsb));
    bit_utils::set_bits(line_entry_data, prefix_msb, prefix_lsb, (uint64_t*)&val);
}

lpm_core_hw_writer_pacific::l1_bucket_data
lpm_core_hw_writer_pacific::init_l1_bucket_data(const lpm_bucket* bucket) const
{
    l1_bucket_data ret;

    if (!bucket) {
        return ret;
    }

    const lpm_buckets_bucket* buckets_bucket = static_cast<const lpm_buckets_bucket*>(bucket);
    ret.entries = buckets_bucket->get_entries();
    ret.has_zero_width_entry = false;

    ret.root_width = std::min((size_t)TCAM_PAYLOAD_FIELD_LENGTH_MAX_VALUE + 1, bucket->get_root_width());
    auto it = ret.entries.begin();
    for (; it != ret.entries.end(); ++it) {
        size_t width = (*it).key.get_width();
        if (width - ret.root_width == 0) {
            ret.has_zero_width_entry = true;
            ret.zero_width_entry = (*it);
            break;
        }
    }

    ret.num_interleaved_entries = std::min((size_t)L1_NUM_OF_FIXED_ENTRIES, ret.entries.size());
    ret.num_shared_entries = ret.entries.size() - ret.num_interleaved_entries;

    if (it != ret.entries.end()) {
        ret.entries.erase(it);
        ret.num_interleaved_entries--;
    }

    return ret;
}

bit_vector
lpm_core_hw_writer_pacific::generate_l1_bucket(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const
{
    l1_bucket_data data0 = init_l1_bucket_data(bucket0);
    l1_bucket_data data1 = init_l1_bucket_data(bucket1);

    // Compact the data into the shared area.
    // Add from the largest bucket
    size_t shared_entries_to_add = L1_NUM_OF_SHARED_ENTRIES - (data0.num_shared_entries + data1.num_shared_entries);
    while ((data0.num_interleaved_entries > 0 || data1.num_interleaved_entries > 0) && shared_entries_to_add > 0) {
        if (data0.num_interleaved_entries > data1.num_interleaved_entries) {
            data0.num_interleaved_entries--;
            data0.num_shared_entries++;
        } else {
            data1.num_interleaved_entries--;
            data1.num_shared_entries++;
        }
        shared_entries_to_add--;
    }

    // Make sure that shared entries are continuos, i.e. bucket1 gets exactly how much it needs.
    size_t encoding = data1.num_shared_entries;

    // Non entry data
    lpm_key_payload default0{};
    lpm_key_payload default1{};

    if (bucket0) {
        default0 = bucket0->get_default_entry();
    }

    if (bucket1) {
        default1 = bucket1->get_default_entry();
    }

    bit_vector hw_bucket(0 /* value */, L1_BUCKET_WIDTH /* width */);
    hw_bucket.set_bits(L1_COUNTER_WIDTH - 1, 0, bit_vector64_t(encoding));
    hw_bucket.set_bits(L1_COUNTER_WIDTH + L1_DEFAULT_WIDTH - 1, L1_COUNTER_WIDTH, default0.payload);
    hw_bucket.set_bits(L1_NON_ENTRY_DATA_WIDTH - 1, L1_COUNTER_WIDTH + L1_DEFAULT_WIDTH, default1.payload);

    size_t offset = L1_NON_ENTRY_DATA_WIDTH;
    size_t bucket0_idx = 0;
    size_t bucket1_idx = 0;

    // Shared entries 1 - not an error: bucket 1 is located at the beginning
    for (; bucket1_idx < data1.num_shared_entries; ++bucket1_idx, offset += L1_ENTRY_WIDTH) {
        set_entry_in_l1_bucket(hw_bucket, offset, data1.entries[bucket1_idx], data1.root_width);
    }

    // Shared entries 0 - not an error: bucket 0 is located at location 1
    for (; bucket0_idx < data0.num_shared_entries; ++bucket0_idx, offset += L1_ENTRY_WIDTH) {
        set_entry_in_l1_bucket(hw_bucket, offset, data0.entries[bucket0_idx], data0.root_width);
    }

    // In contrary to L2, in L1, the interleaved entries are placed [bucket0[0], bucket0[1], bucket1[0], bucket1[1]]
    // Fixed interleaved entries 0
    offset = L1_BUCKET_SHARED_ENTRIES_END;
    for (size_t i = 0; i < L1_NUM_OF_FIXED_ENTRIES; ++i) {
        if (bucket0_idx < data0.entries.size()) {
            set_entry_in_l1_bucket(hw_bucket, offset, data0.entries[bucket0_idx++], data0.root_width);
        }
        offset += L1_ENTRY_WIDTH;
    }
    dassert_crit(bucket0_idx == data0.entries.size());

    // Fixed interleaved entries 1
    for (size_t i = 0; i < L1_NUM_OF_FIXED_ENTRIES; ++i) {
        if (bucket1_idx < data1.entries.size()) {
            set_entry_in_l1_bucket(hw_bucket, offset, data1.entries[bucket1_idx++], data1.root_width);
        }
        offset += L1_ENTRY_WIDTH;
    }
    dassert_crit(bucket1_idx == data1.entries.size());

    // Zero width entry must be the last entry in every L1 bucket.
    if (data0.has_zero_width_entry) {
        offset = L1_BUCKET_WIDTH - (L1_NUM_OF_FIXED_ENTRIES + 1) * L1_ENTRY_WIDTH;
        set_entry_in_l1_bucket(hw_bucket, offset, data0.zero_width_entry, data0.root_width);
    }

    if (data1.has_zero_width_entry) {
        offset = L1_BUCKET_WIDTH - 1 * L1_ENTRY_WIDTH;
        set_entry_in_l1_bucket(hw_bucket, offset, data1.zero_width_entry, data1.root_width);
    }

    return hw_bucket;
}

la_status
lpm_core_hw_writer_pacific::read_index_of_last_accessed_l2_sram_buckets(vector_alloc<size_t>& out_bucket_indexes)
{
    cdb_core_lpm_last_shared_sram_ptr_reg_register reg;
    la_status status = m_ll_device->read_register(*m_cdb_core_pacific.lpm_last_shared_sram_ptr_reg, reg);
    return_on_error(status);
    size_t row = reg.fields.lpm_last_shared_sram_ptr;
    out_bucket_indexes.push_back(2 * row);
    out_bucket_indexes.push_back(2 * row + 1);

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
