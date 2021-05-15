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
#include "lld/gibraltar_tree.h"
#include "lld/interrupt_tree.h"
#include "lld/ll_device.h"

#include "lpm_bucket.h"
#include "lpm_buckets_bucket.h"
#include "lpm_core_hw_writer_gb.h"
#include "lpm_core_tcam.h"
#include "lpm_nodes_bucket.h"

namespace silicon_one
{

lpm_core_hw_writer_gb::lpm_core_hw_writer_gb(const ll_device_sptr& ldevice,
                                             lpm_core_id_t core_id,
                                             size_t l2_double_bucket_size,
                                             uint8_t tcam_num_banksets)
    : lpm_core_hw_writer_pacific_gb(ldevice, core_id, tcam_num_banksets), m_use_fat_hbm_buckets(false)
{
    if (!m_ll_device) {
        // This is an empty object to mimic HW writes.
        // It should not be initialized and will not be used.
        return;
    }

    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();

    lpm_core_id_t lpm_core_idx = core_id & 0x1; // first bit
    lpm_core_id_t cdb_core_idx = core_id >> 1;  // idx in cdb core array

    // TCAM
    const size_t TOTAL_NUM_TCAMS = m_tcam_num_banksets * NUM_TCAMS_PER_BANKSET;
    m_cdb_core_pa_gb.cdb_core.lpm_tcam.resize(TOTAL_NUM_TCAMS);

    if (lpm_core_idx == 0) {
        for (size_t i = 0; i < TOTAL_NUM_TCAMS; i++) {
            m_cdb_core_pa_gb.cdb_core.lpm_tcam[i] = (*tree->cdb->core[cdb_core_idx]->lpm0_tcam)[i];
        }
    } else {
        for (size_t i = 0; i < TOTAL_NUM_TCAMS; i++) {
            m_cdb_core_pa_gb.cdb_core.lpm_tcam[i] = (*tree->cdb->core[cdb_core_idx]->lpm1_tcam)[i];
        }
    }

    m_cdb_core_pa_gb.trie_mem[0] = (*tree->cdb->core[cdb_core_idx]->trie_mem)[lpm_core_idx];
    m_cdb_core_pa_gb.trie_mem[1] = (*tree->cdb->core[cdb_core_idx]->extnd_trie_mem)[lpm_core_idx];

    // L1
    m_cdb_core_pa_gb.cdb_core.subtrie_mem = (*tree->cdb->core[cdb_core_idx]->subtrie_mem)[lpm_core_idx];
    m_cdb_core_pa_gb.subtrie_extended_mem = (*tree->cdb->core[cdb_core_idx]->extnd_subtrie_mem)[lpm_core_idx];

    // L2
    m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_valid_reg = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr)[lpm_core_idx];
    m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_address_reg = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_address_reg)[lpm_core_idx];
    m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_non_entry_data_reg
        = (*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_non_entry_data_reg)[lpm_core_idx];
    m_cdb_core_gb.lpm_rd_mod_wr_group_data_reg = (lpm_core_idx == 0) ? tree->cdb->core[cdb_core_idx]->lpm0_rd_mod_wr_group_data_reg
                                                                     : tree->cdb->core[cdb_core_idx]->lpm1_rd_mod_wr_group_data_reg;
    m_cdb_core_pa_gb.cdb_core.srams_group
        = (lpm_core_idx == 0) ? tree->cdb->core[cdb_core_idx]->srams_group0 : tree->cdb->core[cdb_core_idx]->srams_group1;
    m_cdb_core_pa_gb.cdb_core.ecc_1b_int_reg = (*tree->cdb->core[cdb_core_idx]->lpm_shared_sram_1b_err_int_reg)[lpm_core_idx];
    m_cdb_core_pa_gb.cdb_core.ecc_2b_int_reg = (*tree->cdb->core[cdb_core_idx]->lpm_shared_sram_2b_err_int_reg)[lpm_core_idx];

    m_cdb_core_gb.accessed_buckets_wr = tree->cdb->core[cdb_core_idx]->lpm_l2_accessed_buckets_wr;
    m_cdb_core_gb.accessed_buckets_status_reg = tree->cdb->core[cdb_core_idx]->lpm_l2_accessed_buckets_status_reg;

    // Setting timer bubble for HW purposes only, the change from pacific is it was internal HW data and now
    // it is configurable from SDK
    // This bubble is to make sure that will be availible buble for read modify write
    m_ll_device->write_register(*(*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_bubble_timer_reg)[0], bit_vector(0x7));
    m_ll_device->write_register(*(*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_bubble_timer_reg)[1], bit_vector(0x7));

    m_l2_bucket_width = L2_NON_ENTRY_DATA_WIDTH + l2_double_bucket_size * L2_ENTRY_WIDTH;
    size_t num_groups = l2_double_bucket_size / 2;
    m_l2_bucket_num_interleaved_groups = std::max(((int)num_groups - (int)L2_NUM_OF_SHARED_GROUPS) / 2, 0);
    m_l2_all_groups_width = L2_GROUP_WIDTH * num_groups;

    // In pacific and GB we need to update the whole line every time we write a bucket, it will be changed in graphine
    // In order to write the whole line we need to configure this register to 31
    // If we would like entry we would need to put the id of the entry (not in pacific and GB)
    const lld_register& lpm_rd_mod_wr_id_reg = *(*tree->cdb->core[cdb_core_idx]->lpm_rd_mod_wr_id_reg)[lpm_core_idx];
    bit_vector write_all_line = bit_vector::ones(lpm_rd_mod_wr_id_reg.get_desc()->width_in_bits);
    la_status status = m_ll_device->write_register(lpm_rd_mod_wr_id_reg, write_all_line);
    dassert_crit(status == LA_STATUS_SUCCESS);

    // Initialize registers that won't be used later during update of L2 line.
    size_t num_rd_mod_wr_data_regs = m_cdb_core_gb.lpm_rd_mod_wr_group_data_reg->get_desc()->instances;
    for (size_t reg_idx = 0; reg_idx < num_rd_mod_wr_data_regs; reg_idx++) {
        status = m_ll_device->write_register(*(*m_cdb_core_gb.lpm_rd_mod_wr_group_data_reg)[reg_idx], 0 /* value */);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }
}

la_status
lpm_core_hw_writer_gb::write_l1_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }
    dassert_crit(bucket0);

    lpm_bucket_index_t hw_index = bucket0->get_hw_index();
    lpm_bucket_index_t hw_row = hw_index / 2;

    l1_hw_line l1_fields = generate_l1_line(bucket0, bucket1);
    bit_vector hw_line(l1_fields);

    log_l1_double_bucket(hw_row, bucket0, bucket1, hw_line);

    // Write L1 bucket
    dassert_crit(hw_line.get_width() == m_cdb_core_pa_gb.cdb_core.subtrie_mem->get_desc()->width_bits);
    size_t l1_subtrie_mem_rows = m_cdb_core_pa_gb.cdb_core.subtrie_mem->get_desc()->entries;
    const lld_memory* subtrie_mem;
    if (hw_row < (int)l1_subtrie_mem_rows) {
        subtrie_mem = m_cdb_core_pa_gb.cdb_core.subtrie_mem.get();
    } else {
        subtrie_mem = m_cdb_core_pa_gb.subtrie_extended_mem.get();
        hw_row -= l1_subtrie_mem_rows;
    }

    la_status status = m_ll_device->write_memory(*subtrie_mem, hw_row /* line */, hw_line);
    return status;
}

std::vector<lpm_entry>
lpm_core_hw_writer_gb::read_l1_bucket(size_t hw_index, size_t& out_default_payload) const
{
    log_err(TABLES, "Function is not implmeneted yet");
    dassert_crit(false);
    return std::vector<lpm_entry>();
}

void
lpm_core_hw_writer_gb::log_l1_double_bucket(lpm_bucket_index_t hw_row,
                                            const lpm_bucket* bucket0,
                                            const lpm_bucket* bucket1,
                                            const bit_vector& hw_bucket) const
{
    if (!logger::instance().is_logging(m_ll_device->get_device_id(), la_logger_component_e::TABLES, la_logger_level_e::DEBUG)) {
        return;
    }

    // Encoding represents allocation of non-shared entries between the buckets
    const size_t payload_start = 0;

    size_t shared_entries_to_1 = hw_bucket.bits(L1_COUNTER_WIDTH - 1, 0).get_value();
    size_t shared_entries_to_0 = L1_NUM_OF_SHARED_ENTRIES - shared_entries_to_1;
    log_debug(TABLES,
              "lpm::write_l1_line(core: %d, hw_row: %d, shared_entries [0]: %zu, [1]: %zu, default [0]: 0x%s, [1]: 0x%s, sw_index "
              "[0]: %d, [1]: %d)",
              m_core_id,
              hw_row,
              shared_entries_to_0,
              shared_entries_to_1,
              hw_bucket.bits(L1_NON_ENTRY_DATA_WIDTH - L1_PAYLOAD_WIDTH - 1, L1_NON_ENTRY_DATA_WIDTH - 2 * L1_PAYLOAD_WIDTH)
                  .to_string()
                  .c_str(),
              hw_bucket.bits(L1_NON_ENTRY_DATA_WIDTH - 1, L1_NON_ENTRY_DATA_WIDTH - L1_PAYLOAD_WIDTH).to_string().c_str(),
              bucket0 ? (int)bucket0->get_sw_index() : -1,
              bucket1 ? (int)bucket1->get_sw_index() : -1);

    for (size_t entry = L1_NON_ENTRY_DATA_WIDTH; entry < hw_bucket.get_width(); entry += L1_ENTRY_WIDTH) {
        bit_vector entry_bv = hw_bucket.bits(entry + L1_ENTRY_WIDTH - 1, entry);
        size_t prefix = entry_bv.bits(L1_PAYLOAD_WIDTH + ENTRY_ENC_PREFIX_WIDTH - 1, L1_PAYLOAD_WIDTH).get_value();
        if (prefix) {
            log_spam(TABLES,
                     "lpm::write_l1_line(idx: %zd, prefix: 0x%s, payload: 0x%s)",
                     (entry - L1_NON_ENTRY_DATA_WIDTH) / L1_ENTRY_WIDTH,
                     entry_bv.bits(L1_PAYLOAD_WIDTH + ENTRY_ENC_PREFIX_WIDTH - 1, L1_PAYLOAD_WIDTH).to_string().c_str(),
                     entry_bv.bits(payload_start + L1_PAYLOAD_WIDTH - 1, payload_start).to_string().c_str());
        }
    }
}

void
lpm_core_hw_writer_gb::log_l2_double_bucket(lpm_bucket_index_t hw_row,
                                            const lpm_bucket* bucket0,
                                            const lpm_bucket* bucket1,
                                            const l2_sram_line& hw_l2_line) const
{
    if (!logger::instance().is_logging(m_ll_device->get_device_id(), la_logger_component_e::TABLES, la_logger_level_e::DEBUG)) {
        return;
    }

    // Encoding represents allocation of non-shared entries between the buckets

    size_t shared_entries_to_1 = hw_l2_line.non_entry_data.data_struct.counter;
    size_t shared_entries_to_0 = L2_NUM_OF_SHARED_ENTRIES - shared_entries_to_1;
    log_debug(TABLES,
              "lpm::write_l2_line(core: %d, hw_row: %d, shared_entries [0]: %zu, [1]: %zu, default [0]: 0x%s, [1]: 0x%s, sw_index "
              "[0]: %d, [1]: %d)",
              m_core_id,
              hw_row,
              shared_entries_to_0,
              shared_entries_to_1,
              bit_vector(hw_l2_line.non_entry_data.data_struct.bucket0_default, L2_DEFAULT_WIDTH).to_string().c_str(),
              bit_vector(hw_l2_line.non_entry_data.data_struct.bucket1_default, L2_DEFAULT_WIDTH).to_string().c_str(),
              bucket0 ? (int)bucket0->get_sw_index() : -1,
              bucket1 ? (int)bucket1->get_sw_index() : -1);

    log_l2_groups(hw_l2_line, "shared" /*group_name*/, 0 /*group_start*/, L2_BUCKET_SHARED_GROUPS_WIDTH);
    log_l2_groups(
        hw_l2_line, "interleaved_bucket0" /*group_name*/, L2_BUCKET_SHARED_GROUPS_WIDTH, m_l2_all_groups_width, L2_ENTRY_WIDTH + 1);
    log_l2_groups(hw_l2_line,
                  "interleaved_bucket1" /*group_name*/,
                  L2_BUCKET_SHARED_GROUPS_WIDTH + L2_ENTRY_WIDTH + 1,
                  m_l2_all_groups_width,
                  L2_ENTRY_WIDTH);
}

void
lpm_core_hw_writer_gb::log_l2_groups(const l2_sram_line& hw_l2_line,
                                     const char* group_name,
                                     int group_start,
                                     int group_end,
                                     int bits_between_entries) const
{
    size_t group_width = L2_GROUP_WIDTH;
    if (bits_between_entries != 0) {
        group_width *= 2;
    }
    for (size_t entry = group_start; entry < (size_t)group_end; entry += group_width) {
        bit_vector group_bv = hw_l2_line.entry_data.bits(entry + group_width - 1, entry);
        l2_group_data group;
        get_shared_group_for_log(group_bv, bits_between_entries, group);
        if (group.fields.prefix0 || group.fields.prefix1) {
            log_spam(
                TABLES,
                "lpm::write_l2_line_%s_group(group_idx: %zd, double entry: %s, prefix0: 0x%05lx, is leaf0: %s, payload0: 0x%07lx "
                "prefix1: 0x%05lx, is leaf1: %s, payload1: 0x%07lx)",
                group_name,
                entry / L2_GROUP_WIDTH,
                group.fields.is_double ? "true" : "false",
                group.fields.prefix0,
                group.fields.is_leaf0 ? "true" : "false",
                group.fields.payload0,
                group.fields.prefix1,
                group.fields.is_leaf1 ? "true" : "false",
                group.fields.payload1);
        } else {
            break;
        }
    }
}

void
lpm_core_hw_writer_gb::get_shared_group_for_log(const bit_vector& group_bv,
                                                size_t bits_between_entries,
                                                l2_group_data& out_group) const
{
    size_t lsb = L2_ENTRY_PREFIX_START;
    size_t msb = L2_ENTRY_PREFIX_START + L2_IS_DOUBLE_GROUP_WIDTH - 1;
    out_group.fields.is_double = group_bv.bits(msb, lsb).get_value();
    lsb += L2_IS_DOUBLE_GROUP_WIDTH;
    msb += ENTRY_ENC_PREFIX_WIDTH;
    out_group.fields.prefix0 = group_bv.bits(msb, lsb).get_value();
    lsb += ENTRY_ENC_PREFIX_WIDTH;
    msb += L2_ENTRY_TYPE_WIDTH;
    out_group.fields.is_leaf0 = group_bv.bits(msb, lsb).get_value();
    lsb += L2_ENTRY_TYPE_WIDTH;
    msb += L2_ENTRY_PAYLOAD_WIDTH;
    out_group.fields.payload0 = group_bv.bits(msb, lsb).get_value();
    lsb += L2_ENTRY_PAYLOAD_WIDTH + bits_between_entries;
    msb += bits_between_entries;
    msb += ENTRY_ENC_PREFIX_WIDTH;
    out_group.fields.prefix0 = group_bv.bits(msb, lsb).get_value();
    lsb += ENTRY_ENC_PREFIX_WIDTH;
    msb += L2_ENTRY_TYPE_WIDTH;
    out_group.fields.is_leaf0 = group_bv.bits(msb, lsb).get_value();
    lsb += L2_ENTRY_TYPE_WIDTH;
    msb += L2_ENTRY_PAYLOAD_WIDTH;
    out_group.fields.payload0 = group_bv.bits(msb, lsb).get_value();
}

la_status
lpm_core_hw_writer_gb::write_l2_sram_buckets(const lpm_bucket* bucket, const lpm_bucket* neighbor_bucket) const
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }
    dassert_crit(bucket);

    lpm_bucket_index_t hw_index = bucket->get_hw_index();

    lpm_bucket_index_t hw_row;

    hw_row = hw_index / 2;
    l2_sram_line hw_l2_line = generate_l2_sram_line(bucket, neighbor_bucket);

    dassert_crit(hw_l2_line.entry_data.get_width() > 0);

    log_l2_double_bucket(hw_row, bucket, neighbor_bucket, hw_l2_line);

    la_status status = write_l2_sram_line(hw_row, hw_l2_line);
    return status;
}

la_status
lpm_core_hw_writer_gb::write_l2_hbm_bucket(const lpm_bucket* bucket) const
{
    if (!m_ll_device) {
        return LA_STATUS_SUCCESS;
    }

    dassert_crit(bucket);

    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    std::array<bit_vector, 2> hw_bucket = generate_l2_hbm_bucket(bucket);
    la_status status = write_l2_hbm_line(hw_index, hw_bucket);
    return status;
}

la_status
lpm_core_hw_writer_gb::write_l2_hbm_line(size_t hw_index, const std::array<bit_vector, 2>& hbm_line_data) const
{
    for (size_t repl_idx = 0; repl_idx < HBM_NUM_REPLICATIONS; repl_idx++) {
        hbm_physical_location hbm_location;
        la_status status = calculate_bucket_location_in_hbm(hw_index, repl_idx, hbm_location);
        dassert_crit(status == LA_STATUS_SUCCESS);

        status = write_hbm_data(hbm_location, hbm_line_data[0]);
        return_on_error(status);

        if (m_use_fat_hbm_buckets) {
            hbm_location.column++;
            status = write_hbm_data(hbm_location, hbm_line_data[1]);
            return_on_error(status);
        }
    }

    log_xdebug(TABLES,
               "Wrote L2 HBM Bucket (idx: %zu): use_fat_hbm_buckets? %s    data[0] = 0x%s   data[1]=0x%s",
               hw_index,
               m_use_fat_hbm_buckets ? "Yes" : "No",
               hbm_line_data[0].to_string().c_str(),
               hbm_line_data[1].to_string().c_str());

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_gb::calculate_bucket_location_in_hbm(size_t hw_index,
                                                        size_t repl_idx,
                                                        hbm_physical_location& out_hbm_location) const
{
    constexpr bool m_use_fat_hbm_buckets = false;

    // Destination HW index is total 19b:
    // [3:0] - core index
    // [18:4] - bucket index between 4k and <end of HBM>
    // Note: core index is not a part of the L1 payload.
    size_t dest_hw_index = (hw_index << HBM_CORE_ID_WIDTH) + m_core_id;

    log_debug(TABLES, "lpm::write_l2_hbm_bucket(l2_idx: %zu, hbm_idx: %zu)", hw_index, dest_hw_index);

    if (m_use_fat_hbm_buckets) {
        out_hbm_location.row = bit_utils::get_bits(dest_hw_index, 15, 8) + (256 * repl_idx);
        out_hbm_location.column = bit_utils::get_bits(dest_hw_index, 18, 16) << 1;
    } else {
        out_hbm_location.row = bit_utils::get_bits(dest_hw_index, 14, 8) + (128 * repl_idx);
        out_hbm_location.column = bit_utils::get_bits(dest_hw_index, 18, 15);
    }

    size_t bank_channel_base = bit_utils::get_bits(dest_hw_index, 7, 0);
    size_t bank_channel = bank_channel_base + (4 * repl_idx);

    out_hbm_location.channel = bit_utils::get_bits(bank_channel, 3, 0);
    out_hbm_location.bank = (bit_utils::get_bits(bank_channel, 5, 4) << 2) | bit_utils::get_bits(bank_channel, 7, 6);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_hw_writer_gb::write_hbm_data(const hbm_physical_location& hbm_location, const bit_vector& data) const
{
    size_t cif_num = hbm_location.channel / 2;
    size_t addr = (hbm_location.row << 4) | hbm_location.column;

    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();

    la_status status = LA_STATUS_SUCCESS;

    if (hbm_location.channel % 2 == 0) {
        status = m_ll_device->write_memory(*(*tree->hbm->chnl[cif_num]->hbm_cpu_mem_access_ch0)[hbm_location.bank], addr, data);
    } else {
        status = m_ll_device->write_memory(*(*tree->hbm->chnl[cif_num]->hbm_cpu_mem_access_ch1)[hbm_location.bank], addr, data);
    }

    return status;
}

la_status
lpm_core_hw_writer_gb::write_l2_sram_line(lpm_bucket_index_t row, const l2_sram_line& hw_l2_line) const
{
    // We must make sure the HW finished to write the previous write.
    constexpr size_t NUM_WAIT_FOR_VALUE_ITERATIONS = 10;
    for (size_t iteration = 0; iteration < NUM_WAIT_FOR_VALUE_ITERATIONS; iteration++) {
        la_status status = m_ll_device->wait_for_value(
            *m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_valid_reg, true /* equal */, 0 /* val */, 1 /* mask */);
        if (status == LA_STATUS_SUCCESS) {
            break;
        }

        log_err(TABLES, "wait_for_value failed. iteration %lu", iteration);
    }

    // Memory address of bucket to write + full row flag
    bit_vector address_reg(row /* address */);
    la_status status
        = m_ll_device->write_register(*m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_address_reg, address_reg /* line index */);
    return_on_error(status);

    // Non entry data of bucket to write
    const bit_vector non_entry_data(hw_l2_line.non_entry_data.flat, L2_NON_ENTRY_DATA_WIDTH);

    const size_t entry_data_width = hw_l2_line.entry_data.get_width();

    // debug
    if (logger::instance().is_logging(m_ll_device->get_device_id(), la_logger_component_e::TABLES, la_logger_level_e::DEBUG)) {
        size_t entries_for_1 = non_entry_data.bits(L2_COUNTER_WIDTH, 1).get_value();
        size_t entries_for_0 = L2_NUM_OF_SHARED_ENTRIES - entries_for_1;
        bit_vector default_bucket_1 = non_entry_data.bits_from_msb(0, L2_DEFAULT_WIDTH);
        size_t is_leaf_1 = non_entry_data.bits_from_msb(L2_DEFAULT_WIDTH, L2_ENTRY_TYPE_WIDTH).get_value();
        bit_vector default_bucket_0 = non_entry_data.bits_from_msb(L2_DEFAULT_WIDTH + L2_ENTRY_TYPE_WIDTH, L2_DEFAULT_WIDTH);
        size_t is_leaf_0
            = non_entry_data.bits_from_msb(2 * L2_DEFAULT_WIDTH + L2_ENTRY_TYPE_WIDTH, L2_ENTRY_TYPE_WIDTH).get_value();
        log_debug(
            TABLES,
            "lpm::write_l2_line(non_entry_data number of shared_entries for bucket [0]: %zd, [1]: %zd, default value [0]: 0x%s, "
            "[1]: 0x%s, is_leaf [0]: %zd, [1]: %zd)",
            entries_for_0,
            entries_for_1,
            default_bucket_0.to_string().c_str(),
            default_bucket_1.to_string().c_str(),
            is_leaf_0,
            is_leaf_1);

        for (size_t entry = 0; entry < entry_data_width; entry += L2_ENTRY_WIDTH) {
            bit_vector entry_bv = hw_l2_line.entry_data.bits(entry + L2_ENTRY_WIDTH - 1, entry);
            const size_t prefix = entry_bv.bits(L2_ENTRY_TYPE_START - 1, L2_ENTRY_PREFIX_START).get_value();
            if (prefix) {
                log_debug(
                    TABLES,
                    "lpm::write_l2_line(idx: %zd, prefix: 0x%s, payload: 0x%s, type: %d)",
                    (entry - L2_BUCKET_ENTRY_DATA_START) / L2_ENTRY_WIDTH,
                    entry_bv.bits(L2_ENTRY_PREFIX_START + ENTRY_ENC_PREFIX_WIDTH - 1, L2_ENTRY_PREFIX_START).to_string().c_str(),
                    entry_bv.bits(L2_ENTRY_PAYLOAD_START + L2_ENTRY_PAYLOAD_WIDTH - 1, L2_ENTRY_PAYLOAD_START).to_string().c_str(),
                    entry_bv.bit(L2_ENTRY_TYPE_START));
            }
        }
    }

    status = m_ll_device->write_register(*m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_non_entry_data_reg, non_entry_data);
    return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());

    // Other entries of bucket to write.
    size_t reg_width_in_bits = m_cdb_core_gb.lpm_rd_mod_wr_group_data_reg->get_desc()->width_in_bits;
    size_t hw_bucket_lsb = L2_BUCKET_ENTRY_DATA_START;
    size_t reg_idx = 0;
    while (hw_bucket_lsb < entry_data_width) {
        size_t data_to_write_width = std::min(entry_data_width - hw_bucket_lsb, reg_width_in_bits);
        status = m_ll_device->write_register(*(*m_cdb_core_gb.lpm_rd_mod_wr_group_data_reg)[reg_idx],
                                             hw_l2_line.entry_data.bits(hw_bucket_lsb + data_to_write_width - 1, hw_bucket_lsb));
        return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());
        reg_idx += 1;
        hw_bucket_lsb += data_to_write_width;
    }

    // Set read modify write valid bit
    bit_vector valid_bit(1);
    status = m_ll_device->write_register(*m_cdb_core_pa_gb.cdb_core.lpm_rd_mod_wr_valid_reg, valid_bit /* set valid bit */);
    return_on_error(status, TABLES, ERROR, "%s:%d: write_register() failed %d", __func__, __LINE__, status.value());

    log_xdebug(TABLES, "Wrote L2 SRAM double Bucket (row: %d): data = 0x%s", row, hw_l2_line.entry_data.to_string().c_str());

    return status;
}

std::vector<lpm_entry>
lpm_core_hw_writer_gb::read_l2_bucket(size_t hw_index, size_t& out_default_payload) const
{
    log_err(TABLES, "Function not implemented yet");
    dassert_crit(false);
    return std::vector<lpm_entry>();
}

bool
lpm_core_hw_writer_gb::is_mark_as_leaf(const lpm_node* node) const
{
    if (!m_key_to_force_is_leaf.empty()) {
        const lpm_key_t& node_key = node->get_key();
        auto it = m_key_to_force_is_leaf.find(node_key);
        if (it != m_key_to_force_is_leaf.end()) {
            return it->second;
        }
    }

    return node->is_leaf();
}

lpm_core_hw_writer_gb::l2_sram_line
lpm_core_hw_writer_gb::generate_l2_sram_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const
{
    l2_sram_line hw_l2_line;
    hw_l2_line.non_entry_data.flat = 0;

    // TODO: For now we must write the whole line, because of HW bug
    hw_l2_line.entry_data = bit_vector(0, m_l2_all_groups_width);
    uint64_t* const line_entry_data = reinterpret_cast<uint64_t*>(hw_l2_line.entry_data.byte_array());
    const lpm_bucket* buckets[2] = {bucket1, bucket0};
    if (bucket0->get_hw_index() % 2 == 1) {
        buckets[0] = bucket0;
        buckets[1] = bucket1;
    }
    size_t shared_group_idx = 0;
    for (const lpm_bucket* current_bucket : buckets) {
        if (current_bucket == nullptr) {
            continue;
        }

        size_t group_idx = 0;
        const lpm_nodes_bucket* nodes_bucket = reinterpret_cast<const lpm_nodes_bucket*>(current_bucket);
        lpm_payload_t default_payload = nodes_bucket->get_default_entry().payload;
        bool default_is_leaf = false;
        const size_t root_width = nodes_bucket->get_root_width();
        const size_t bucket_idx = nodes_bucket->get_hw_index() % 2;
        const lpm_node* single_pending_node = nullptr;
        for (const lpm_node* node : nodes_bucket->get_nodes()) {
            const bool is_leaf = is_mark_as_leaf(node);
            const size_t prefix_width = node->get_width() - root_width;
            if (prefix_width == 0) {
                const lpm_bucketing_data& node_data = node->data();
                default_payload = node_data.payload;
                default_is_leaf = is_leaf;
            } else if (prefix_width > ENTRY_PREFIX_WIDTH) {
                // Double entry.
                l2_group_data group_info;
                generate_group_from_double_l2_entry(node, root_width, is_leaf, group_info);
                set_l2_sram_line_group(line_entry_data, group_info, bucket_idx, group_idx, shared_group_idx);
            } else {
                // Single entry.
                if (single_pending_node == nullptr) {
                    single_pending_node = node;
                } else {
                    l2_group_data group_info;
                    generate_group_from_single_l2_entries(single_pending_node, node, root_width, group_info);
                    set_l2_sram_line_group(line_entry_data, group_info, bucket_idx, group_idx, shared_group_idx);
                    single_pending_node = nullptr;
                }
            }
        }

        // Last single entry.
        if (single_pending_node) {
            l2_group_data group_info;
            generate_group_from_single_l2_entries(single_pending_node, nullptr /* node1 */, root_width, group_info);
            set_l2_sram_line_group(line_entry_data, group_info, bucket_idx, group_idx, shared_group_idx);
        }

        // Set default entry.
        set_l2_sram_default(hw_l2_line, bucket_idx, default_payload, default_is_leaf);

        if (bucket_idx == 1) {
            hw_l2_line.non_entry_data.data_struct.counter = shared_group_idx;
        }
    }

    return hw_l2_line;
}

void
lpm_core_hw_writer_gb::set_l2_sram_default(l2_sram_line& hw_l2_line,
                                           size_t bucket_idx,
                                           lpm_payload_t default_payload,
                                           bool is_leaf) const
{
    if (bucket_idx == 0) {
        hw_l2_line.non_entry_data.data_struct.bucket0_default_is_leaf = is_leaf;
        hw_l2_line.non_entry_data.data_struct.bucket0_default = default_payload;
    } else {
        hw_l2_line.non_entry_data.data_struct.bucket1_default_is_leaf = is_leaf;
        hw_l2_line.non_entry_data.data_struct.bucket1_default = default_payload;
    }
}

void
lpm_core_hw_writer_gb::generate_group_from_double_l2_entry(const lpm_node* node,
                                                           size_t root_width,
                                                           bool is_leaf,
                                                           l2_group_data& out_group) const
{
    const lpm_key_t& node_key = node->get_key();
    const lpm_key_t& prefix0 = encode_prefix(node_key, root_width + ENTRY_PREFIX_WIDTH, ENTRY_ENC_PREFIX_WIDTH);
    const lpm_key_t& prefix1 = encode_prefix(node_key, root_width, ENTRY_ENC_PREFIX_WIDTH);
    out_group.fields.prefix0 = prefix0.get_value();
    out_group.fields.prefix1 = prefix1.get_value();
    const lpm_bucketing_data& node_data = node->data();
    out_group.fields.payload0 = node_data.payload;
    // When group stores double-entry, payload1 should be 0.
    out_group.fields.payload1 = 0;
    out_group.fields.is_leaf0 = is_leaf;
    out_group.fields.is_leaf1 = 0;
    out_group.fields.is_double = true;
}

void
lpm_core_hw_writer_gb::generate_group_from_single_l2_entries(const lpm_node* node0,
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
    out_group.fields.prefix0 = encode_prefix(node0_key, root_width, ENTRY_ENC_PREFIX_WIDTH).get_value();
    const lpm_bucketing_data& node0_data = node0->data();
    out_group.fields.payload0 = node0_data.payload;
    out_group.fields.is_leaf0 = is_mark_as_leaf(node0);
    if (node1) {
        const lpm_key_t& node1_key = node1->get_key();
        out_group.fields.prefix1 = encode_prefix(node1_key, root_width, ENTRY_ENC_PREFIX_WIDTH).get_value();
        const lpm_bucketing_data& node1_data = node1->data();
        out_group.fields.payload1 = node1_data.payload;
        out_group.fields.is_leaf1 = is_mark_as_leaf(node1);
    }
}

void
lpm_core_hw_writer_gb::set_l2_sram_line_group(uint64_t* const line_entry_data,
                                              const l2_group_data& group,
                                              const size_t bucket_idx,
                                              size_t& group_idx,
                                              size_t& shared_group_idx) const
{
    const bool group_is_shared = group_idx >= m_l2_bucket_num_interleaved_groups;
    if (group_is_shared) {
        size_t lsb = shared_group_idx * L2_GROUP_WIDTH;
        size_t msb = lsb + L2_GROUP_WIDTH - 1;
        dassert_slow(verify_no_overrides(line_entry_data, msb, lsb));
        bit_utils::set_bits(line_entry_data, msb, lsb, reinterpret_cast<const uint64_t*>(&group));
        shared_group_idx++;
    } else {
        set_l2_sram_line_interleaved_group_bits(line_entry_data, bucket_idx, group, group_idx);
    }

    group_idx++;
}

void
lpm_core_hw_writer_gb::set_l2_sram_line_interleaved_group_bits(uint64_t* line_entry_data,
                                                               size_t bucket_idx,
                                                               const l2_group_data& group,
                                                               size_t group_idx) const
{
    size_t lsb;
    size_t bits_between_entries = L2_IS_DOUBLE_GROUP_WIDTH + L2_ENTRY_WIDTH;
    if (bucket_idx == 0) {
        bits_between_entries += L2_ENTRY_WIDTH + 1;
        lsb = L2_BUCKET_SHARED_GROUPS_WIDTH + L2_INTERLEAVED_GROUP_WIDTH * group_idx;
    } else {
        bits_between_entries += L2_ENTRY_WIDTH;
        lsb = L2_BUCKET_SHARED_GROUPS_WIDTH + L2_ENTRY_WIDTH + 1 + L2_INTERLEAVED_GROUP_WIDTH * group_idx;
    }

    // Writing is_double bit and entry0.
    size_t msb = lsb + L2_IS_DOUBLE_GROUP_WIDTH + L2_ENTRY_WIDTH - 1;
    dassert_slow(verify_no_overrides(line_entry_data, msb, lsb));
    bit_utils::set_bits(line_entry_data, msb, lsb, reinterpret_cast<const uint64_t*>(&group));

    // Writing entry1.
    uint64_t entry1_bits;
    size_t lsb_extract = L2_IS_DOUBLE_GROUP_WIDTH + L2_ENTRY_WIDTH;
    size_t msb_extract = lsb_extract + L2_ENTRY_WIDTH - 1;

    // Extract entry1 bits from bit fields.
    bit_utils::get_bits(reinterpret_cast<const uint64_t*>(&group), msb_extract, lsb_extract, &entry1_bits);
    lsb += bits_between_entries;
    msb = lsb + L2_ENTRY_WIDTH - 1;
    dassert_slow(verify_no_overrides(line_entry_data, msb, lsb));
    bit_utils::set_bits(line_entry_data, msb, lsb, &entry1_bits);
}

std::array<bit_vector, 2>
lpm_core_hw_writer_gb::generate_l2_hbm_bucket(const lpm_bucket* bucket) const
{
    std::array<bit_vector, 2> bucket_bits;

    if (bucket == nullptr) {
        return bucket_bits;
    }

    const lpm_nodes_bucket* nodes_bucket = reinterpret_cast<const lpm_nodes_bucket*>(bucket);
    const auto nodes = nodes_bucket->get_nodes();
    size_t root_width = bucket->get_root().get_width();

    dassert_crit(nodes.size() <= (m_use_fat_hbm_buckets ? 2 : 1) * 2 * HBM_NUM_GROUPS_PER_THIN_BUCKET);

    size_t num_thin_buckets = (nodes.size() <= (2 * HBM_NUM_GROUPS_PER_THIN_BUCKET)) ? 1 : 2;
    bucket_bits[0] = bit_vector(0 /* value */, HBM_THIN_BUCKET_WIDTH);
    if (num_thin_buckets == 2) {
        bucket_bits[1] = bit_vector(0 /* value */, HBM_THIN_BUCKET_WIDTH);
    }

    bool has_zero_width_node = false;
    for (size_t i = 0; i < nodes.size(); i++) {
        if (nodes[i]->get_width() == root_width) {
            has_zero_width_node = true;
        }

        dassert_crit(nodes[i] != nullptr);
        const lpm_key_t& current_key = nodes[i]->get_key();
        const lpm_bucketing_data& node_data = nodes[i]->data();
        lpm_payload_t current_payload = node_data.payload;
        bool is_leaf = is_mark_as_leaf(nodes[i]);
        set_node_in_hbm_bucket(current_key, current_payload, is_leaf, root_width, i, bucket_bits);
    }

    // There is no special "default" entry in HBM bucket. If we don't have a real entry of zero width, we will write the bucket's
    // default as a zero width entry.
    if (!has_zero_width_node) {
        const lpm_key_payload& default_entry = bucket->get_default_entry();
        const lpm_key_t& root_key = bucket->get_root();

        set_node_in_hbm_bucket(root_key, default_entry.payload, false /* is_leaf */, root_width, nodes.size(), bucket_bits);
    }

    return bucket_bits;
}

void
lpm_core_hw_writer_gb::set_node_in_hbm_bucket(const lpm_key_t& key,
                                              lpm_payload_t payload,
                                              bool is_leaf,
                                              size_t root_width,
                                              size_t node_idx,
                                              std::array<bit_vector, 2>& bucket_bits) const
{
    bool is_double = false; // SDK doesn't support double entries in HBM yet.

    size_t group = node_idx / 2;
    size_t entry_in_group = node_idx % 2;
    size_t thin_bucket_idx = group / HBM_NUM_GROUPS_PER_THIN_BUCKET;

    dassert_crit(thin_bucket_idx <= 1);
    dassert_crit(group < (m_use_fat_hbm_buckets ? 2 : 1) * HBM_NUM_GROUPS_PER_THIN_BUCKET);

    size_t group_start_offset = group * HBM_GROUP_WIDTH;

    size_t offset_width_type = 0;
    size_t offset_is_leaf = (entry_in_group == 0) ? HBM_GROUP_IS_LEAF0_START : HBM_GROUP_IS_LEAF1_START;
    size_t offset_prefix = (entry_in_group == 0) ? HBM_GROUP_PREFIX0_START : HBM_GROUP_PREFIX1_START;
    size_t offset_payload = (entry_in_group == 0) ? HBM_GROUP_PAYLOAD0_START : HBM_GROUP_PAYLOAD1_START;
    size_t offset_is_hbm = offset_payload + IS_HBM_OFFSET;

    lpm_key_t encoded_prefix = encode_prefix(key, root_width, ENTRY_ENC_PREFIX_WIDTH);

    bucket_bits[thin_bucket_idx].set_bits_from_lsb(group_start_offset + offset_width_type, 1 /* width */, is_double);
    bucket_bits[thin_bucket_idx].set_bits_from_lsb(group_start_offset + offset_is_leaf, 1 /* width */, is_leaf);
    bucket_bits[thin_bucket_idx].set_bits_from_lsb(
        group_start_offset + offset_prefix, ENTRY_ENC_PREFIX_WIDTH, encoded_prefix.get_value());
    bucket_bits[thin_bucket_idx].set_bits_from_lsb(group_start_offset + offset_payload, L2_ENTRY_PAYLOAD_WIDTH, payload);
    bucket_bits[thin_bucket_idx].set_bits_from_lsb(group_start_offset + offset_is_hbm, 1 /* width */, true /* is_hbm */);

    return;
}

lpm_core_hw_writer_gb::l1_entry_data
lpm_core_hw_writer_gb::generate_l1_entry_data(const lpm_nodes_bucket* bucket, size_t l1_root_width) const
{
    l1_entry_data l1_entry;
    const lpm_key_t& bucket_root = bucket->get_root();
    const lpm_key_t& encoded_key = encode_prefix(bucket_root, l1_root_width, ENTRY_ENC_PREFIX_WIDTH);
    l1_entry.fields.prefix = encoded_key.get_value();
    l1_entry.fields.payload = bucket->get_hw_index();
    l1_entry.fields.double_line_in_hbm = false;
    return l1_entry;
}

void
lpm_core_hw_writer_gb::set_l1_sram_line_entry(uint64_t* line_entry_data,
                                              const l1_entry_data& l1_entry,
                                              size_t entry_idx,
                                              size_t& shared_entry_idx,
                                              size_t bucket_idx) const
{
    // Bucket entries are arranged in a way where first L1_NUM_OF_FIXED_ENTRIES number of entries are placed at fixed part.
    // After that they are placed in shared part.
    // MSBs are the fixed and the LSB are the shared.
    // Within the shared entries bucket1 entries are the LSBs.
    // Below is the layout of a line with the entries indexes:
    //
    // | b1-e1-F| b1-e0-F| b0-e1-F| b0-e0-F|...|b0-e_last-S|...|b0-e3-S|b0-e2-S|b1-e_last-S|...|b1-e3-S|b1-e2-S|
    bool fixed_entry = entry_idx < L1_NUM_OF_FIXED_ENTRIES;
    size_t entry_lsb;
    if (fixed_entry) {
        if (bucket_idx == 0) {
            entry_lsb = L1_BUCKET0_FIXED_ENTRIES_START + entry_idx * L1_ENTRY_WIDTH;
        } else {
            entry_lsb = L1_BUCKET1_FIXED_ENTRIES_START + entry_idx * L1_ENTRY_WIDTH;
        }
    } else {
        // Shared entries.
        entry_lsb = L1_NON_ENTRY_DATA_WIDTH + shared_entry_idx * L1_ENTRY_WIDTH;
        shared_entry_idx++;
    }

    const size_t entry_msb = entry_lsb + L1_ENTRY_WIDTH - 1;
    dassert_slow(verify_no_overrides(line_entry_data, entry_msb, entry_lsb));
    bit_utils::set_bits(line_entry_data, entry_msb, entry_lsb, &l1_entry.flat);
}

void
lpm_core_hw_writer_gb::set_l1_defaults(l1_hw_line& l1_sram_line,
                                       const lpm_bucket* bucket0,
                                       const lpm_bucket* bucket1,
                                       size_t default_counter) const
{
    if (bucket0) {
        dassert_crit(bucket0->get_hw_index() % 2 == 0);
        const lpm_key_payload& bucket0_default_entry = bucket0->get_default_entry();
        const lpm_key_t& bucket0_default_key = bucket0_default_entry.key;
        l1_sram_line.bucket0_default = bucket0_default_entry.payload;
        // The following field indicates where to start the lookup in L2.
        // We count it from the beginning of the lookup key without the V4/V6 bit.
        l1_sram_line.bucket0_bits_to_trim = bucket0_default_key.get_width() - 1;
    }

    if (bucket1) {
        dassert_crit(bucket1->get_hw_index() % 2 == 1);
        const lpm_key_payload& bucket1_default_entry = bucket1->get_default_entry();
        const lpm_key_t& bucket1_default_key = bucket1_default_entry.key;
        l1_sram_line.bucket1_default = bucket1_default_entry.payload;
        // The following field indicates where to start the lookup in L2.
        // We count it from the beginning of the lookup key without the V4/V6 bit.
        l1_sram_line.bucket1_bits_to_trim = bucket1_default_key.get_width() - 1;
    }

    // In case of hit in HBM is it two lines hit or one.
    l1_sram_line.bucket0_hbm_lines = false;
    l1_sram_line.bucket1_hbm_lines = false;
    // Set default counter.
    l1_sram_line.counter = default_counter;
}

lpm_core_hw_writer_gb::l1_hw_line
lpm_core_hw_writer_gb::generate_l1_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const
{
    l1_hw_line hw_bucket_line{};
    uint64_t* const line_entry_data = (uint64_t*)&hw_bucket_line;
    size_t shared_entry_idx = 0;
    size_t default_counter = 0;

    // buckets should contain {odd_index_bucket, even_index_bucket}
    const lpm_bucket* buckets[2] = {bucket1, bucket0};
    if (bucket0->get_hw_index() % 2 == 1) {
        buckets[0] = bucket0;
        buckets[1] = bucket1;
    }

    for (const lpm_bucket* current_bucket : buckets) {
        if (current_bucket == nullptr) {
            continue;
        }

        const size_t l1_root_width = std::min((size_t)TCAM_PAYLOAD_FIELD_LENGTH_MAX_VALUE + 1, current_bucket->get_root_width());
        const size_t bucket_idx = current_bucket->get_hw_index() % 2;
        const lpm_buckets_bucket* buckets_bucket = reinterpret_cast<const lpm_buckets_bucket*>(current_bucket);
        size_t entry_idx = 0;
        for (const std::shared_ptr<silicon_one::lpm_nodes_bucket>& bucket_sptr : buckets_bucket->get_members()) {
            const lpm_nodes_bucket* bucket = bucket_sptr.get();
            l1_entry_data l1_entry = generate_l1_entry_data(bucket, l1_root_width);
            set_l1_sram_line_entry(line_entry_data, l1_entry, entry_idx, shared_entry_idx, bucket_idx);
            entry_idx++;
        }

        if (bucket_idx == 1) {
            default_counter = shared_entry_idx;
        }
    }

    dassert_crit(shared_entry_idx <= L1_NUM_OF_SHARED_ENTRIES);
    set_l1_defaults(hw_bucket_line, buckets[1], buckets[0], default_counter);
    return hw_bucket_line;
}

static constexpr size_t STATUS_BITS_VECTOR_WIDTH = 2 * 1024;

void
lpm_core_hw_writer_gb::bit_vector_to_bucket_indexes(bit_vector& bv,
                                                    size_t start_index,
                                                    vector_alloc<size_t>& out_bucket_indexes) const
{
    uint64_t* underlying_array = reinterpret_cast<uint64_t*>(bv.byte_array());

    for (size_t i = 0; i < STATUS_BITS_VECTOR_WIDTH / 64; i++) {
        uint64_t qword = underlying_array[i];
        uint64_t offset = start_index + 64 * i;

        while (qword != 0) {
            int lsb = bit_utils::get_lsb(qword);
            out_bucket_indexes.push_back(offset + lsb);
            qword ^= (1ULL << lsb);
        }
    }
}

la_status
lpm_core_hw_writer_gb::read_index_of_last_accessed_l2_sram_buckets(vector_alloc<size_t>& out_bucket_indexes)
{
    // select access bits (also clears bits for next read)
    la_status status = m_ll_device->write_register(*m_cdb_core_gb.accessed_buckets_wr, m_core_id % 2);
    return_on_error(status);

    bit_vector status_bits;
    for (size_t i = 0; i < 2; i++) {
        status = m_ll_device->read_register(*(*m_cdb_core_gb.accessed_buckets_status_reg)[i], status_bits);
        return_on_error(status);
        dassert_crit(status_bits.get_width() == STATUS_BITS_VECTOR_WIDTH);

        bit_vector_to_bucket_indexes(status_bits, i * STATUS_BITS_VECTOR_WIDTH, out_bucket_indexes);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
