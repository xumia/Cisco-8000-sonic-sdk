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

#include "lpm_config.h"

#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"

#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"

namespace silicon_one
{

//**************************************
// Aux functions
//**************************************
gibraltar::cdb_core_lpm_tcam_bypass_register
get_lpm_tcam_bypass_register_val(const std::shared_ptr<gibraltar_tree_cdb_core>& core)
{
    gibraltar::cdb_core_lpm_tcam_bypass_register ret = {.u8 = {0}};

    ret.fields.lpm_tcam_bypass_index = 0x1fff;
    ret.fields.lpm_tcam_bypass_mask_n_p0 = (size_t)-1;
    ret.fields.lpm_tcam_bypass_mask_n_p1 = (size_t)-1;
    ret.fields.lpm_tcam_bypass_mask_n_p2 = 0x3fff;

    return ret;
}

//**************************************
// lpm_config
//**************************************
la_status
lpm_config::configure_hw(const ll_device_sptr& ldevice, bool hbm_enabled, size_t tcam_num_banksets) const
{
    gibraltar_tree_scptr tree = ldevice->get_gibraltar_tree_scptr();

    // Update cores
    for (auto& core : tree->cdb->core) {
        log_debug(RA, "lpm_config::configure_hw configure core");
        la_status status = write_cdb_core_config(ldevice, core, tcam_num_banksets);
        return_on_error(status);
    }
    if (hbm_enabled) {
        return configure_hbm(ldevice);
    }

    return LA_STATUS_SUCCESS;
}

template <class CDB_CORE>
la_status
lpm_config::configure_lpm_tcams(const ll_device_sptr& ldevice, const CDB_CORE& core, size_t tcam_num_banksets) const
{
    const lld_register_array_container& lpm0_tcam_for_ctm_reg = *core->lpm0_tcam_for_ctm;
    const lld_register_array_container& lpm1_tcam_for_ctm_reg = *core->lpm1_tcam_for_ctm;

    size_t reg_array_size = lpm0_tcam_for_ctm_reg.size();

    for (size_t reg_idx = 0; reg_idx < reg_array_size; ++reg_idx) {
        // For 1 bankset
        // Setting 0
        // for
        //  tcams 0,1
        // at both sub rings
        //
        //  For 2 banksets
        // Setting 0
        // for
        //  tcams 0,1,2,3
        // at both sub rings
        gibraltar::cdb_core_lpm0_tcam_for_ctm_register reg_val0 = {.u8 = {}};
        gibraltar::cdb_core_lpm1_tcam_for_ctm_register reg_val1 = {.u8 = {}};
        reg_val0.fields.lpm0_tcam_in_use_of_ctm = 1;
        reg_val1.fields.lpm1_tcam_in_use_of_ctm = 1;
        size_t num_tcams_used_per_core = tcam_num_banksets * 2;
        if (reg_idx < num_tcams_used_per_core) {
            reg_val0.fields.lpm0_tcam_in_use_of_ctm = 0;
            reg_val1.fields.lpm1_tcam_in_use_of_ctm = 0;
        }

        la_status status = ldevice->write_register(lpm0_tcam_for_ctm_reg[reg_idx], reg_val0);
        return_on_error(status);
        status = ldevice->write_register(lpm1_tcam_for_ctm_reg[reg_idx], reg_val1);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class CDB_CORE>
la_status
lpm_config::write_cdb_core_config(const ll_device_sptr& ldevice, const CDB_CORE& core, size_t tcam_num_banksets) const
{
    la_status status = configure_lpm_tcams(ldevice, core, tcam_num_banksets);
    return_on_error(status);

    // To support keys of 160 bit, the following registers should be configured
    // per tcam
    // enable:  tree->cdb.core->lpm_ipv6_over_80b_supported_tcam_reg;
    // number:  tree->cdb.core->lpm_num_of_ipv6_over_80b_tcam_reg;
    // Only first TCAM of each LPM will be configured with 160b keys.
    // sub ring 0
    for (size_t reg_idx = 0; reg_idx < core->lpm0_ipv6_over_80b_supported_tcam_reg->size(); ++reg_idx) {
        gibraltar::cdb_core_lpm0_ipv6_over_80b_supported_tcam_reg_register val = {.u8 = {0}};
        bool enable_160bit = (reg_idx == 0);
        val.fields.lpm0_ipv6_over_80b_supported_in_tcam = enable_160bit;
        status = ldevice->write_register((*core->lpm0_ipv6_over_80b_supported_tcam_reg)[reg_idx], val);
        return_on_error(status);
    }

    for (size_t reg_idx = 0; reg_idx < core->lpm0_num_of_ipv6_over_80b_tcam_reg->size(); ++reg_idx) {
        gibraltar::cdb_core_lpm0_num_of_ipv6_over_80b_tcam_reg_register val = {.u8 = {0}};
        size_t max_160bit_rows = (reg_idx == 0) ? 240 : 0;                // Pacific mode. In GB we can cover more.
        val.fields.lpm0_num_of_ipv6_over_80b_tcam = max_160bit_rows / 32; // Register counts in steps of 32.
        status = ldevice->write_register((*core->lpm0_num_of_ipv6_over_80b_tcam_reg)[reg_idx], val);
        return_on_error(status);
    }
    // sub ring 1
    for (size_t reg_idx = 0; reg_idx < core->lpm1_ipv6_over_80b_supported_tcam_reg->size(); ++reg_idx) {
        gibraltar::cdb_core_lpm1_ipv6_over_80b_supported_tcam_reg_register val = {.u8 = {0}};
        bool enable_160bit = (reg_idx == 0);
        val.fields.lpm1_ipv6_over_80b_supported_in_tcam = enable_160bit;
        status = ldevice->write_register((*core->lpm1_ipv6_over_80b_supported_tcam_reg)[reg_idx], val);
        return_on_error(status);
    }

    for (size_t reg_idx = 0; reg_idx < core->lpm1_num_of_ipv6_over_80b_tcam_reg->size(); ++reg_idx) {
        gibraltar::cdb_core_lpm1_num_of_ipv6_over_80b_tcam_reg_register val = {.u8 = {0}};
        size_t max_160bit_rows = (reg_idx == 0) ? 240 : 0;                // Pacific mode. In GB we can cover more.
        val.fields.lpm1_num_of_ipv6_over_80b_tcam = max_160bit_rows / 32; // Register counts in steps of 32.
        status = ldevice->write_register((*core->lpm1_num_of_ipv6_over_80b_tcam_reg)[reg_idx], val);
        return_on_error(status);
    }

    // Set lpm_cache_mode = 0.
    bit_vector cache_mode(0, 1 /* width */);

    status = ldevice->write_register(core->lpm_cache_mode, cache_mode);
    return_on_error(status);

    // Disable tcam bypass mode.
    // key = 0
    // mask = all ones
    auto bypass_val = get_lpm_tcam_bypass_register_val(core);

    status = ldevice->write_register((*core->lpm_tcam_bypass)[0], bypass_val);
    return_on_error(status);

    status = ldevice->write_register((*core->lpm_tcam_bypass)[1], bypass_val);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_config::configure_hbm(const ll_device_sptr& ldevice) const
{
    // Let's talk about this first:
    // You see, there is this huge DRAM memory called HBM. It is mostly used for packet storage.
    // Anyway, we want to steal some memory of this HBM for the use of LPM.
    // In order to do so, we need to do 3 things:
    // 1. Decide which parts of HBM we want to steal for LPM.
    // 2. Tell "packet storage" to not use these parts because otherwise we'll be overriding each other's data - Not good.
    //    We do this by clearing the relevant bits from FBM, which is the component responsible for telling which DRAM buffers can
    //    be used by packet storage.
    // 3. Tell LPM which parts we reserved for it so it knows what areas to use.
    //
    // Now, there is the concept of replications. Basically we store each LPM bucket multiple (4) times,
    // to allow better lookup balancing etc..
    //
    // Each replica, is going to consume some contiguous piece of HBM.
    // Now, HBM is a 4D creature. Do not be afraid though, for we, the software people, will mostly look at it as a 2D guy.
    // HBMs coordinates are: channel (0..15), bank (0..15), colum (0..15), row (0..whatever)
    // For the sake of our discussion, we'll talk about 2 dimenstions:
    // X-dimension is the "channel_bank" (0..255) dimension.
    // Y-dimension is the "row_column" (0..whatever) dimension.
    //
    // Now, the basic "page" of HBM, has size of 8KB. It is called a "DRAM buffer". We must steal whole DRAM buffers.
    //
    // Let's draw this HBM and place these DRAM buffers on it (Notice the weird numbering. Will address it in a moment)
    //
    //
    //                   channel bank (256 of these)
    //                   -------------->
    //                 |  +------+------+------+------+------+------+------+------+
    //     row col     |  |      |      |      |      |      |      |      |      |
    // a lot of these  |  | DRAM |      |      |      |      |      |      |      |
    //                 |  | Buff |  1   |  2   |  3   | 64K  |64K+1 |64K+2 |64K+3 |
    //                 |  |  0   |      |      |      |      |      |      |      |
    //                 |  |      |      |      |      |      |      |      |      |
    //                 v  |      |      |      |      |      |      |      |      |
    //                    +------+------+------+------+------+------+------+------+
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    | 128K |128K+ |128K+ |128K+ |128K+ |128K+ |128K+ |128K+ |
    //                    |      |  1   |  2   |  3   | 64K  |64K+1 |64K+2 |64K+3 |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    +------+------+------+------+------+------+------+------+
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    | ...  | ...  | ...  | ...  | ...  | ...  | ...  | ...  |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    +------+------+------+------+------+------+------+------+
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    | 896K |896K  | 896K | 896K |896K+ |896K+ |896K+ |896K+ |
    //                    |      |  +1  |  +2  |  +3  | 64K  |64K+1 |64K+2 |64K+3 |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    +------+------+------+------+------+------+------+------+
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    |  4   |  5   |  6   |  7   |64K+4 |64K+5 |64K+6 |64K+7 |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    +------+------+------+------+------+------+------+------+
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    | ...  | ...  | ...  | ...  | ...  | ...  | ...  | ...  |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    |      |      |      |      |      |      |      |      |
    //                    +------+------+------+------+------+------+------+------+
    //
    // Now, we want to have 512K LPM buckets. Why 512K? It must be related to how many buckets LPM L1 pointers can span.
    // We know that a DRAM Buf is 8KB, LPM-HBM Bucket is 128B, So, how many DRAM buffers do we need for 512K buckets?
    //
    // We need not 1 replica of 512K buckets, but 4 replicas. We choose to stack them on after the other.
    //
    // Let's talk about the DRAM buffers numbering.
    // First: Why do we care about these numbers? Because when we ask the HBM memory allocator (FBM) to allocate a buffer for LPM,
    // we need to
    // tell it in terms of DRAM buffer numbers.
    // Second: How are these numbers constructed?
    //   Per row-col pair, we have 8 DRAM buffers, with IDs: x, x+1, ..., x+3, x+64K, ... x+64K+3
    //   The way we move along the vertical dimension is: {row=0, col=0}, {row=0, col=1}, ..., {row=0, col=7}, {row=1, col=0},
    //   {row=1, col=1}, ...
    //  (We actually have 16 columns, but each DRAM buffers has 2 columns in it - so we consider them as if they were 8 "fat"
    //  columns)
    //   and by concatinating the column, row, and index of buffer in the row-column, we get the buffer ID.
    //
    // So the plan is: We decide how many DRAM buffers we need for LPM, from this we derive how many row-columns we need,
    // And from this we derive how many rows we need (we have "8" columns per row).
    // Now we iterate on theses rows, on 8 columns, and on 8 DRAM buffers per row-column, and build the DRAM buffer IDs.
    //
    // Now, that we know which DRAM buffers we are stealing from HBM, we will want to tell HBM that we are taking them.
    // (We will also reserve buffer 0xfffff due to HW bug, it must not be used by anybody)
    // The way we do this is by configuring FBM (HBM's memory allocator). Each DRAM buffer is represented by a bit in FBM.
    // FBM consists of 16 banks, each one with 512 rows x 128 columns. The mapping between DRAM buffer and FBM bit is in the code.
    //
    // After we configured FBM, we need to tell hardware which FBM rows have 1 or more buffers available (not stolen by LPM /
    // reserved).
    // I think hardware uses this as an optimization for a more efficient search.
    // Additionally, we need to configure the total number of available buffers (i.e. not taken by LPM / reserved) for each FBM
    // bank.
    //
    // We need to push all kinds of buttons (flex mode / soft reset) along the way, but that's just boring stuff the HW people told
    // us to do.

    log_debug(RA, "lpm_config::%s", __func__);
    gibraltar_tree_scptr tree = ldevice->get_gibraltar_tree_scptr();

    // Configuring for replications=4
    constexpr size_t NUM_REPLICATIONS = 4;

    constexpr bool use_lpm_fat_buckets = false;

    // Calculate how many DRAM Buffers we need from HBM
    constexpr size_t NUM_BUCKETS = 512 * 1024;
    constexpr size_t DRAM_BUF_SIZE = 8 * 1024;
    constexpr size_t BUCKET_SIZE = (use_lpm_fat_buckets ? 256 : 128);
    constexpr size_t NUM_BUCKETS_IN_DRAM_BUF = DRAM_BUF_SIZE / BUCKET_SIZE;
    constexpr size_t NUM_DRAM_BUFS_PER_REPLICA = NUM_BUCKETS / NUM_BUCKETS_IN_DRAM_BUF;

    constexpr size_t NUM_DRAM_BUFS_PER_ROW_COL = 8;
    constexpr size_t NUM_ROW_COLS_PER_REPLICA = NUM_DRAM_BUFS_PER_REPLICA / NUM_DRAM_BUFS_PER_ROW_COL;
    constexpr size_t NUM_HBM_COLS = 8; // fat columns. (we have 2 cols in each DRAM buffer, so we consider them 1 fat column)
    constexpr size_t NUM_ROWS_PER_REPLICA = NUM_ROW_COLS_PER_REPLICA / NUM_HBM_COLS;

    size_t row_offsets[NUM_REPLICATIONS] = {0};

    fbm_bit_vector_array fbm_shadow;

    // Init FBM shadow so that all buffers are initially free (non-LPM)
    for (size_t fbm_instance = 0; fbm_instance < FBM_NUM_INSTANCES; fbm_instance++) {
        for (size_t row = 0; row < FBM_NUM_ROWS; row++) {
            bit_vector row_data = bit_vector::ones(FBM_ROW_WIDTH_BITS);

            fbm_shadow[fbm_instance][row] = row_data;
        }
    }

    // Map HBM DRAM bufs that we plan to steal for LPM to a bit in FBM, by first computing their DRAM buffer ID
    for (size_t replica = 0; replica < NUM_REPLICATIONS; replica++) {
        row_offsets[replica] = NUM_ROWS_PER_REPLICA * replica;

        for (size_t row = 0; row < NUM_ROWS_PER_REPLICA; row++) {
            for (size_t col = 0; col < NUM_HBM_COLS; col++) {
                for (size_t buf_idx = 0; buf_idx < NUM_DRAM_BUFS_PER_ROW_COL; buf_idx++) {

                    size_t dram_buf_id = dram_buf_location_to_id(row + row_offsets[replica], col, buf_idx);

                    steal_dram_buf_from_fbm(fbm_shadow, dram_buf_id);
                }
            }
        }
    }

    // Remove buffer fffff from FBM (HW bug).
    // (buffer 0xfffff is in memory 15)
    // This should be done regardless of LPM. For now it is handled here because why not give me one more task. I am diffenetly
    // underpaid.
    steal_dram_buf_from_fbm(fbm_shadow, 0xfffff /* dram_buf_id */);

    // Let's configure the HW.
    // Things must be done in this order. Please do not reorder them without consulting first with HW people.

    // 1. Write FBM to Hardware
    la_status status = write_fbm_shadow_to_hw(ldevice, fbm_shadow);
    return_on_error(status);

    // 2. Set flexible mode
    for (size_t fbm_instance = 0; fbm_instance < FBM_NUM_INSTANCES; fbm_instance++) {
        gibraltar::mmu_buff_buffer_alloc_mode_register alloc_mode_reg;

        status = ldevice->read_register(tree->mmu_buff->buffer_alloc_mode, alloc_mode_reg);
        return_on_error(status);

        alloc_mode_reg.fields.flexible_buffer_alloc = bit_utils::ones(FBM_NUM_INSTANCES);

        status = ldevice->write_register(tree->mmu_buff->buffer_alloc_mode, alloc_mode_reg);
        return_on_error(status);
    }

    // 3. Soft reset/set
    status = ldevice->write_register(tree->mmu->soft_reset_configuration, bit_vector(1 /* value */, 1 /* width */));
    return_on_error(status);

    // 4. Configure valid_rows and total_free_buffers
    status = write_fbm_valid_rows_to_hw(ldevice, fbm_shadow);
    return_on_error(status);

    // 5. Configure channel and row offset (Tell LPM which areas in LPM we allocated for it)
    gibraltar::mmu_mmu_parameters_register mmu_params_reg;
    status = ldevice->read_register(tree->mmu->mmu_parameters, mmu_params_reg);
    return_on_error(status);

    mmu_params_reg.fields.use_lpm_double_buckets = use_lpm_fat_buckets;
    status = ldevice->write_register(tree->mmu->mmu_parameters, mmu_params_reg);
    return_on_error(status);

    for (size_t replica = 0; replica < NUM_REPLICATIONS; replica++) {
        gibraltar::mmu_lpm_replication_config_register replication_config_register = {.u8 = {0}};
        replication_config_register.fields.lpm_start_bank_channel_offset = 4 * replica;
        replication_config_register.fields.lpm_start_row_offset = row_offsets[replica];

        status = ldevice->write_register((*tree->mmu->lpm_replication_config)[replica], replication_config_register);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
lpm_config::dram_buf_location_to_id(size_t row, size_t col, size_t buf_idx) const
{
    size_t buf_idx_1_0 = bit_utils::get_bits(buf_idx, 1, 0);
    size_t buf_idx_2 = bit_utils::get_bits(buf_idx, 2, 2);

    dassert_crit(bit_utils::bits_to_represent(col) <= 3);
    dassert_crit(bit_utils::bits_to_represent(row) <= 14);

    size_t dram_buf_id = 0;
    dram_buf_id = bit_utils::set_bits(dram_buf_id, 19, 17, col);
    dram_buf_id = bit_utils::set_bits(dram_buf_id, 16, 16, buf_idx_2);
    dram_buf_id = bit_utils::set_bits(dram_buf_id, 15, 2, row);
    dram_buf_id = bit_utils::set_bits(dram_buf_id, 1, 0, buf_idx_1_0);

    return dram_buf_id;
}

lpm_config::hbm_fbm_bit_location
lpm_config::dram_buf_id_to_fbm_bit(size_t dram_buf_id) const
{
    hbm_fbm_bit_location location;
    // The FBM holds mapping from each DRAM buffer to its memory location.
    // In GB, the HW supports 2 modes: old & new.
    // SDK always works in the new mode, but in case of change the old mapping is coded here too.
    constexpr bool fbm_mapping_old_mode = false;
    if (fbm_mapping_old_mode) {
        location.fbm_instance = bit_utils::get_bits(dram_buf_id, 3, 0);
        location.column = bit_utils::get_bits(dram_buf_id, 10, 4);
        location.row = bit_utils::get_bits(dram_buf_id, 19, 11);
    } else {
        location.fbm_instance = bit_utils::get_bits(dram_buf_id, 2, 0);
        location.fbm_instance = bit_utils::set_bit(location.fbm_instance, 3, bit_utils::get_bit(dram_buf_id, 16));
        location.column = bit_utils::get_bits(dram_buf_id, 9, 3);
        location.row = bit_utils::get_bits(dram_buf_id, 15, 10);
        location.row = bit_utils::set_bits(location.row, 8, 6, bit_utils::get_bits(dram_buf_id, 19, 17));
    }

    return location;
}

void
lpm_config::steal_dram_buf_from_fbm(fbm_bit_vector_array& fbm, size_t dram_buf_id) const
{
    hbm_fbm_bit_location bit_location = dram_buf_id_to_fbm_bit(dram_buf_id);
    fbm[bit_location.fbm_instance][bit_location.row].set_bit(bit_location.column, 0);
}

la_status
lpm_config::write_fbm_shadow_to_hw(const ll_device_sptr& ldevice, const fbm_bit_vector_array& fbm) const
{

    gibraltar_tree_scptr tree = ldevice->get_gibraltar_tree_scptr();
    const lld_memory_array_container& allocator_mem = *tree->mmu_buff->mmu_buffer_allocator;

    dassert_crit(allocator_mem.get_desc()->entries == FBM_NUM_ROWS);
    dassert_crit(allocator_mem.size() == FBM_NUM_INSTANCES);
    dassert_crit(allocator_mem.get_desc()->width_bits == FBM_ROW_WIDTH_BITS);

    for (size_t instance = 0; instance < FBM_NUM_INSTANCES; instance++) {
        for (size_t row = 0; row < FBM_NUM_ROWS; row++) {
            const bit_vector& row_data = fbm[instance][row];

            la_status status = ldevice->write_memory(allocator_mem[instance], row, row_data);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_config::write_fbm_valid_rows_to_hw(const ll_device_sptr& ldevice, const fbm_bit_vector_array& fbm) const
{
    // This function has 2 jobs:
    // 1. For every row in FBM, if this row has at least 1 bit set3 (i.e. at least one DRAM buffer is allocated for packet storage)
    //    set the bit representing this line in the "valid_memory_lines" register.
    // 2. Count all set bits in each FBM bank, and write this count to the "total free buffers" registers.

    for (size_t fbm_instance = 0; fbm_instance < FBM_NUM_INSTANCES; fbm_instance++) {
        bit_vector valid_memory_lines_bv(0, FBM_NUM_ROWS); // valid == not given to LPM
        size_t total_free_buffers = 0;                     // non-LPM buffers

        for (size_t row = 0; row < FBM_NUM_ROWS; row++) {
            const bit_vector& row_data = fbm[fbm_instance][row];
            size_t num_free_buffers = row_data.count_ones();
            if (num_free_buffers > 0) {
                valid_memory_lines_bv.set_bit(row, 1);
            }
            total_free_buffers += num_free_buffers;
        }

        const uint64_t* valid_memory_lines = (const uint64_t*)valid_memory_lines_bv.byte_array();
        gibraltar::mmu_buff_cpu_occupy_buffers_register cpu_occupy_buffers_val = {.u8 = {0}};
        cpu_occupy_buffers_val.fields.set_valid_memory_lines(valid_memory_lines);

        gibraltar_tree_scptr tree = ldevice->get_gibraltar_tree_scptr();
        cpu_occupy_buffers_val.fields.total_free_buffers = total_free_buffers;

        la_status status = ldevice->write_register((*tree->mmu_buff->cpu_occupy_buffers)[fbm_instance], cpu_occupy_buffers_val);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
