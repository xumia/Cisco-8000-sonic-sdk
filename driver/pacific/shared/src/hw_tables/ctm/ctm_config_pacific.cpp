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

#include "ctm_config_pacific.h"

#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "ctm_common_tcam.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

ctm_config_pacific::ctm_config_pacific(const ll_device_sptr& ldevice,
                                       bool is_linecard_mode,
                                       size_t lpm_tcam_num_banksets,
                                       size_t number_of_slices)
    : ctm_config_tcam(ldevice, is_linecard_mode, lpm_tcam_num_banksets, number_of_slices)
{

    if (!m_is_stand_alone) {
        m_lpm_tcams_ring0 = increased_lpm_tcams_ring0;
        m_lpm_tcams_ring1 = increased_lpm_tcams_ring1;

    } else {
        if (lpm_tcam_num_banksets == 1) {
            m_lpm_tcams_ring0 = lpm_tcams_ring0_sa;
            m_lpm_tcams_ring1 = lpm_tcams_ring1_sa;
        } else {
            m_lpm_tcams_ring0 = increased_lpm_tcams_ring0;
            m_lpm_tcams_ring1 = increased_lpm_tcams_ring1;
        }
    }

    map_init();
}

bool
ctm_config_pacific::is_msb_tcam(size_t tcam_idx) const
{
    if (tcam_idx >= get_key_320_tcam_offset()) {
        return true;
    }
    return false;
}

size_t
ctm_config_pacific::get_key_320_tcam_offset() const
{
    // 320b keys are written to two TCAMs with indices X, X+6
    return KEY_320_TCAM_OFFSET;
}

size_t
ctm_config_pacific::get_number_of_subrings() const
{
    return NUM_SUBRINGS;
}

// Configuring:
// 1. Core channels -> Input interface (slice, ifs)
// 2. Output interface (slice, ifs) -> Core channels
la_status
ctm_config_pacific::configure_cdb_top() const
{
    la_status status = LA_STATUS_SUCCESS;
    pacific_tree_scptr tree = m_ll_device->get_pacific_tree_scptr();

    // Configuring:
    // 1. Core channels -> Input interface (slice, ifs)
    const lld_register_array_container& ring_channel_select_regs(*tree->cdb->top->ring_channel_select);
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ++ring_idx) {
        cdb_top_ring_channel_select_register val = {.u8 = {0}};
        val.fields.cdb_core_ring_ch0_select = m_key_channel_to_abs_input_interface[ring_idx][0];
        val.fields.cdb_core_ring_ch1_select = m_key_channel_to_abs_input_interface[ring_idx][1];
        val.fields.cdb_core_ring_ch2_select = m_key_channel_to_abs_input_interface[ring_idx][2];
        val.fields.cdb_core_ring_ch3_select = m_key_channel_to_abs_input_interface[ring_idx][3];
        val.fields.cdb_core_ring_ch4_select = m_key_channel_to_abs_input_interface[ring_idx][4];

        log_debug(RA,
                  "ctm_config setting input interface: core=%zd, term=%zd, fwd0=%zd, fwd1=%zd, tx0=%zd, tx1=%zd",
                  ring_idx,
                  val.fields.cdb_core_ring_ch0_select,
                  val.fields.cdb_core_ring_ch1_select,
                  val.fields.cdb_core_ring_ch2_select,
                  val.fields.cdb_core_ring_ch3_select,
                  val.fields.cdb_core_ring_ch4_select);

        status = m_ll_device->write_register(ring_channel_select_regs[ring_idx], val);
        return_on_error(status);
    }

    // Configuring:
    // 2. Output interface (slice, ifs) -> Core channels
    // Value can be up to 43: 0-39 - core interfaces; 40:43 results from 4 DB mergers (dbm[4]_join_ringsg)
    const lld_register_array_container& slice_result_index_select_regs(*tree->cdb->top->slice_result_index_select);

    for (size_t slice_idx = 0; slice_idx < m_num_of_slices; ++slice_idx) {
        cdb_top_slice_result_index_select_register val = {.u8 = {0}};

        val.fields.slice_term_res_select = m_output_interface_to_abs_result_channel[slice_idx][ctm::INTERFACE_TERM];
        val.fields.slice_fwd0_res_select = m_output_interface_to_abs_result_channel[slice_idx][ctm::INTERFACE_FWD0];
        val.fields.slice_fwd1_res_select = m_output_interface_to_abs_result_channel[slice_idx][ctm::INTERFACE_FWD1];
        val.fields.slice_egr0_res_select = m_output_interface_to_abs_result_channel[slice_idx][ctm::INTERFACE_TX0];
        val.fields.slice_egr1_res_select = m_output_interface_to_abs_result_channel[slice_idx][ctm::INTERFACE_TX1];

        log_debug(RA,
                  "ctm_config setting output interface: slice=%zd, term=%zd, fwd0=%zd, fwd1=%zd, tx0=%zd, tx1=%zd",
                  slice_idx,
                  val.fields.slice_term_res_select,
                  val.fields.slice_fwd0_res_select,
                  val.fields.slice_fwd1_res_select,
                  val.fields.slice_egr0_res_select,
                  val.fields.slice_egr1_res_select);

        status = m_ll_device->write_register(*slice_result_index_select_regs[slice_idx], val);
        return_on_error(status);
    }

    // Configuring:
    // 3. DB mergers. Each DB merger getting bitmap indicating which cores it is merging
    //    If relevant bit is 1, res chan 0 of this core is entered to the DB merger
    const lld_register_array_container& dbm_join_rings_regs(*tree->cdb->top->dbm_join_rings);
    for (size_t idx = 0; idx < ctm::NUM_DB_MERGERS; ++idx) {
        cdb_top_dbm_join_rings_register val = {.u8 = {0}};
        val.fields.dbm_use_rings = m_dbm[idx];

        log_debug(RA, "ctm_config configuring db merger %zd: value:%x", idx, m_dbm[idx]);

        status = m_ll_device->write_register(*dbm_join_rings_regs[idx], val);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class CORE>
la_status
ctm_config_pacific::set_default_cdb_core(const CORE& cdb_core, size_t core_idx) const
{
    la_status status = LA_STATUS_SUCCESS;

    // Invalidate TCAM -> key channel, hit channel and relevant tables for the TCAM
    for (size_t tcam_idx = 0; tcam_idx < ctm::NUM_MEMS_PER_SUBRING; ++tcam_idx) {
        cdb_core_ctm_ring_tcams_cfg_register tcam_cfg_val = {.u8 = {0}};
        tcam_cfg_val.fields.tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;

        tcam_cfg_val.fields.tcam_key_ch_sel = CHANNEL_INVAL_REG_VALUE;
        tcam_cfg_val.fields.tcam_hit_ch_sel = CHANNEL_INVAL_REG_VALUE;

        const lld_register_array_container& tcam_regs(*cdb_core->ctm_ring_tcams_cfg);
        status = m_ll_device->write_register(*tcam_regs[tcam_idx], tcam_cfg_val);
        return_on_error(status);
    }

    // Invalidate SRAM -> TCAM and hit channel for each one of the banks (each SRAM is 2 banks of 512 each)
    for (size_t sram_idx = 0; sram_idx < ctm::NUM_MEMS_PER_SUBRING; ++sram_idx) {
        cdb_core_ctm_ring_srams_cfg_register sram_reg_val = {.u8 = {0}};

        sram_reg_val.fields.sram_tcam_a_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val.fields.sram_ch_a_sel = CHANNEL_INVAL_REG_VALUE;

        sram_reg_val.fields.sram_tcam_b_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val.fields.sram_ch_b_sel = CHANNEL_INVAL_REG_VALUE;

        sram_reg_val.fields.sram_payload_size = 1; // 32bit - not 2x16bit

        const lld_register_array_container& sram_regs(*cdb_core->ctm_ring_srams_cfg);
        status = m_ll_device->write_register(*sram_regs[sram_idx], sram_reg_val);
        return_on_error(status);
    }

    // Invalidate core result channel MSB/LSB regs.
    cdb_core_ctm_ring_result_channel_sram_sel_register res_channel_val[ctm::NUM_CHANNELS_PER_CORE];
    memset(res_channel_val, 0, sizeof(res_channel_val));

    for (size_t res_idx = 0; res_idx < ctm::NUM_CHANNELS_PER_CORE; ++res_idx) {
        const lld_register_array_container& ring_result_regs(*cdb_core->ctm_ring_result_channel_sram_sel);
        status = m_ll_device->write_register(*ring_result_regs[res_idx], res_channel_val[res_idx]);
        return_on_error(status);
    }

    // TCAM size is configured only on the first 6 rings. The last 6 rings are set to 160b by default.
    // We set all TCAMs to 320b as it should also work with 160b.
    const lld_register_array_container& acl_size_regs(*cdb_core->acl_tcam_size);
    for (size_t acl_idx = 0; acl_idx < acl_size_regs.size(); ++acl_idx) {
        cdb_core_acl_tcam_size_register tcam_size_val = {.u8 = {0}};
        tcam_size_val.fields.acl_tcam_size = ctm::KEY_SIZE_320b;
        status = m_ll_device->write_register(*acl_size_regs[acl_idx], tcam_size_val);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_pacific::configure_hw()
{
    la_status status = LA_STATUS_SUCCESS;

    status = configure_cdb_top();
    return_on_error(status);

    pacific_tree_scptr tree = m_ll_device->get_pacific_tree_scptr();
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS / 2; ++ring_idx) {

        status = set_default_cdb_core(tree->cdb->core_reduced[ring_idx], ring_idx * 2);
        return_on_error(status);

        status = set_default_cdb_core(tree->cdb->core[ring_idx], ring_idx * 2 + 1);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
ctm_config_pacific::invalidate_tcam(const tcam_desc& tcam, const ctm_sram_pair& srams, size_t result_channel)
{
    dassert_crit(tcam.subring_idx == 0);
    const pacific_tree* tree = m_ll_device->get_pacific_tree();
    size_t core_idx = tcam.ring_idx / 2;
    bool is_full_core = (tcam.ring_idx % 2);
    if (is_full_core) {
        core_invalidate_tcam(tree->cdb->core[core_idx], tcam, srams, result_channel);
    } else {
        core_invalidate_tcam(tree->cdb->core_reduced[core_idx], tcam, srams, result_channel);
    }
}

template <class CORE>
void
ctm_config_pacific::core_invalidate_tcam(const CORE& cdb_core,
                                         const tcam_desc& tcam,
                                         const ctm_sram_pair& srams,
                                         size_t result_channel)
{
    la_status status;
    cdb_core_ctm_ring_tcams_cfg_register tcam_cfg_val = {.u8 = {0}};
    tcam_cfg_val.fields.tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;
    tcam_cfg_val.fields.tcam_key_ch_sel = CHANNEL_INVAL_REG_VALUE;
    tcam_cfg_val.fields.tcam_hit_ch_sel = CHANNEL_INVAL_REG_VALUE;
    const lld_register_array_container& tcam_regs(*cdb_core->ctm_ring_tcams_cfg);
    status = m_ll_device->write_register(*tcam_regs[tcam.tcam_idx], tcam_cfg_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    log_debug(RA, "ctm_config invalidating TCAM: ring=%lu, subring=%lu, tcam=%lu", tcam.ring_idx, tcam.subring_idx, tcam.tcam_idx);

    if (srams.lsb_sram_idx != MEM_IDX_INVAL) {
        core_invalidate_sram(cdb_core, tcam, srams.lsb_sram_idx, srams.sram_half, result_channel);
    }
    if (srams.msb_sram_idx != MEM_IDX_INVAL) {
        core_invalidate_sram(cdb_core, tcam, srams.msb_sram_idx, srams.sram_half, result_channel);
    }
}

template <class CORE>
void
ctm_config_pacific::core_invalidate_sram(const CORE& cdb_core,
                                         const tcam_desc& tcam,
                                         size_t sram_idx,
                                         ctm_sram_half sram_half,
                                         size_t result_channel)
{
    la_status status;
    const lld_register_array_container& sram_regs(*cdb_core->ctm_ring_srams_cfg);

    cdb_core_ctm_ring_srams_cfg_register sram_reg_val;
    status = m_ll_device->read_register(*sram_regs[sram_idx], sram_reg_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_half == ctm_sram_half::FIRST_HALF) {
        sram_reg_val.fields.sram_tcam_a_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val.fields.sram_ch_a_sel = CHANNEL_INVAL_REG_VALUE;
    } else {
        sram_reg_val.fields.sram_tcam_b_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val.fields.sram_ch_b_sel = CHANNEL_INVAL_REG_VALUE;
    }

    log_debug(RA,
              "ctm_config invalidating SRAM: ring=%lu, subring=%lu, tcam=%lu, sram=%lu half=%d",
              tcam.ring_idx,
              tcam.subring_idx,
              tcam.tcam_idx,
              sram_idx,
              (int)sram_half);

    status = m_ll_device->write_register(*sram_regs[sram_idx], sram_reg_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_reg_val.fields.sram_tcam_a_sel == MEM_IDX_INVAL_REG_VALUE
        && sram_reg_val.fields.sram_tcam_b_sel == MEM_IDX_INVAL_REG_VALUE) {
        dassert_crit(result_channel != CHANNEL_INVAL);
        // Remove SRAM from result channel if both of its halves are free.
        const lld_register_array_container& ring_result_regs(*cdb_core->ctm_ring_result_channel_sram_sel);
        cdb_core_ctm_ring_result_channel_sram_sel_register res_channel_val;

        status = m_ll_device->read_register(*ring_result_regs[result_channel], res_channel_val);
        dassert_crit(status == LA_STATUS_SUCCESS);

        res_channel_val.fields.ch_msb_sram_sel &= ~(1UL << sram_idx);
        res_channel_val.fields.ch_lsb_sram_sel &= ~(1UL << sram_idx);
        status = m_ll_device->write_register(*ring_result_regs[result_channel], res_channel_val);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }
}

void
ctm_config_pacific::configure_tcam(size_t ring_idx, size_t subring_idx, size_t tcam_idx, size_t channel, bool configure_sram)
{
    dassert_crit(subring_idx == 0);
    const pacific_tree* tree = m_ll_device->get_pacific_tree();
    size_t core_idx = ring_idx / 2;
    bool is_full_core = (ring_idx % 2);
    if (is_full_core) {
        core_configure_tcam(tree->cdb->core[core_idx], ring_idx, tcam_idx, channel, configure_sram);
    } else {
        core_configure_tcam(tree->cdb->core_reduced[core_idx], ring_idx, tcam_idx, channel, configure_sram);
    }
}

template <class CORE>
void
ctm_config_pacific::core_configure_tcam(const CORE& cdb_core, size_t ring_idx, size_t tcam_idx, size_t channel, bool configure_sram)
{
    la_status status;
    cdb_core_ctm_ring_tcams_cfg_register tcam_cfg_val = {.u8 = {0}};
    tcam_cfg_val.fields.tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;
    tcam_cfg_val.fields.tcam_key_ch_sel = channel;
    tcam_cfg_val.fields.tcam_hit_ch_sel = channel;

    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, 0 /* subring */);
    ctm_sram_pair srams = m_sram_allocator->get_srams_by_tcam(sram_ring_idx, tcam_idx);

    ctm_sram_half sram_half = srams.sram_half;

    size_t tcam_index_offset = (sram_half == ctm_sram_half::FIRST_HALF) ? 0 : 1;
    tcam_cfg_val.fields.tcam_index_offset = tcam_index_offset;

    log_debug(RA,
              "ctm_config setting TCAM: core=%lu, tcam=%lu key_channel=%zd, hit_channel=%zd, tcam_index_offset=%zu ldb=0x%zx",
              ring_idx,
              tcam_idx,
              tcam_cfg_val.fields.tcam_key_ch_sel,
              tcam_cfg_val.fields.tcam_hit_ch_sel,
              tcam_cfg_val.fields.tcam_index_offset,
              tcam_cfg_val.fields.tcam_ldb_access);

    const lld_register_array_container& tcam_regs(*cdb_core->ctm_ring_tcams_cfg);
    status = m_ll_device->write_register(*tcam_regs[tcam_idx], tcam_cfg_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (configure_sram) {
        dassert_crit(srams.lsb_sram_idx != MEM_IDX_INVAL);
        core_configure_sram_to_tcam(cdb_core, ring_idx, tcam_idx, channel, srams.lsb_sram_idx, srams.sram_half);
        if (srams.msb_sram_idx != MEM_IDX_INVAL) {
            core_configure_sram_to_tcam(cdb_core, ring_idx, tcam_idx, channel, srams.msb_sram_idx, srams.sram_half);
        }
    }
}

template <class CORE>
void
ctm_config_pacific::core_configure_sram_to_tcam(const CORE& cdb_core,
                                                size_t ring_idx,
                                                size_t tcam_idx,
                                                size_t channel,
                                                size_t sram_idx,
                                                ctm_sram_half sram_half)
{
    la_status status;
    const lld_register_array_container& sram_regs(*cdb_core->ctm_ring_srams_cfg);

    cdb_core_ctm_ring_srams_cfg_register sram_reg_val;
    status = m_ll_device->read_register(*sram_regs[sram_idx], sram_reg_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_half == ctm_sram_half::FIRST_HALF) {
        dassert_crit(sram_reg_val.fields.sram_tcam_a_sel == MEM_IDX_INVAL_REG_VALUE);
        dassert_crit(sram_reg_val.fields.sram_ch_a_sel == CHANNEL_INVAL_REG_VALUE);
        sram_reg_val.fields.sram_tcam_a_sel = tcam_idx;
        sram_reg_val.fields.sram_ch_a_sel = channel;
    } else {
        dassert_crit(sram_reg_val.fields.sram_tcam_b_sel == MEM_IDX_INVAL_REG_VALUE);
        dassert_crit(sram_reg_val.fields.sram_ch_b_sel == CHANNEL_INVAL_REG_VALUE);
        sram_reg_val.fields.sram_tcam_b_sel = tcam_idx;
        sram_reg_val.fields.sram_ch_b_sel = channel;
    }

    sram_reg_val.fields.sram_payload_size = 1; // 32bit - not 2x16bit

    log_debug(RA,
              "ctm_config setting SRAM: core=%lu, sram=%lu, tcamA=%zd, %s=%zd",
              ring_idx,
              sram_idx,
              sram_reg_val.fields.sram_tcam_a_sel,
              sram_half == ctm_sram_half::FIRST_HALF ? "hit_channelA" : "hit_channelB",
              sram_reg_val.fields.sram_ch_a_sel);

    status = m_ll_device->write_register(*sram_regs[sram_idx], sram_reg_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, 0 /* subring */);
    const sram_desc& desc = m_sram_allocator->get_sram_result_desc(sram_ring_idx, sram_idx);
    dassert_crit(desc.result_channel != CHANNEL_INVAL);

    const lld_register_array_container& ring_result_regs(*cdb_core->ctm_ring_result_channel_sram_sel);
    cdb_core_ctm_ring_result_channel_sram_sel_register res_channel_val;

    status = m_ll_device->read_register(*ring_result_regs[desc.result_channel], res_channel_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (desc.is_msb) {
        res_channel_val.fields.ch_msb_sram_sel |= (1 << sram_idx);
    } else {
        res_channel_val.fields.ch_lsb_sram_sel |= (1 << sram_idx);
    }
    dassert_crit((res_channel_val.fields.ch_msb_sram_sel & res_channel_val.fields.ch_lsb_sram_sel) == 0);

    status = m_ll_device->write_register(*ring_result_regs[desc.result_channel], res_channel_val);
    dassert_crit(status == LA_STATUS_SUCCESS);
}

} // namespace silicon_one
