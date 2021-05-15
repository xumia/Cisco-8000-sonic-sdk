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

#include "ctm_config_gibraltar.h"

#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "ctm_common_tcam.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/ll_device.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

ctm_config_gibraltar::ctm_config_gibraltar(const ll_device_sptr& ldevice,
                                           bool is_linecard_mode,
                                           size_t lpm_tcam_num_banksets,
                                           size_t number_of_slices)
    : ctm_config_tcam(ldevice, is_linecard_mode, lpm_tcam_num_banksets, number_of_slices)
{
    m_lpm_tcams_ring0 = lpm_tcams;
    m_lpm_tcams_ring1 = lpm_tcams;

    map_init();
}

bool
ctm_config_gibraltar::is_msb_tcam(size_t tcam_idx) const
{
    if (tcam_idx % 2 == get_key_320_tcam_offset()) {
        return true;
    }
    return false;
}

size_t
ctm_config_gibraltar::get_key_320_tcam_offset() const
{
    // 320b keys are written to two consequitive TCAMs with indices X, X+1, where X is even number
    return KEY_320_TCAM_OFFSET;
}

size_t
ctm_config_gibraltar::get_number_of_subrings() const
{
    return NUM_SUBRINGS;
}

// Configuring:
// 1. Core channels -> Input interface (slice, ifs)
// 2. Output interface (slice, ifs) -> Core channels
la_status
ctm_config_gibraltar::configure_cdb_top() const
{
    la_status status = LA_STATUS_SUCCESS;
    gibraltar_tree_scptr tree = m_ll_device->get_gibraltar_tree_scptr();

    // Configuring:
    // 1. Core channels -> Input interface (slice, ifs)
    const lld_register_array_container& ring_channel_select_regs(*tree->cdb->top->ring_channel_select);
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ++ring_idx) {
        gibraltar::cdb_top_ring_channel_select_register val = {.u8 = {0}};
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
        gibraltar::cdb_top_slice_result_index_select_register val = {.u8 = {0}};

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

        status = m_ll_device->write_register(slice_result_index_select_regs[slice_idx], val);
        return_on_error(status);
    }

    // Configuring:
    // 3. DB mergers. Each DB merger getting bitmap indicating which cores it is merging
    //    If relevant bit is 1, res chan 0 of this core is entered to the DB merger
    const lld_register_array_container& dbm_join_rings_regs(*tree->cdb->top->dbm_join_rings);
    for (size_t idx = 0; idx < ctm::NUM_DB_MERGERS; ++idx) {
        gibraltar::cdb_top_dbm_join_rings_register val = {.u8 = {0}};
        val.fields.dbm_use_rings = m_dbm[idx];

        log_debug(RA, "ctm_config configuring db merger %zd: value:%x", idx, m_dbm[idx]);

        status = m_ll_device->write_register(dbm_join_rings_regs[idx], val);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

template <class CORE>
la_status
ctm_config_gibraltar::set_default_cdb_core(const CORE& cdb_core, size_t core_idx) const
{
    la_status status = LA_STATUS_SUCCESS;

    // Invalidate TCAM -> key channel, hit channel and relevant tables for the TCAM
    for (size_t tcam_idx = 0; tcam_idx < ctm::NUM_MEMS_PER_SUBRING; ++tcam_idx) {
        gibraltar::cdb_core_ctm_ring0_tcams_cfg_register tcam_cfg_val0 = {.u8 = {0}};
        tcam_cfg_val0.fields.ring0_tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;
        gibraltar::cdb_core_ctm_ring1_tcams_cfg_register tcam_cfg_val1 = {.u8 = {0}};
        tcam_cfg_val1.fields.ring1_tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;

        tcam_cfg_val0.fields.ring0_tcam_key_ch_sel = CHANNEL_INVAL_REG_VALUE;
        tcam_cfg_val0.fields.ring0_tcam_hit_ch_sel = CHANNEL_INVAL_REG_VALUE;
        tcam_cfg_val1.fields.ring1_tcam_key_ch_sel = CHANNEL_INVAL_REG_VALUE;
        tcam_cfg_val1.fields.ring1_tcam_hit_ch_sel = CHANNEL_INVAL_REG_VALUE;

        const lld_register_array_container& tcam_regs0(*cdb_core->ctm_ring0_tcams_cfg);
        status = m_ll_device->write_register(tcam_regs0[tcam_idx], tcam_cfg_val0);
        return_on_error(status);
        const lld_register_array_container& tcam_regs1(*cdb_core->ctm_ring1_tcams_cfg);
        status = m_ll_device->write_register(tcam_regs1[tcam_idx], tcam_cfg_val1);
        return_on_error(status);
    }

    // Invalidate SRAM -> TCAM and hit channel for each one of the banks (each SRAM is 2 banks of 512 each)
    for (size_t sram_idx = 0; sram_idx < ctm::NUM_MEMS_PER_SUBRING; ++sram_idx) {
        gibraltar::cdb_core_ctm_ring0_srams_cfg_register sram_reg_val0 = {.u8 = {0}};
        sram_reg_val0.fields.ring0_sram_tcam_a_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val0.fields.ring0_sram_ch_a_sel = CHANNEL_INVAL_REG_VALUE;

        gibraltar::cdb_core_ctm_ring1_srams_cfg_register sram_reg_val1 = {.u8 = {0}};
        sram_reg_val1.fields.ring1_sram_tcam_a_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val1.fields.ring1_sram_ch_a_sel = CHANNEL_INVAL_REG_VALUE;

        sram_reg_val0.fields.ring0_sram_tcam_b_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val0.fields.ring0_sram_ch_b_sel = CHANNEL_INVAL_REG_VALUE;

        sram_reg_val1.fields.ring1_sram_tcam_b_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val1.fields.ring1_sram_ch_b_sel = CHANNEL_INVAL_REG_VALUE;

        sram_reg_val0.fields.ring0_sram_payload_size = 1; // 32bit - not 2x16bit
        sram_reg_val1.fields.ring1_sram_payload_size = 1; // 32bit - not 2x16bit

        const lld_register_array_container& ring0_sram_regs(*cdb_core->ctm_ring0_srams_cfg);
        status = m_ll_device->write_register(ring0_sram_regs[sram_idx], sram_reg_val0);
        return_on_error(status);
        const lld_register_array_container& ring1_sram_regs(*cdb_core->ctm_ring1_srams_cfg);
        status = m_ll_device->write_register(ring1_sram_regs[sram_idx], sram_reg_val1);
        return_on_error(status);
    }

    // Invalidate core result channel MSB/LSB regs.
    gibraltar::cdb_core_ctm_ring0_result_channel_sram_sel_register ring0_res_channel_val[ctm::NUM_CHANNELS_PER_CORE];
    memset(ring0_res_channel_val, 0, sizeof(ring0_res_channel_val));
    gibraltar::cdb_core_ctm_ring1_result_channel_sram_sel_register ring1_res_channel_val[ctm::NUM_CHANNELS_PER_CORE];
    memset(ring1_res_channel_val, 0, sizeof(ring1_res_channel_val));

    for (size_t res_idx = 0; res_idx < ctm::NUM_CHANNELS_PER_CORE; ++res_idx) {
        const lld_register_array_container& ring0_result_regs(*cdb_core->ctm_ring0_result_channel_sram_sel);
        status = m_ll_device->write_register(ring0_result_regs[res_idx], ring0_res_channel_val[res_idx]);
        return_on_error(status);
        const lld_register_array_container& ring1_result_regs(*cdb_core->ctm_ring1_result_channel_sram_sel);
        status = m_ll_device->write_register(ring1_result_regs[res_idx], ring1_res_channel_val[res_idx]);
        return_on_error(status);
    }

    // Set all TCAMs key size to 320b, this configuration allows also 160b keys.
    const lld_register_array_container& ring0_shared_acl_size_regs(*cdb_core->ring0_shared_tcam_size_reg);
    const lld_register_array_container& ring1_shared_acl_size_regs(*cdb_core->ring1_shared_tcam_size_reg);
    for (size_t acl_idx = 0; acl_idx < ring0_shared_acl_size_regs.size(); ++acl_idx) {
        gibraltar::cdb_core_ring0_shared_tcam_size_reg_register ring0_shared_tcam_size_val = {.u8 = {0}};
        gibraltar::cdb_core_ring1_shared_tcam_size_reg_register ring1_shared_tcam_size_val = {.u8 = {0}};
        ring0_shared_tcam_size_val.fields.ring0_shared_tcam_size = KEY_SIZE_320b;
        ring1_shared_tcam_size_val.fields.ring1_shared_tcam_size = KEY_SIZE_320b;
        status = m_ll_device->write_register(ring0_shared_acl_size_regs[acl_idx], ring0_shared_tcam_size_val);
        return_on_error(status);
        status = m_ll_device->write_register(ring1_shared_acl_size_regs[acl_idx], ring1_shared_tcam_size_val);
        return_on_error(status);
    }
    const lld_register_array_container& ring0_acl_size_regs(*cdb_core->ring0_acl_tcam_is_320_reg);
    const lld_register_array_container& ring1_acl_size_regs(*cdb_core->ring1_acl_tcam_is_320_reg);
    for (size_t acl_idx = 0; acl_idx < ring0_acl_size_regs.size(); ++acl_idx) {
        gibraltar::cdb_core_ring0_acl_tcam_is_320_reg_register ring0_acl_tcam_size_val = {.u8 = {0}};
        gibraltar::cdb_core_ring1_acl_tcam_is_320_reg_register ring1_acl_tcam_size_val = {.u8 = {0}};
        ring0_acl_tcam_size_val.fields.ring0_acl_tcam_is_320 = true;
        ring1_acl_tcam_size_val.fields.ring1_acl_tcam_is_320 = true;
        status = m_ll_device->write_register(ring0_acl_size_regs[acl_idx], ring0_acl_tcam_size_val);
        return_on_error(status);
        status = m_ll_device->write_register(ring1_acl_size_regs[acl_idx], ring1_acl_tcam_size_val);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_gibraltar::configure_hw()
{
    la_status status = LA_STATUS_SUCCESS;

    status = configure_cdb_top();
    return_on_error(status);

    gibraltar_tree_scptr tree = m_ll_device->get_gibraltar_tree_scptr();
    for (size_t ring_idx = 0; ring_idx < ctm::NUM_RINGS; ++ring_idx) {

        status = set_default_cdb_core(tree->cdb->core[ring_idx], ring_idx);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

void
ctm_config_gibraltar::invalidate_tcam(const tcam_desc& tcam, const ctm_sram_pair& srams, size_t result_channel)
{
    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();
    if (tcam.subring_idx == 0) {
        core_invalidate_tcam_subring0(tree->cdb->core[tcam.ring_idx], tcam, srams, result_channel);
    } else {
        dassert_crit(tcam.subring_idx == 1);
        core_invalidate_tcam_subring1(tree->cdb->core[tcam.ring_idx], tcam, srams, result_channel);
    }
}

template <class CORE>
void
ctm_config_gibraltar::core_invalidate_tcam_subring0(const CORE& cdb_core,
                                                    const tcam_desc& tcam,
                                                    const ctm_sram_pair& srams,
                                                    size_t result_channel)
{
    dassert_crit(tcam.subring_idx == 0);
    la_status status;
    gibraltar::cdb_core_ctm_ring0_tcams_cfg_register tcam_cfg_val0 = {.u8 = {0}};
    tcam_cfg_val0.fields.ring0_tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;
    tcam_cfg_val0.fields.ring0_tcam_key_ch_sel = CHANNEL_INVAL_REG_VALUE;
    tcam_cfg_val0.fields.ring0_tcam_hit_ch_sel = CHANNEL_INVAL_REG_VALUE;
    const lld_register_array_container& tcam_regs0(*cdb_core->ctm_ring0_tcams_cfg);
    status = m_ll_device->write_register(tcam_regs0[tcam.tcam_idx], tcam_cfg_val0);
    dassert_crit(status == LA_STATUS_SUCCESS);
    if (srams.lsb_sram_idx != MEM_IDX_INVAL) {
        core_invalidate_sram_subring0(cdb_core, tcam, srams.lsb_sram_idx, srams.sram_half, result_channel);
    }
    if (srams.msb_sram_idx != MEM_IDX_INVAL) {
        core_invalidate_sram_subring0(cdb_core, tcam, srams.msb_sram_idx, srams.sram_half, result_channel);
    }
}

template <class CORE>
void
ctm_config_gibraltar::core_invalidate_tcam_subring1(const CORE& cdb_core,
                                                    const tcam_desc& tcam,
                                                    const ctm_sram_pair& srams,
                                                    size_t result_channel)
{
    dassert_crit(tcam.subring_idx == 1);
    la_status status;
    gibraltar::cdb_core_ctm_ring1_tcams_cfg_register tcam_cfg_val = {.u8 = {0}};
    tcam_cfg_val.fields.ring1_tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;
    tcam_cfg_val.fields.ring1_tcam_key_ch_sel = CHANNEL_INVAL_REG_VALUE;
    tcam_cfg_val.fields.ring1_tcam_hit_ch_sel = CHANNEL_INVAL_REG_VALUE;
    const lld_register_array_container& tcam_regs1(*cdb_core->ctm_ring1_tcams_cfg);
    status = m_ll_device->write_register(tcam_regs1[tcam.tcam_idx], tcam_cfg_val);
    dassert_crit(status == LA_STATUS_SUCCESS);
    if (srams.lsb_sram_idx != MEM_IDX_INVAL) {
        core_invalidate_sram_subring1(cdb_core, tcam, srams.lsb_sram_idx, srams.sram_half, result_channel);
    }
    if (srams.msb_sram_idx != MEM_IDX_INVAL) {
        core_invalidate_sram_subring1(cdb_core, tcam, srams.msb_sram_idx, srams.sram_half, result_channel);
    }
}

template <class CORE>
void
ctm_config_gibraltar::core_invalidate_sram_subring0(const CORE& cdb_core,
                                                    const tcam_desc& tcam,
                                                    size_t sram_idx,
                                                    ctm_sram_half sram_half,
                                                    size_t result_channel)
{
    dassert_crit(tcam.subring_idx == 0);

    log_debug(RA,
              "ctm_config invalidating SRAM: ring=%lu, subring=%lu, tcam=%lu, sram=%lu half=%d",
              tcam.ring_idx,
              tcam.subring_idx,
              tcam.tcam_idx,
              sram_idx,
              (int)sram_half);

    la_status status;
    const lld_register_array_container& ring0_sram_regs(*cdb_core->ctm_ring0_srams_cfg);

    gibraltar::cdb_core_ctm_ring0_srams_cfg_register sram_reg_val0;

    status = m_ll_device->read_register(ring0_sram_regs[sram_idx], sram_reg_val0);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_half == ctm_sram_half::FIRST_HALF) {
        sram_reg_val0.fields.ring0_sram_tcam_a_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val0.fields.ring0_sram_ch_a_sel = CHANNEL_INVAL_REG_VALUE;
    } else {
        sram_reg_val0.fields.ring0_sram_tcam_b_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val0.fields.ring0_sram_ch_b_sel = CHANNEL_INVAL_REG_VALUE;
    }

    status = m_ll_device->write_register(ring0_sram_regs[sram_idx], sram_reg_val0);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_reg_val0.fields.ring0_sram_tcam_a_sel == MEM_IDX_INVAL_REG_VALUE
        && sram_reg_val0.fields.ring0_sram_tcam_b_sel == MEM_IDX_INVAL_REG_VALUE) {
        dassert_crit(result_channel != CHANNEL_INVAL);
        // Remove SRAM from result channel if both of its halves are free.
        gibraltar::cdb_core_ctm_ring0_result_channel_sram_sel_register res_channel_val;
        const lld_register_array_container& ring0_result_regs(*cdb_core->ctm_ring0_result_channel_sram_sel);
        status = m_ll_device->read_register(ring0_result_regs[result_channel], res_channel_val);
        dassert_crit(status == LA_STATUS_SUCCESS);

        res_channel_val.fields.ring0_ch_msb_sram_sel &= ~(1UL << sram_idx);
        res_channel_val.fields.ring0_ch_lsb_sram_sel &= ~(1UL << sram_idx);
        status = m_ll_device->write_register(ring0_result_regs[result_channel], res_channel_val);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }
}

template <class CORE>
void
ctm_config_gibraltar::core_invalidate_sram_subring1(const CORE& cdb_core,
                                                    const tcam_desc& tcam,
                                                    size_t sram_idx,
                                                    ctm_sram_half sram_half,
                                                    size_t result_channel)
{
    dassert_crit(tcam.subring_idx == 1);

    log_debug(RA,
              "ctm_config invalidating SRAM: ring=%lu, subring=%lu, tcam=%lu, sram=%lu half=%d",
              tcam.ring_idx,
              tcam.subring_idx,
              tcam.tcam_idx,
              sram_idx,
              (int)sram_half);

    la_status status;
    const lld_register_array_container& ring1_sram_regs(*cdb_core->ctm_ring1_srams_cfg);

    gibraltar::cdb_core_ctm_ring1_srams_cfg_register sram_reg_val1;

    status = m_ll_device->read_register(ring1_sram_regs[sram_idx], sram_reg_val1);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_half == ctm_sram_half::FIRST_HALF) {
        sram_reg_val1.fields.ring1_sram_tcam_a_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val1.fields.ring1_sram_ch_a_sel = CHANNEL_INVAL_REG_VALUE;
    } else {
        sram_reg_val1.fields.ring1_sram_tcam_b_sel = MEM_IDX_INVAL_REG_VALUE;
        sram_reg_val1.fields.ring1_sram_ch_b_sel = CHANNEL_INVAL_REG_VALUE;
    }

    status = m_ll_device->write_register(ring1_sram_regs[sram_idx], sram_reg_val1);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_reg_val1.fields.ring1_sram_tcam_a_sel == MEM_IDX_INVAL_REG_VALUE
        && sram_reg_val1.fields.ring1_sram_tcam_b_sel == MEM_IDX_INVAL_REG_VALUE) {
        dassert_crit(result_channel != CHANNEL_INVAL);
        // Remove SRAM from result channel if both of its halves are free.
        gibraltar::cdb_core_ctm_ring1_result_channel_sram_sel_register res_channel_val;
        const lld_register_array_container& ring1_result_regs(*cdb_core->ctm_ring1_result_channel_sram_sel);
        status = m_ll_device->read_register(ring1_result_regs[result_channel], res_channel_val);
        dassert_crit(status == LA_STATUS_SUCCESS);

        res_channel_val.fields.ring1_ch_msb_sram_sel &= ~(1UL << sram_idx);
        res_channel_val.fields.ring1_ch_lsb_sram_sel &= ~(1UL << sram_idx);
        status = m_ll_device->write_register(ring1_result_regs[result_channel], res_channel_val);
        dassert_crit(status == LA_STATUS_SUCCESS);
    }
}

void
ctm_config_gibraltar::configure_tcam(size_t ring_idx, size_t subring_idx, size_t tcam_idx, size_t channel, bool configure_sram)
{
    const gibraltar_tree* tree = m_ll_device->get_gibraltar_tree();
    if (subring_idx == 0) {
        core_configure_tcam_subring0(tree->cdb->core[ring_idx], ring_idx, tcam_idx, channel, configure_sram);
    } else {
        dassert_crit(subring_idx == 1);
        core_configure_tcam_subring1(tree->cdb->core[ring_idx], ring_idx, tcam_idx, channel, configure_sram);
    }
}

template <class CORE>
void
ctm_config_gibraltar::core_configure_tcam_subring0(const CORE& cdb_core,
                                                   size_t ring_idx,
                                                   size_t tcam_idx,
                                                   size_t channel,
                                                   bool configure_sram)
{
    la_status status;
    gibraltar::cdb_core_ctm_ring0_tcams_cfg_register tcam_cfg_val0 = {.u8 = {0}};
    tcam_cfg_val0.fields.ring0_tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;

    tcam_cfg_val0.fields.ring0_tcam_key_ch_sel = channel;
    tcam_cfg_val0.fields.ring0_tcam_hit_ch_sel = channel;

    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, 0 /* subring */);
    ctm_sram_pair srams = m_sram_allocator->get_srams_by_tcam(sram_ring_idx, tcam_idx);

    ctm_sram_half sram_half = srams.sram_half;
    size_t tcam_index_offset = (sram_half == ctm_sram_half::FIRST_HALF) ? 0 : 1;
    tcam_cfg_val0.fields.ring0_tcam_index_offset = tcam_index_offset;

    log_debug(RA,
              "ctm_config setting TCAM: core=%lu, tcam=%lu "
              "ring0: key_channel=%zd, hit_channel=%zd, ldb=0x%zx ",
              ring_idx,
              tcam_idx,
              tcam_cfg_val0.fields.ring0_tcam_key_ch_sel,
              tcam_cfg_val0.fields.ring0_tcam_hit_ch_sel,
              tcam_cfg_val0.fields.ring0_tcam_ldb_access);

    const lld_register_array_container& tcam_regs0(*cdb_core->ctm_ring0_tcams_cfg);
    status = m_ll_device->write_register(tcam_regs0[tcam_idx], tcam_cfg_val0);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (configure_sram) {
        dassert_crit(srams.lsb_sram_idx != MEM_IDX_INVAL);
        core_configure_sram_to_tcam_subring0(cdb_core, ring_idx, tcam_idx, channel, srams.lsb_sram_idx, srams.sram_half);
        if (srams.msb_sram_idx != MEM_IDX_INVAL) {
            core_configure_sram_to_tcam_subring0(cdb_core, ring_idx, tcam_idx, channel, srams.msb_sram_idx, srams.sram_half);
        }
    }
}

template <class CORE>
void
ctm_config_gibraltar::core_configure_tcam_subring1(const CORE& cdb_core,
                                                   size_t ring_idx,
                                                   size_t tcam_idx,
                                                   size_t channel,
                                                   bool configure_sram)
{
    la_status status;
    gibraltar::cdb_core_ctm_ring1_tcams_cfg_register tcam_cfg_val1 = {.u8 = {0}};
    tcam_cfg_val1.fields.ring1_tcam_ldb_access = TCAM_LDB_ACCESS_FULL_MASK;

    tcam_cfg_val1.fields.ring1_tcam_key_ch_sel = channel;
    tcam_cfg_val1.fields.ring1_tcam_hit_ch_sel = channel;

    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, 1 /* subring */);
    ctm_sram_pair srams = m_sram_allocator->get_srams_by_tcam(sram_ring_idx, tcam_idx);

    ctm_sram_half sram_half = srams.sram_half;
    size_t tcam_index_offset = (sram_half == ctm_sram_half::FIRST_HALF) ? 0 : 1;

    tcam_cfg_val1.fields.ring1_tcam_index_offset = tcam_index_offset;

    log_debug(RA,
              "ctm_config setting TCAM: core=%lu, tcam=%lu "
              "ring1: key_channel=%zd, hit_channel=%zd, ldb=0x%zx",
              ring_idx,
              tcam_idx,
              tcam_cfg_val1.fields.ring1_tcam_key_ch_sel,
              tcam_cfg_val1.fields.ring1_tcam_hit_ch_sel,
              tcam_cfg_val1.fields.ring1_tcam_ldb_access);

    const lld_register_array_container& tcam_regs1(*cdb_core->ctm_ring1_tcams_cfg);
    status = m_ll_device->write_register(tcam_regs1[tcam_idx], tcam_cfg_val1);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (configure_sram) {
        dassert_crit(srams.lsb_sram_idx != MEM_IDX_INVAL);
        core_configure_sram_to_tcam_subring1(cdb_core, ring_idx, tcam_idx, channel, srams.lsb_sram_idx, srams.sram_half);
        if (srams.msb_sram_idx != MEM_IDX_INVAL) {
            core_configure_sram_to_tcam_subring1(cdb_core, ring_idx, tcam_idx, channel, srams.msb_sram_idx, srams.sram_half);
        }
    }
}

template <class CORE>
void
ctm_config_gibraltar::core_configure_sram_to_tcam_subring0(const CORE& cdb_core,
                                                           size_t ring_idx,
                                                           size_t tcam_idx,
                                                           size_t channel,
                                                           size_t sram_idx,
                                                           ctm_sram_half sram_half)
{
    la_status status;
    const lld_register_array_container& ring0_sram_regs(*cdb_core->ctm_ring0_srams_cfg);

    gibraltar::cdb_core_ctm_ring0_srams_cfg_register sram_reg_val0;

    status = m_ll_device->read_register(ring0_sram_regs[sram_idx], sram_reg_val0);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_half == ctm_sram_half::FIRST_HALF) {
        dassert_crit(sram_reg_val0.fields.ring0_sram_tcam_a_sel == MEM_IDX_INVAL_REG_VALUE);
        dassert_crit(sram_reg_val0.fields.ring0_sram_ch_a_sel == CHANNEL_INVAL_REG_VALUE);
        sram_reg_val0.fields.ring0_sram_tcam_a_sel = tcam_idx;
        sram_reg_val0.fields.ring0_sram_ch_a_sel = channel;
    } else {
        dassert_crit(sram_reg_val0.fields.ring0_sram_tcam_b_sel == MEM_IDX_INVAL_REG_VALUE);
        dassert_crit(sram_reg_val0.fields.ring0_sram_ch_b_sel == CHANNEL_INVAL_REG_VALUE);
        sram_reg_val0.fields.ring0_sram_tcam_b_sel = tcam_idx;
        sram_reg_val0.fields.ring0_sram_ch_b_sel = channel;
    }

    sram_reg_val0.fields.ring0_sram_payload_size = 1; // 32bit - not 2x16bit

    log_debug(RA,
              "ctm_config setting SRAM: core=%lu, sram=%lu, "
              "ring0: tcamA=%zd, %s=%zd",
              ring_idx,
              sram_idx,
              sram_reg_val0.fields.ring0_sram_tcam_a_sel,
              (sram_half == ctm_sram_half::FIRST_HALF) ? "hit_channelA" : "hit_channelB",
              sram_reg_val0.fields.ring0_sram_ch_a_sel);

    status = m_ll_device->write_register(ring0_sram_regs[sram_idx], sram_reg_val0);
    dassert_crit(status == LA_STATUS_SUCCESS);

    gibraltar::cdb_core_ctm_ring0_result_channel_sram_sel_register ring0_res_channel_val;

    const lld_register_array_container& ring0_result_regs(*cdb_core->ctm_ring0_result_channel_sram_sel);

    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, 0 /* subring */);
    const sram_desc& desc = m_sram_allocator->get_sram_result_desc(sram_ring_idx, sram_idx);
    dassert_crit(desc.result_channel != CHANNEL_INVAL);

    status = m_ll_device->read_register(ring0_result_regs[desc.result_channel], ring0_res_channel_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (desc.is_msb) {
        ring0_res_channel_val.fields.ring0_ch_msb_sram_sel |= (1 << sram_idx);
    } else {
        ring0_res_channel_val.fields.ring0_ch_lsb_sram_sel |= (1 << sram_idx);
    }

    dassert_crit((ring0_res_channel_val.fields.ring0_ch_lsb_sram_sel & ring0_res_channel_val.fields.ring0_ch_msb_sram_sel) == 0);

    status = m_ll_device->write_register(ring0_result_regs[desc.result_channel], ring0_res_channel_val);
    dassert_crit(status == LA_STATUS_SUCCESS);
}

template <class CORE>
void
ctm_config_gibraltar::core_configure_sram_to_tcam_subring1(const CORE& cdb_core,
                                                           size_t ring_idx,
                                                           size_t tcam_idx,
                                                           size_t channel,
                                                           size_t sram_idx,
                                                           ctm_sram_half sram_half)
{
    la_status status;
    const lld_register_array_container& ring1_sram_regs(*cdb_core->ctm_ring1_srams_cfg);

    gibraltar::cdb_core_ctm_ring1_srams_cfg_register sram_reg_val1;

    status = m_ll_device->read_register(ring1_sram_regs[sram_idx], sram_reg_val1);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (sram_half == ctm_sram_half::FIRST_HALF) {
        dassert_crit(sram_reg_val1.fields.ring1_sram_tcam_a_sel == MEM_IDX_INVAL_REG_VALUE);
        dassert_crit(sram_reg_val1.fields.ring1_sram_ch_a_sel == CHANNEL_INVAL_REG_VALUE);
        sram_reg_val1.fields.ring1_sram_tcam_a_sel = tcam_idx;
        sram_reg_val1.fields.ring1_sram_ch_a_sel = channel;
    } else {
        dassert_crit(sram_reg_val1.fields.ring1_sram_tcam_b_sel == MEM_IDX_INVAL_REG_VALUE);
        dassert_crit(sram_reg_val1.fields.ring1_sram_ch_b_sel == CHANNEL_INVAL_REG_VALUE);
        sram_reg_val1.fields.ring1_sram_tcam_b_sel = tcam_idx;
        sram_reg_val1.fields.ring1_sram_ch_b_sel = channel;
    }

    sram_reg_val1.fields.ring1_sram_payload_size = 1; // 32bit - not 2x16bit

    log_debug(RA,
              "ctm_config setting SRAM: core=%lu, sram=%lu, "
              "ring1: tcamA=%zd, %s=%zd",
              ring_idx,
              sram_idx,
              sram_reg_val1.fields.ring1_sram_tcam_a_sel,
              (sram_half == ctm_sram_half::FIRST_HALF) ? "hit_channelA" : "hit_channelB",
              sram_reg_val1.fields.ring1_sram_ch_a_sel);

    status = m_ll_device->write_register(ring1_sram_regs[sram_idx], sram_reg_val1);
    dassert_crit(status == LA_STATUS_SUCCESS);

    gibraltar::cdb_core_ctm_ring1_result_channel_sram_sel_register ring1_res_channel_val;

    const lld_register_array_container& ring1_result_regs(*cdb_core->ctm_ring1_result_channel_sram_sel);

    size_t sram_ring_idx = cdb_ring_to_sram_allcoator_ring(ring_idx, 1 /* subring */);
    const sram_desc& desc = m_sram_allocator->get_sram_result_desc(sram_ring_idx, sram_idx);
    dassert_crit(desc.result_channel != CHANNEL_INVAL);

    status = m_ll_device->read_register(ring1_result_regs[desc.result_channel], ring1_res_channel_val);
    dassert_crit(status == LA_STATUS_SUCCESS);

    if (desc.is_msb) {
        ring1_res_channel_val.fields.ring1_ch_msb_sram_sel |= (1 << sram_idx);
    } else {
        ring1_res_channel_val.fields.ring1_ch_lsb_sram_sel |= (1 << sram_idx);
    }

    dassert_crit((ring1_res_channel_val.fields.ring1_ch_lsb_sram_sel & ring1_res_channel_val.fields.ring1_ch_msb_sram_sel) == 0);

    status = m_ll_device->write_register(ring1_result_regs[desc.result_channel], ring1_res_channel_val);
    dassert_crit(status == LA_STATUS_SUCCESS);
}

} // namespace silicon_one
