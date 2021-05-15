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

#include "la_hbm_handler_impl.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "la_device_impl.h"
#include "la_strings.h"
#include "lld/ll_device.h"
#include "lld/lld_utils.h"
#include "lld/pacific_reg_structs.h"
#include "lld/pacific_tree.h"

#include "aapl/aapl.h"
#include "aapl/sbus.h"
#include "aapl/spico.h"

#include <cmath>
#include <sstream>
#include <unordered_map>

using namespace std;
using namespace silicon_one::bit_utils;

namespace silicon_one
{

enum {
    SBUS_HBM_PLL_ADDR = 0x12,
    SBUS_HBM_ADDR = 0xFD,

    SBUS_SPARE_1_REG = 71,

    // Program repair type into F/W parameter - Repair mode : 0 = No repair, 1 = Hard repair, 2 = Soft repair
    HBM_MBIST_REPAIR_MODE_NONE = 0,
    HBM_MBIST_REPAIR_MODE_HARD = 1,
    HBM_MBIST_REPAIR_MODE_SOFT = 2,

    HBM_MAX_AVAGO_CHANNELS = 8,

    HBM_OPERATION_MAX_TIMEOUT = 5000,
    HBM_MBIST_TIMEOUT = 100000,

    PLL_LOCK_TIMEOUT = 500,

    MBIST_PLL_DIV = 32, // PLL divider for MBIST (should be run at 800MHz)

    DEFAULT_B_DIE_FREQUENCY = 1800,
    DEFAULT_X_DIE_FREQUENCY = 2000,

    LANE_REPAIR_MODE = 2, // Read hard repair = 2, not to read hard repairs = 1
};

static const size_t hbm_wide_channels[] = {0, 1, 6, 7};
static const size_t hbm_tall_channels[] = {2, 3, 4, 5};

struct hbm_config_data_t {
    float dfi_clock_period_ns;
    la_uint_t pll_freq;
    la_uint_t pll_div;
};

typedef std::unordered_map<la_uint_t, hbm_config_data_t> hbm_rate_to_config_t;

static const hbm_rate_to_config_t s_hbm_rate_to_config = {
    hbm_rate_to_config_t::value_type(1600, {1.25, 800, 32}),
    hbm_rate_to_config_t::value_type(1800, {1.11, 900, 36}),
    hbm_rate_to_config_t::value_type(2000, {1, 1000, 40}),
};

static inline bool
is_channel_valid(size_t channel)
{
    return (channel < array_size(hbm_wide_channels) + array_size(hbm_tall_channels));
}

static inline bool
is_wide_channel(size_t channel)
{
    const size_t* end = hbm_wide_channels + array_size(hbm_wide_channels);
    const size_t* it = find(hbm_wide_channels, end, channel);

    return (it != end);
}

static inline bool
is_tall_channel(size_t channel)
{
    const size_t* end = hbm_tall_channels + array_size(hbm_tall_channels);
    const size_t* it = find(hbm_tall_channels, end, channel);

    return (it != end);
}

la_hbm_handler_impl::la_hbm_handler_impl(la_device_impl_wptr device)
    : m_device(device), m_aapl_handler{nullptr, nullptr}, m_hbm_rate(0), m_pll_div(0), m_is_done(false), m_on_done_cb(nullptr)
{
    ll_device_sptr ll_dev = m_device->get_ll_device_sptr();
    m_device_revision = ll_dev->get_device_revision();
}

la_hbm_handler_impl::~la_hbm_handler_impl()
{
}

la_status
la_hbm_handler_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    bool does_hbm_exist;

    auto status = m_device->hbm_exists(does_hbm_exist);
    return_on_error(status);

    // Check HBM exists
    if (!does_hbm_exist) {
        return LA_STATUS_SUCCESS;
    }

    if ((m_device->m_device_mode == device_mode_e::STANDALONE) || (m_device->m_device_mode == device_mode_e::LINECARD)) {
        m_hbm_read_cycles = 512;
        m_hbm_write_cycles = 640;
    } else if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
        status = m_device->get_int_property(la_device_property_e::HBM_READ_CYCLES, m_hbm_read_cycles);
        return_on_error(status);
        status = m_device->get_int_property(la_device_property_e::HBM_WRITE_CYCLES, m_hbm_write_cycles);
        return_on_error(status);
    } else {
        m_hbm_read_cycles = 512;
        m_hbm_write_cycles = 512;
    }

    if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
        // Read LPM-HBM properties
        status = m_device->get_int_property(la_device_property_e::HBM_MIN_MOVE_TO_READ, m_hbm_min_move_to_read);
        return_on_error(status);
        status = m_device->get_int_property(la_device_property_e::HBM_LPM_FAVOR_MODE, m_hbm_lpm_favor_mode);
        return_on_error(status);
        status = m_device->get_bool_property(la_device_property_e::HBM_MOVE_TO_READ_ON_EMPTY, m_hbm_move_to_read_on_empty);
        return_on_error(status);
        status = m_device->get_bool_property(la_device_property_e::HBM_MOVE_TO_WRITE_ON_EMPTY, m_hbm_move_to_write_on_empty);
        return_on_error(status);
    } else {
        m_hbm_min_move_to_read = 0;
        m_hbm_lpm_favor_mode = 0; // No favor
        m_hbm_move_to_read_on_empty = 0;
        m_hbm_move_to_write_on_empty = 0;
    }
    status = m_device->get_int_property(la_device_property_e::HBM_PHY_T_RDLAT_OFFSET, m_hbm_phy_t_rdlat_offset);
    return_on_error(status);

    // Take out of reset HBM related blocks
    status = soft_reset();
    return_on_error(status);

    // Configure HBM related blocks
    status = initialize_mmu_general();
    return_on_error(status);

    for (size_t hbm = 0; hbm < NUM_HBM_INTERFACES; ++hbm) {
        status = m_device->get_hbm_aapl_handler(hbm, m_aapl_handler[hbm]);
        return_on_error(status);

        status = initialize_avago(hbm);
        return_on_error(status);
    }

    status = read_device_model_id();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::destroy()
{
    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::read_device_model_id()
{
    uint32_t device_model_id[NUM_HBM_INTERFACES];

    for (size_t hbm = 0; hbm < NUM_HBM_INTERFACES; ++hbm) {
        Avago_hbm_operation_results_t op_result;
        int rc = avago_hbm_launch_operation(
            m_aapl_handler[hbm], SBUS_HBM_ADDR, AVAGO_HBM_OP_READ_DEVICE_ID, &op_result, HBM_OPERATION_MAX_TIMEOUT);
        if (rc != 0) {
            log_err(HLD, "%s: result %d, global_error_code %d", __func__, rc, op_result.global_error_code);
            return LA_STATUS_EUNKNOWN;
        }

        uint32_t device_id_15_0 = avago_spico_int(m_aapl_handler[hbm], SBUS_HBM_ADDR, 0x32, 0x12);

        device_model_id[hbm] = device_id_15_0 & 0x7f;

        log_debug(HLD, "HBM on inteface %ld has model 0x%X", hbm, device_model_id[hbm]);
    }

    if (device_model_id[0] != device_model_id[1]) {
        log_warning(HLD, "HBM[0/1] model id mismatch %d/%d", device_model_id[0], device_model_id[1]);
    }

    m_device_model_id = device_model_id[0];

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::initialize_avago(size_t hbm)
{
    Aapl_t* aapl_handler = m_aapl_handler[hbm];

    // Configure sbus divider to 1 instead of 8
    avago_sbus_wr(aapl_handler, 0xFE, 10, 0);

    // FW upload
    la_status status = upload_firmware(hbm, m_device->m_hbm_fw_info.filepath.c_str());
    return_on_error(status);

    status = verify_firmware_version_and_build(hbm, m_device->m_hbm_fw_info.revision, m_device->m_hbm_fw_info.build_id);
    return_on_error(status);

    Avago_hbm_operation_results_t op_result;
    int rc = avago_hbm_launch_operation(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_OP_RESET, &op_result, HBM_OPERATION_MAX_TIMEOUT);

    if (rc != 0) {
        avago_print_operation_result("AVAGO_HBM_OP_RESET", rc, op_result);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::initialize_mmu_hbm_samsung(int t_rd_data_en,
                                                int almost_full_level,
                                                float dfi_clock_period_ns,
                                                int dbi_enable,
                                                int relax_percent)
{
    static_assert((size_t)hbm_chnl_4x_tall_hbm_timing_params_register::SIZE
                      == (size_t)hbm_chnl_4x_wide_hbm_timing_params_register::SIZE,
                  "hbm_chnl_4x_XXXX_hbm_timing_params_register SIZE does not match");
    static_assert((size_t)hbm_chnl_4x_tall_hbm_more_timing_parameters_register::SIZE
                      == (size_t)hbm_chnl_4x_wide_hbm_more_timing_parameters_register::SIZE,
                  "hbm_chnl_4x_XXXX_hbm_more_timing_parameters_register SIZE does not match");

    hbm_async_fifo_config_register async_fifo_cfg;
    hbm_hbm_config_register hbm_cfg;

    hbm_chnl_4x_tall_hbm_timing_params_register timing_reg;
    hbm_chnl_4x_tall_hbm_more_timing_parameters_register timing2_reg;

    async_fifo_cfg.fields.almost_full = almost_full_level;

    hbm_cfg.fields.hbm_pl = 2;
    hbm_cfg.fields.dbi_enable = dbi_enable;
    hbm_cfg.fields.ecc_check_enable = 1;
    hbm_cfg.fields.count_one_bit_ecc_as_error = 0;
    hbm_cfg.fields.check_rx_data_parity = 1;

    timing_reg.fields.phy_t_rddata_en = t_rd_data_en;
    timing_reg.fields.hbm_trcdrd = ceil((14.0 / dfi_clock_period_ns) * (1 + relax_percent / 100)); // tRCDRD. Samsung=14, Hynix=16
    timing_reg.fields.hbm_trcdwr = ceil((10.0 / dfi_clock_period_ns) * (1 + relax_percent / 100)); // tRCDWR, Samsung=10, Hynix=14
    timing_reg.fields.hbm_trrdl = ceil((6.0 / dfi_clock_period_ns) * (1 + relax_percent / 100));   // tRRDL, Samsung=6, Hynix=3
    if (timing_reg.fields.hbm_trrdl > 7) {
        timing_reg.fields.hbm_trrdl = 7;
    }

    // NOTE: Changing tRRDS has direct effect on B/W (cycles btwn 2 ACTIVATEs). Do not change past 4
    //   (4 does not work, but 5 seems not to give errors)
    // For B-die, if work with normal RL and tRTW, then need tRRDS=6
    // If work with expanded RL and tRTW, then can use tRRDS = 4, but will still get occasional errors that way
    // For X-die, use tRRDS=4
    if (m_device_model_id == HBM_MODEL_X_DIE) {
        timing_reg.fields.hbm_trrds = 4;
    } else {
        timing_reg.fields.hbm_trrds = 6;
    }

    // tRP, Samsung = 14, Hynix = 16 [precharge time]
    timing_reg.fields.hbm_trp = ceil((14.0 / dfi_clock_period_ns) * (1 + relax_percent / 100));

    // This is measured in clocks. It cannot be changed without directly affecting B/W
    timing_reg.fields.hbm_tccdl = 4; // tCCDL. Samsung = 4, Hynix = 4

    timing_reg.fields.hbm_tccds = 2; // This is measured in clocks.  It cannot be changed without directly affecting B/W

    // tWTRL, Samsung = 7.5 + 1, Hynix = max (5 nCK, 5ns + 1nCK). Add WL + BL/2 to data sheet value
    timing_reg.fields.hbm_twtrl = ceil((7.5 / dfi_clock_period_ns) * (1 + relax_percent / 100)) + 10;

    // tWTRS, Samsung = 2.5 + 1, Hynix = max (5 nCK, 4ns + 1nCK)
    timing_reg.fields.hbm_twtrs = ceil((2.5 / dfi_clock_period_ns) * (1 + relax_percent / 100)) + 10;

    // Looks like 25 is OK. Should be able to reduce to 22/23, but has no real effect on B/W
    timing_reg.fields.hbm_trtw = 22 + ceil((3.0 / dfi_clock_period_ns) * (1 + relax_percent / 100));

    timing_reg.fields.hbm_tras = ceil((33.0 / dfi_clock_period_ns) * (1 + relax_percent / 100)); // tRAS, Samsung = 33, Hynix = 29
    timing_reg.fields.hbm_wl = 7;

    // tRREFD, 8ns for both .Time from SINGLE_BANK_REFRESH to ACTIVATE
    timing_reg.fields.hbm_trrefd = ceil((8.0 / dfi_clock_period_ns) * (1 + relax_percent / 100));

    // tRFCSB, 160 for Samsung, 120 for Hynix. SINGLE_BANK_REFRESH command period
    timing_reg.fields.hbm_trfcsb = ceil((160.0 / dfi_clock_period_ns) * (1 + relax_percent / 100));

    // Even though this is given in ns, it cannot be smaller than 16 (for slower B/Ws). If it is larger than 16 (for > 2 Gbps),
    // Hynix mode must be used. Not yet supported
    timing2_reg.fields.hbm_tfaw = 16;
    timing2_reg.fields.hbm_trefi = ceil(3900.0 / dfi_clock_period_ns); // tREFI = 3.9us. Should NOT be relaxed

    // tWR, Samsung = 15 + 1nCK, Hynix = 16 + 1nCK
    timing2_reg.fields.hbm_twr = ceil((15.0 / dfi_clock_period_ns) * (1 + relax_percent / 100)) + 1;
    timing2_reg.fields.hbm_trtp = ceil(5.0 * (1 + relax_percent / 100)); // tRTPL, Samsung = 5nCK, Hynix = max(5tCK,5ns+2tCK)
    // Looks like tRTPL has no effect on errors, so don't relax
    timing2_reg.fields.hbm_trtp = 5;

    lld_register_value_list_t reg_val_list;

    for (size_t ch = 0; ch < m_device->m_pacific_tree->hbm->lo->async_fifo_config->size(); ch++) {
        // HBM LO
        reg_val_list.push_back({(*m_device->m_pacific_tree->hbm->lo->async_fifo_config)[ch], async_fifo_cfg});
        reg_val_list.push_back({(*m_device->m_pacific_tree->hbm->lo->hbm_config)[ch], hbm_cfg});
        // HBM HI
        reg_val_list.push_back({(*m_device->m_pacific_tree->hbm->hi->async_fifo_config)[ch], async_fifo_cfg});
        reg_val_list.push_back({(*m_device->m_pacific_tree->hbm->hi->hbm_config)[ch], hbm_cfg});
    }

    for (size_t i = 0; i < array_size(hbm_wide_channels); i++) {
        reg_val_list.push_back({(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->hbm_timing_params), timing_reg});
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->hbm_more_timing_parameters), timing2_reg});
    }

    for (size_t i = 0; i < array_size(hbm_tall_channels); i++) {
        reg_val_list.push_back({(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->hbm_timing_params), timing_reg});
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->hbm_more_timing_parameters), timing2_reg});
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::initialize_mmu_general()
{
    bit_vector rd_to_wr_arb_criteria;
    bit_vector wr_to_rd_arb_criteria;
    bit_vector hbm_chnl_4x_spare_register;

    // This is time-only config

    static_assert((size_t)hbm_chnl_4x_tall_hbm_rd_to_wr_arbitration_config_register::SIZE
                      == (size_t)hbm_chnl_4x_wide_hbm_rd_to_wr_arbitration_config_register::SIZE,
                  "hbm_chnl_4x_XXXX_hbm_rd_to_wr_arbitration_config_register SIZE does not match");
    static_assert((size_t)hbm_chnl_4x_tall_hbm_wr_to_rd_arbitration_config_register::SIZE
                      == (size_t)hbm_chnl_4x_wide_hbm_wr_to_rd_arbitration_config_register::SIZE,
                  "hbm_chnl_4x_XXXX_hbm_wr_to_rd_arbitration_config_register SIZE does not match");
    static_assert((size_t)hbm_chnl_4x_tall_channel_fifo_sizes_register::SIZE
                      == (size_t)hbm_chnl_4x_wide_channel_fifo_sizes_register::SIZE,
                  "hbm_chnl_4x_XXXX_channel_fifo_sizes_register SIZE does not match");

    static_assert((size_t)hbm_chnl_4x_tall_mmu_bank_arbitration_register::SIZE
                      == (size_t)hbm_chnl_4x_wide_mmu_bank_arbitration_register::SIZE,
                  "hbm_chnl_4x_XXXX_mmu_bank_arbitration_register SIZE does not match");

    hbm_chnl_4x_tall_hbm_rd_to_wr_arbitration_config_register rd_to_wr_cfg;
    hbm_chnl_4x_tall_hbm_wr_to_rd_arbitration_config_register wr_to_rd_cfg;
    hbm_chnl_4x_tall_channel_fifo_sizes_register channel_fifo_sizes;
    hbm_chnl_4x_tall_mmu_bank_arbitration_register mmu_bank_arbitration;

    rd_to_wr_cfg.fields.rd_total_cycles = m_hbm_read_cycles;
    wr_to_rd_cfg.fields.wr_total_cycles = m_hbm_write_cycles;
    rd_to_wr_cfg.fields.move_to_wr_on_empty = m_hbm_move_to_write_on_empty;
    wr_to_rd_cfg.fields.move_to_rd_on_empty = m_hbm_move_to_read_on_empty;
    wr_to_rd_cfg.fields.min_move_to_rd_requests = m_hbm_min_move_to_read;
    wr_to_rd_cfg.fields.move_to_rd_if_stuck = 0;
    channel_fifo_sizes.fields.read_fifo_size = 0x1F;               // Max
    channel_fifo_sizes.fields.write_fifo_size = 16;                // Default
    mmu_bank_arbitration.fields.rd_fifo_priority_threshold = 0x1F; // Max
    mmu_bank_arbitration.fields.wr_fifo_priority_threshold = 12;   // Default

    // Must set LPM priority to strict  (only works that way due to bug)
    int mmu_lpm_read_arbitration = 1;
    lld_register_value_list_t reg_val_list;

    rd_to_wr_arb_criteria.set_bits(127, 64, bit_vector("0xFFFFFFFFFFFFFFFF"));
    if (m_hbm_lpm_favor_mode == NO_FAVOR_LPM) { // No favor
        wr_to_rd_arb_criteria.set_bits(127, 64, bit_vector("0xFFFFFFFFFFFFFFFF"));
    } else { // favor LPM
        wr_to_rd_arb_criteria.set_bits(127, 0, bit_vector("0xFFFFFFFFFFFFFFFFFFFF0000FFFF0000"));
    }

    if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
        // Spare register  (default is 63:0 all 1s)
        // Bit 0 : lpm_eco_chicken_bit (rd_channel)
        // bit 1 : delay_move_to_rd (channel_arb) (wait min 256 cycles)
        // bit 64 : lpm_rd_priority_eco_sel (rd_channel, use LPM entries for total_entries)
        bool is_favor_lpm_min_write = (m_hbm_lpm_favor_mode == FAVOR_LPM_MIN_WRITE);
        bool is_favor_lpm = (m_hbm_lpm_favor_mode != NO_FAVOR_LPM);
        hbm_chnl_4x_spare_register.set_bit(0, true /* lpm_eco_chicken_bit */);
        hbm_chnl_4x_spare_register.set_bit(1, is_favor_lpm_min_write);
        hbm_chnl_4x_spare_register.set_bits(63, 2, bit_utils::ones(62));
        hbm_chnl_4x_spare_register.set_bit(64, is_favor_lpm);
    }

    for (size_t i = 0; i < array_size(hbm_wide_channels); i++) {
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->hbm_rd_to_wr_arbitration_criteria),
             rd_to_wr_arb_criteria});
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->hbm_wr_to_rd_arbitration_criteria),
             wr_to_rd_arb_criteria});

        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->hbm_rd_to_wr_arbitration_config), rd_to_wr_cfg});
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->hbm_wr_to_rd_arbitration_config), wr_to_rd_cfg});

        reg_val_list.push_back({(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->mmu_lpm_read_arbitration),
                                mmu_lpm_read_arbitration});

        if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
            reg_val_list.push_back(
                {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->spare_reg), hbm_chnl_4x_spare_register});
            reg_val_list.push_back(
                {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->channel_fifo_sizes), channel_fifo_sizes});
            reg_val_list.push_back(
                {(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->mmu_bank_arbitration), mmu_bank_arbitration});
        }
    }

    for (size_t i = 0; i < array_size(hbm_tall_channels); i++) {
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->hbm_rd_to_wr_arbitration_criteria),
             rd_to_wr_arb_criteria});
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->hbm_wr_to_rd_arbitration_criteria),
             wr_to_rd_arb_criteria});

        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->hbm_rd_to_wr_arbitration_config), rd_to_wr_cfg});
        reg_val_list.push_back(
            {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->hbm_wr_to_rd_arbitration_config), wr_to_rd_cfg});

        reg_val_list.push_back({(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->mmu_lpm_read_arbitration),
                                mmu_lpm_read_arbitration});

        if ((m_device_revision == la_device_revision_e::PACIFIC_B0) || (m_device_revision == la_device_revision_e::PACIFIC_B1)) {
            reg_val_list.push_back(
                {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->spare_reg), hbm_chnl_4x_spare_register});
            reg_val_list.push_back(
                {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->channel_fifo_sizes), channel_fifo_sizes});
            reg_val_list.push_back(
                {(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->mmu_bank_arbitration), mmu_bank_arbitration});
        }
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::soft_reset()
{
    // We are called *after* soft_reset_configuration was deasserted then asserted on
    // hbm.lo, hbm.hi, hbm->chnl[], mmu, mmu_buff

    lld_register_value_list_t reg_val_list;

    // HBM LO
    reg_val_list.push_back({(m_device->m_pacific_tree->hbm->lo->soft_reset_configuration), 1});

    // HBM HI
    reg_val_list.push_back({(m_device->m_pacific_tree->hbm->hi->soft_reset_configuration), 1});

    reg_val_list.push_back({(m_device->m_pacific_tree->mmu->soft_reset_configuration), 1});
    reg_val_list.push_back({(m_device->m_pacific_tree->mmu_buff->soft_reset_configuration), 1});

    for (size_t i = 0; i < array_size(hbm_wide_channels); i++) {
        reg_val_list.push_back({(m_device->m_pacific_tree->hbm->chnl[hbm_wide_channels[i]]->wide->soft_reset_configuration), 1});
    }

    for (size_t i = 0; i < array_size(hbm_tall_channels); i++) {
        reg_val_list.push_back({(m_device->m_pacific_tree->hbm->chnl[hbm_tall_channels[i]]->tall->soft_reset_configuration), 1});
    }

    la_status status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    status = soft_reset_mmu_buff();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::soft_reset_mmu_buff()
{
    // Remove buffer 0xfffff from MMU allocator due to HW bug

    // This function assumes that the MMU buffer is out of reset, this is required to be able to write memories.

    lld_register_value_list_t reg_val_list;
    lld_memory_value_list_t mem_val_list;
    lld_memory_line_value_list_t mem_line_val_list;

    const lld_memory_array_container& mmu_buffer_allocator(*m_device->m_pacific_tree->mmu_buff->mmu_buffer_allocator);
    size_t num_memory_banks = mmu_buffer_allocator.size();

    lld_memory_scptr last_mmu_buffer_allocator = (*m_device->m_pacific_tree->mmu_buff->mmu_buffer_allocator)[num_memory_banks - 1];

    size_t num_entries = mmu_buffer_allocator.get_desc()->entries;
    size_t mmu_buffer_allocator_width = mmu_buffer_allocator.get_desc()->width_bits;

    // Make the last memory bank allocation flexible and de-allocate the last buffer due to HW bug.
    bit_vector allocatable = bit_vector::ones(mmu_buffer_allocator_width);
    mem_val_list.push_back({last_mmu_buffer_allocator, allocatable});

    bit_vector not_allocatable = bit_vector::ones(mmu_buffer_allocator_width);
    not_allocatable.set_bit(mmu_buffer_allocator_width - 1, false);

    mem_line_val_list.push_back({{last_mmu_buffer_allocator, num_entries - 1}, not_allocatable});

    la_status status = lld_write_memory_list(m_device->m_ll_device, mem_val_list);
    return_on_error(status);

    status = lld_write_memory_line_list(m_device->m_ll_device, mem_line_val_list);
    return_on_error(status);

    reg_val_list.push_back({(*m_device->m_pacific_tree->mmu_buff->buffer_alloc_mode)[num_memory_banks - 1], 1 /* flexible */});

    // After all memory writes, toggle the soft reset.
    reg_val_list.push_back({(m_device->m_pacific_tree->mmu->soft_reset_configuration), 0});
    reg_val_list.push_back({(m_device->m_pacific_tree->mmu_buff->soft_reset_configuration), 0});
    reg_val_list.push_back({(m_device->m_pacific_tree->mmu->soft_reset_configuration), 1});
    reg_val_list.push_back({(m_device->m_pacific_tree->mmu_buff->soft_reset_configuration), 1});

    // Set the valid_rows and total_free_buffers: all entries to '1'
    bit_vector valid_memory_lines_bv = bit_vector::ones(num_entries);
    const uint64_t* valid_memory_lines = (const uint64_t*)valid_memory_lines_bv.byte_array();
    mmu_buff_cpu_occupy_buffers_register cpu_occupy_buffers_val = {.u8 = {0}};
    cpu_occupy_buffers_val.fields.set_valid_memory_lines(valid_memory_lines);
    cpu_occupy_buffers_val.fields.total_free_buffers = 65535; // Total number of buffers - 1 (64K - 1)

    reg_val_list.push_back(
        {(*m_device->m_pacific_tree->mmu_buff->cpu_occupy_buffers)[num_memory_banks - 1], cpu_occupy_buffers_val});

    status = lld_write_register_list(m_device->m_ll_device, reg_val_list);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::avago_mbist(size_t hbm)
{
    avago_sbus_wr(m_aapl_handler[hbm], SBUS_HBM_ADDR, 0, 3);
    avago_sbus_wr(m_aapl_handler[hbm], SBUS_HBM_ADDR, 0, 5);

    std::this_thread::sleep_for(std::chrono::milliseconds(10));

    int rd_data = avago_sbus_rd(m_aapl_handler[hbm], SBUS_HBM_ADDR, 0);

    // pass is bit 3
    int bist_pass = rd_data & 8;
    if (bist_pass == 0) {
        log_err(HLD, "HBM Spico BIST failed (0x%X)", rd_data);
    } else {
        log_err(HLD, "HBM Spico BIST passed (0x%X)", rd_data);
    }

    // Must reset the BIST registers afterwards
    avago_sbus_wr(m_aapl_handler[hbm], SBUS_HBM_ADDR, 0, 0);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::samsung_mbist(size_t hbm, bool repair)
{
    Aapl_t* aapl_handler = m_aapl_handler[hbm];

    // Configure sbus divider to 1 instead of 8
    avago_sbus_wr(aapl_handler, 0xFE, 10, 0);

    // Must set HBM CK freq to 800 MHz to run MBIST. This is true also for X-die (Aquabolt)
    la_status status = set_hbm_pll(hbm, MBIST_PLL_DIV);
    return_on_error(status);

    // MBIST FW upload
    status = upload_firmware(hbm, m_device->m_hbm_mbist_fw_info.filepath.c_str());
    return_on_error(status);

    status = verify_firmware_version_and_build(hbm, m_device->m_hbm_mbist_fw_info.revision, m_device->m_hbm_mbist_fw_info.build_id);
    return_on_error(status);

    Avago_hbm_operation_results_t op_result;
    int rc;

    rc = avago_hbm_launch_operation(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_OP_RESET, &op_result, HBM_OPERATION_MAX_TIMEOUT);
    if (rc != 0) {
        avago_print_operation_result("AVAGO_HBM_OP_RESET", rc, op_result);
        return LA_STATUS_EUNKNOWN;
    }

    rc = avago_hbm_launch_operation(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_OP_RESET_HBM, &op_result, HBM_OPERATION_MAX_TIMEOUT);
    if (rc != 0) {
        avago_print_operation_result("AVAGO_HBM_OP_RESET_HBM", rc, op_result);
        return LA_STATUS_EUNKNOWN;
    }

    // Program repair type into F/W parameter - Repair mode : 0 = No repair, 1 = Hard repair, 2 = Soft repair
    avago_hbm_set_parameter(
        aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MBIST_REPAIR_MODE, repair ? HBM_MBIST_REPAIR_MODE_SOFT : HBM_MBIST_REPAIR_MODE_NONE);

    // Program BIST pattern into F/W parameter - Pattern 0 = SCAN, Pattern 1 = MARCH
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MBIST_PATTERN, 0);

    // Run MBIST
    rc = avago_hbm_launch_operation(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_OP_RUN_SAMSUNG_MBIST, &op_result, HBM_MBIST_TIMEOUT);
    if (rc != 0) {
        avago_print_operation_result("AVAGO_HBM_OP_RUN_SAMSUNG_MBIST", rc, op_result);
        return LA_STATUS_EUNKNOWN;
    }

    uint32_t rd_data = avago_sbus_rd(aapl_handler, 1, SBUS_SPARE_1_REG);
    uint32_t repairs = rd_data & 0xFFFF;
    uint32_t mbist_cycles = (rd_data >> 16) & 0xFFFF;
    log_info(HLD,
             "%s HBM_SAMSUNG_MBIST PASS result: global_error_code %d, cycles %d, repairs %d.",
             to_string().c_str(),
             op_result.global_error_code,
             mbist_cycles,
             repairs);

    // Revert PLL settings to correct PLL.
    status = set_hbm_pll(hbm, m_pll_div);

    return LA_STATUS_SUCCESS;
}

void
la_hbm_handler_impl::avago_print_operation_result(const char* op_name, int rc, Avago_hbm_operation_results_t& op_result)
{
    if (rc == 0) {
        return;
    }

    log_err(HLD, "%s %s: return %d, global_error_code 0x%X.", to_string().c_str(), op_name, rc, op_result.global_error_code);
    for (int i = 0; i < HBM_MAX_AVAGO_CHANNELS; i++) {
        if (op_result.channel_error_code[i] != 0) {
            log_err(HLD,
                    "%s %s channel[%d] result: operation = 0x%X -> result 0x%X.",
                    to_string().c_str(),
                    op_name,
                    i,
                    op_result.channel_operation_code[i],
                    op_result.channel_error_code[i]);
        }
    }
}

la_status
la_hbm_handler_impl::interface_mbist(size_t hbm)
{
    // Configure sbus divider to 1 instead of 8
    avago_sbus_wr(m_aapl_handler[hbm], 0xFE, 10, 0);

    // FW upload
    la_status status = upload_firmware(hbm, m_device->m_hbm_fw_info.filepath.c_str());
    return_on_error(status);

    status = verify_firmware_version_and_build(hbm, m_device->m_hbm_fw_info.revision, m_device->m_hbm_fw_info.build_id);
    return_on_error(status);

    status = set_hbm_pll(hbm, m_pll_div);

    Avago_hbm_operation_results_t op_result;
    int rc = avago_hbm_launch_operation(
        m_aapl_handler[hbm], SBUS_HBM_ADDR, AVAGO_HBM_OP_POWER_ON_FLOW, &op_result, HBM_OPERATION_MAX_TIMEOUT);
    if (rc != 0) {
        avago_print_operation_result("AVAGO_HBM_OP_POWER_ON_FLOW", rc, op_result);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::activate()
{
    bool does_hbm_exist;

    la_status status = m_device->hbm_exists(does_hbm_exist);
    return_on_error(status);

    // Check HBM exists
    if (!does_hbm_exist) {
        return LA_STATUS_SUCCESS;
    }

    int hbm_rate = 0;
    m_device->get_int_property(la_device_property_e::HBM_FREQUENCY, hbm_rate);

    if (hbm_rate == 0) {
        // use default
        if (m_device_model_id == HBM_MODEL_X_DIE) {
            m_hbm_rate = DEFAULT_X_DIE_FREQUENCY;
        } else {
            m_hbm_rate = DEFAULT_B_DIE_FREQUENCY;
        }
    } else {
        m_hbm_rate = hbm_rate;
    }

    hbm_rate_to_config_t::const_iterator config = s_hbm_rate_to_config.find(m_hbm_rate);

    if (config == s_hbm_rate_to_config.end()) {
        // Not found
        return LA_STATUS_EINVAL;
    }

    m_pll_div = config->second.pll_div;

    // hbm_freq is freq of 2X clock [i.e. 2 GHz]
    // Used ONLY to program into F/W as a parameter, which is used for LFSR testing
    float dfi_clock_period_ns = config->second.dfi_clock_period_ns;

    int dbi_enable = 1;    // For debug use. Don't change
    int relax_percent = 0; // relax_percent is, for the moment, only for debug. It may be needed for production at some point

    int t_rd_data_en;
    int almost_full_level;
    if (m_device_model_id == HBM_MODEL_X_DIE) {
        t_rd_data_en = 24;

        // X-die HBM frequency assumed to be 1800MHz.
        switch (m_device->m_device_frequency_int_khz) {
        case 1050000:
            almost_full_level = 58;
            break;

        case 1100000:
            almost_full_level = 55;
            break;

        case 1200000:
            almost_full_level = 50;
            break;

        default:
            almost_full_level = 50;
            break;
        }
    } else {
        t_rd_data_en = 20;
        almost_full_level = 44;

        // B-die HBM frequency assumed to be 1600MHz.
        switch (m_device->m_device_frequency_int_khz) {
        case 1050000:
            almost_full_level = 52;
            break;

        case 1100000:
            almost_full_level = 49;
            break;

        case 1200000:
            almost_full_level = 44;
            break;

        default:
            almost_full_level = 44;
            break;
        }
    }

    for (size_t hbm = 0; hbm < NUM_HBM_INTERFACES; ++hbm) {
        status = set_hbm_pll(hbm, m_pll_div);
        return_on_error(status);
    }

    status = initialize_mmu_hbm_samsung(t_rd_data_en, almost_full_level, dfi_clock_period_ns, dbi_enable, relax_percent);
    return_on_error(status);

    for (size_t hbm = 0; hbm < NUM_HBM_INTERFACES; ++hbm) {
        status = configure_fw_parameters(hbm, hbm_rate);
        return_on_error(status);

        status = configure_fw_mode_parameters(hbm, dfi_clock_period_ns, dbi_enable, relax_percent);
        return_on_error(status);

        avago_hbm_set_parameter(m_aapl_handler[hbm], SBUS_HBM_ADDR, AVAGO_HBM_POWER_ON_LANE_REPAIR_MODE, LANE_REPAIR_MODE);
        avago_hbm_set_parameter(m_aapl_handler[hbm], SBUS_HBM_ADDR, AVAGO_HBM_T_RDLAT_OFFSET, m_hbm_phy_t_rdlat_offset);

        Avago_hbm_operation_results_t op_result;
        int rc = avago_hbm_launch_operation(
            m_aapl_handler[hbm], SBUS_HBM_ADDR, AVAGO_HBM_OP_POWER_ON_FLOW, &op_result, HBM_OPERATION_MAX_TIMEOUT);
        if (rc != 0) {
            avago_print_operation_result("AVAGO_HBM_OP_POWER_ON_FLOW", rc, op_result);
        }
    }

    status = read_device_model_id();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::configure_fw_parameters(size_t hbm, int hbm_freq_in_mhz)
{
    Aapl_t* aapl_handler = m_aapl_handler[hbm];

    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_DIV_MODE, 0); // div_mode = 0, DFI i/f is 1:1
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_FREQ, hbm_freq_in_mhz);
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_TINIT1_CYCLES, 50000);   // tINIT1 = 200us, given in terms
                                                                                            // of 8 x spico_period x cycles
                                                                                            // spico_period = 4ns
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_TINIT2_CYCLES, 3);       // tINIT2 = 10ns
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_TINIT3_CYCLES, 15625);   // tINIT3 = 500us
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_TINIT4_CYCLES, 1);       // tINIT4 = 10nCK
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_TINIT5_CYCLES, 50);      // tINIT5 = 200ns
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_SAVE_RESTORE_CONFIG, 0); // save_restore_config. When
                                                                                            // exiting mission mode, use the
                                                                                            // mode_register values from F/W
                                                                                            // to reprogram when go back to
                                                                                            // mission mode
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_CKE_EXIT_STATE, 1);      // set CKE to 1 when exiting test mode
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_TUPDMRS, 1250); // tUPDMRS is 250 WRCK cycles for Samsung,
                                                                                   // where WRCK freq is 50 MHz
                                                                                   // total of 250 * 20 ns = 5us
    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::configure_fw_mode_parameters(size_t hbm, float dfi_clock_period_ns, int dbi_enable, int relax_percent)
{
    // Relax_percent is percentage relaxation we give for timing parameters
    int mr0 = dbi_enable == 0 ? 0x74 : 0x77;

    // MR1
    // NOTE: The tWR here is used for auto-precharge (which we use).
    // HBM does auto-precharge either tRAS (from MR3) or tWR + WL + BL/2 cycles
    int mr1 = (15 / dfi_clock_period_ns) * (1 + relax_percent / 100) + 1;
    mr1 &= 0x1F;
    mr1 |= 4 << 5; // Driver strength of 18ma recommended for 2GBps

    // MR2: RL and WL
    int rl = 0;
    int mr2 = 6; // WL = 7
    if (m_device_model_id == HBM_MODEL_X_DIE) {
        rl = 24;
    } else {
        rl = 20;
    }

    // NOTE : Need to set the tRddataEn according to the RL

    mr2 |= (rl - 2) << 3; // The value to set is (RL - 2)

    // MR 3, RAS, bank group, BL=4
    // NOTE the tRAS here is used for auto-precharge. HBM does auto-precharge after WRITE/READ if tRAS has been satisfied
    int mr3 = (33 / dfi_clock_period_ns) * (1 + relax_percent / 100);
    mr3 &= 0x3F;
    mr3 |= 1 << 6; // enable bank groups
    mr3 |= 1 << 7; // BL = 4

    // MR 4
    int mr4 = 3;   // enable ECC
    mr4 |= 2 << 2; // PL = 2

    Aapl_t* aapl_handler = m_aapl_handler[hbm];

    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER0, mr0); // MR0 , set parity and DBI enable
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER1, mr1);
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER2, mr2);
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER3, mr3);
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER4, mr4);
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER5, 0); // Not used
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER6, 0); // Implicit precharge not used
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER7, 0); // not used (Test functions)
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_MODE_REGISTER8, 1); // DA[28] lockout
    avago_hbm_set_parameter(aapl_handler, SBUS_HBM_ADDR, AVAGO_HBM_PARITY_LATENCY, 2); // PL = 2

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::run_mbist(bool repair)
{
    bool does_hbm_exist;

    la_status status = m_device->hbm_exists(does_hbm_exist);
    return_on_error(status);

    // Check HBM exists
    if (!does_hbm_exist) {
        log_debug(HLD, "%s no HBM, skip BIST", to_string().c_str());
        return LA_STATUS_SUCCESS;
    }

    for (size_t hbm = 0; hbm < NUM_HBM_INTERFACES; ++hbm) {
        status = samsung_mbist(hbm, repair);
        return_on_error(status);

        // NOTE: Must load regular FW after this
        status = initialize_avago(hbm);
        return_on_error(status);

        /* TODO: Fix and validate interface MBIST */
    }

    status = read_device_model_id();
    return_on_error(status);

    status = activate();
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::read_error_counters(size_t hbm_interface,
                                         size_t channel_id,
                                         la_hbm_handler::error_counters& out_err_counters) const
{
    if (hbm_interface >= NUM_HBM_INTERFACES) {
        return LA_STATUS_EINVAL;
    }

    if (channel_id >= NUM_HBM_CHANNELS) {
        return LA_STATUS_EINVAL;
    }

    lld_register_scptr reg = (hbm_interface == 0 ? (*m_device->m_pacific_tree->hbm->lo->hbm_error_counters)[channel_id]
                                                 : (*m_device->m_pacific_tree->hbm->hi->hbm_error_counters)[channel_id]);

    hbm_hbm_error_counters_register error_counters;
    la_status status = m_device->m_ll_device->read_register(*reg, error_counters);
    return_on_error(status);

    out_err_counters.write_data_parity = error_counters.fields.wr_data_parity_errors;
    out_err_counters.addr_parity = error_counters.fields.addr_parity_errors;
    out_err_counters.one_bit_ecc = error_counters.fields.one_bit_ecc_errors;
    out_err_counters.two_bit_ecc = error_counters.fields.two_bit_ecc_errors;
    out_err_counters.read_data_parity = error_counters.fields.rd_data_parity_errors;

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::upload_firmware(const char* file_path)
{
    for (size_t hbm = 0; hbm < NUM_HBM_INTERFACES; ++hbm) {
        la_status rc = upload_firmware(hbm, file_path);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::upload_firmware(size_t hbm, const char* file_path)
{
    Aapl_t* aapl_handler = m_aapl_handler[hbm];
    int rom_size = -1, *rom;

    if (avago_load_rom_from_file(aapl_handler, file_path, &rom_size, &rom) == 0) {
        avago_sbus_wr(aapl_handler, SBUS_HBM_ADDR, 1, 0xc0);       // Place SPICO into Reset and Enable off.
                                                                   // Sbus controls reset and enable
        avago_sbus_wr(aapl_handler, SBUS_HBM_ADDR, 1, 0x240);      // Remove Reset, Enable off, IMEM_CNTL_EN on
        avago_sbus_wr(aapl_handler, SBUS_HBM_ADDR, 3, 0x80000000); // Set starting IMEM address for burst
                                                                   // (this starts from addr 0, the "8" is write_en for IMEM)

        int data_writes = rom_size;
        int rom_writes = rom_size / 3 + 1;
        for (int fw_line = 0; fw_line < rom_writes; fw_line++) {
            int values = data_writes > 3 ? 3 : data_writes;
            int data = values << 30;
            for (int j = 0; j < values; j++) {
                data |= (rom[fw_line * 3 + j] & 0x3FF) << (j * 10);
            }
            data_writes -= values;
            avago_sbus_wr(aapl_handler, SBUS_HBM_ADDR, 0x14, data);
        }

        avago_sbus_wr(aapl_handler, SBUS_HBM_ADDR, 0x01, 0x40); // Set IMEM_CNTL_EN off (i.e. Sbus no longer controls imem)
        // sbus keeps control of spico_reset and spico_enable, which are bits 7 and 8 of this register
        avago_sbus_wr(aapl_handler, SBUS_HBM_ADDR, 0x16, 0xc0000); // Turn ECC on
        avago_sbus_wr(aapl_handler, SBUS_HBM_ADDR, 0x01, 0x140);   // Set SPICO_ENABLE on

        aapl_free(aapl_handler, rom, __func__);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::get_firmware_version_id(la_uint_t& out_fw_id)
{
    return get_firmware_version_id(0, out_fw_id);
}

la_status
la_hbm_handler_impl::get_firmware_version_id(size_t hbm, la_uint_t& out_fw_id)
{
    out_fw_id = avago_spico_int(m_aapl_handler[hbm], SBUS_HBM_ADDR, 0, 0);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::get_firmware_build_id(la_uint_t& out_build_id)
{
    return get_firmware_build_id(0, out_build_id);
}

la_status
la_hbm_handler_impl::get_firmware_build_id(size_t hbm, la_uint_t& out_build_id)
{
    out_build_id = avago_spico_int(m_aapl_handler[hbm], SBUS_HBM_ADDR, 1, 0);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::verify_firmware_version_and_build(size_t hbm, la_uint_t fw_id, la_uint_t build_id)
{
    // Check FW
    la_uint_t rd_fw_id;
    la_uint_t rd_build_id;
    la_status status = get_firmware_version_id(hbm, rd_fw_id);
    return_on_error(status);

    status = get_firmware_build_id(hbm, rd_build_id);
    return_on_error(status);

    if ((rd_fw_id != fw_id) || (rd_build_id != build_id)) {
        log_err(HLD, "HBM on inteface %ld has wrong firmware: revision 0x%X, build 0x%X", hbm, rd_fw_id, rd_build_id);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::set_pll(size_t hbm, uint pll_id, bool do_reset, bool fbdiv_23, la_uint_t divider, la_uint_t pllout_divcnt)
{
    Aapl_t* aapl_handler = m_aapl_handler[hbm];

    // currently only support 800 MHz, 900 MHz , 1000 MHz. This is DFI freq!!

    // Two step process:
    // 1. Put PLL into reset and configure
    // 2. Take PLL out of reset

    if (do_reset) {
        uint64_t rd_data = avago_sbus_rd(aapl_handler, pll_id, 1);
        bit_utils::set_bit(&rd_data, 14, 1); // NRESET_GATE
        avago_sbus_wr(aapl_handler, pll_id, 1, (uint)rd_data);
    }

    uint64_t rd_data = avago_sbus_rd(aapl_handler, pll_id, 0);
    bit_utils::set_bit(&rd_data, 0, 1);  // SBUS_OVERRIDE
    bit_utils::set_bit(&rd_data, 1, 0);  // NRESET
    bit_utils::set_bit(&rd_data, 2, 1);  // PLL ENABLE
    bit_utils::set_bit(&rd_data, 4, 0);  // REFCLK_BYPASS
    bit_utils::set_bit(&rd_data, 16, 1); // SNAIL_CAL_EN

    avago_sbus_wr(aapl_handler, pll_id, 0, (uint)rd_data);

    rd_data = avago_sbus_rd(aapl_handler, pll_id, 3);

    rd_data = bit_utils::set_bits(rd_data, 5, 0, 1);         // PLL_REFCNT
    bit_utils::set_bit(&rd_data, 18, fbdiv_23);              // FBDIV_23
    rd_data = bit_utils::set_bits(rd_data, 26, 19, divider); // PLL_REFCNT

    avago_sbus_wr(aapl_handler, pll_id, 3, (uint)rd_data);

    rd_data = avago_sbus_rd(aapl_handler, pll_id, 4);
    rd_data = bit_utils::set_bits(rd_data, 7, 2, pllout_divcnt); // PLLOUT_DIVCNT

    avago_sbus_wr(aapl_handler, pll_id, 4, (uint)rd_data);

    // Take PLL out of reset
    rd_data = avago_sbus_rd(aapl_handler, pll_id, 0);
    bit_utils::set_bit(&rd_data, 1, 1); // NRESET

    avago_sbus_wr(aapl_handler, pll_id, 0, (uint)rd_data);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::get_pll_lock(size_t hbm, uint pll_id, bool& out_pll_lock)
{
    out_pll_lock = false;

    for (size_t i = 0; !out_pll_lock && i < PLL_LOCK_TIMEOUT; i++) {
        uint rd_data = avago_sbus_rd(m_aapl_handler[hbm], pll_id, 7);

        out_pll_lock = rd_data & 1;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::set_hbm_pll(size_t hbm, la_uint_t divider)
{
    la_status status = set_pll(hbm, SBUS_HBM_PLL_ADDR, /*do_reset*/ false, /*fbdiv_23*/ true, divider, /*pllout_divcnt*/ 3);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "Failed to set PLL to divider %d", divider);
        return status;
    }

    bool pll_lock;
    status = get_pll_lock(hbm, SBUS_HBM_PLL_ADDR, pll_lock);
    if (status || !pll_lock) {
        log_err(HLD, "Failed PLL lock on divider %d", divider);
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::set_die_ieee1500_enabled(bool enabled)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
la_hbm_handler_impl::get_die_ieee1500_enabled() const
{
    return false;
}

la_status
la_hbm_handler_impl::die_ieee1500_write(size_t hbm_interface,
                                        uint32_t reg_addr,
                                        uint32_t channel_addr,
                                        size_t width_bits,
                                        const bit_vector& in_bv)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::die_ieee1500_read(size_t hbm_interface,
                                       uint32_t reg_addr,
                                       uint32_t channel_addr,
                                       size_t width_bits,
                                       bool reverse,
                                       bit_vector& out_bv)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::set_rate_limit(const la_rate_t rate_limit)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

void
la_hbm_handler_impl::get_rate_limit(la_rate_t& out_rate_limit) const
{
    // Not implemented
    return;
}

la_status
la_hbm_handler_impl::start_rate_measurement(const std::chrono::seconds duration)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
la_hbm_handler_impl::is_rate_measurement_completed() const
{
    // Not implemented
    return false;
}

la_status
la_hbm_handler_impl::read_rate(bool clear_on_read, la_rate_t& out_rate)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

void
la_hbm_handler_impl::register_read_cb(on_done_function_t on_done_cb)
{
    // Not implemented
}

la_status
la_hbm_handler_impl::check_dram_buffer_errors(vector<dram_corrupted_buffer>& out_errors)
{
    vector<uint32_t> error_buffers;

    // Read the list of error buffers. They are cleared on read.
    for (size_t i = 0; i < m_device->m_pacific_tree->mmu->error_buffers->size(); ++i) {
        mmu_error_buffers_register val{{0}};
        la_status rc = m_device->m_ll_device->read_register(*(*m_device->m_pacific_tree->mmu->error_buffers)[i], val);
        return_on_error(rc);

        if (val.fields.error_buffer_valid) {
            error_buffers.push_back(val.fields.error_buffer); // 20-bit integeter
        }
    }

    // Retrieve the more detailed error info for each error_buffer
    for (auto error_buffer : error_buffers) {
        dram_corrupted_buffer info{};
        la_status rc = check_dram_buffer_error(error_buffer, info);
        return_on_error(rc);

        out_errors.push_back(info);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::check_dram_buffer_error(uint32_t dram_buffer, dram_corrupted_buffer& out_error)
{
    log_debug(HLD, "%s: dram_buffer=0x%x", __func__, dram_buffer);

    size_t row = get_bits(dram_buffer, 15, 2);
    size_t col = get_bits(dram_buffer, 19, 16);

    size_t channel_base = 0;
    channel_base = set_bits(channel_base, 1, 0, get_bits(dram_buffer, 5, 4));
    channel_base = set_bits(channel_base, 3, 2, get_bits(dram_buffer, 3, 2));

    size_t bank_base = 0;
    bank_base = set_bits(bank_base, 1, 0, get_bits(dram_buffer, 1, 0));
    bank_base = set_bits(bank_base, 3, 2, get_bits(dram_buffer, 7, 6));

    dram_buffer_cell cell{
        .bank = (uint8_t)bank_base, .channel = (uint8_t)channel_base, .row = (uint16_t)row, .column = (uint8_t)col};
    uint64_t bad_cells = 0;

    // On Pacific, DRAM buffer has 64 cells
    for (size_t i = 0; i < NUM_HBM_DRAM_BUFFER_CELLS; ++i) {
        bool has_error;
        la_status rc = check_dram_buffer_cell(cell, has_error);
        return_on_error(rc);

        if (has_error) {
            bad_cells |= 1 << i;
        }

        la_logger_level_e level = (has_error ? la_logger_level_e::ERROR : la_logger_level_e::DEBUG);
        log_message(la_logger_component_e::HLD,
                    level,
                    "%s: dram_buffer=0x%x, cell=%ld, %s, corrupted=%d",
                    __func__,
                    dram_buffer,
                    i,
                    silicon_one::to_string(cell).c_str(),
                    has_error);

        // bank progresses in the same way as channel, only when hit channel 15.
        if (cell.channel == 15) {
            if (cell.bank == 15) {
                cell.bank = 0;
            } else if (cell.bank == 11) {
                cell.bank = 15;
            } else {
                cell.bank = (cell.bank + 4) % 15;
            }
        }

        // channel always progresses as + 4 mod 15, but 15 goes to 0.
        if (cell.channel == 15) {
            cell.channel = 0;
        } else if (cell.channel == 11) {
            cell.channel = 15;
        } else {
            cell.channel = (cell.channel + 4) % 15;
        }
    }

    out_error.bank_base = bank_base;
    out_error.channel_base = channel_base;
    out_error.row = row;
    out_error.column = col;
    out_error.bad_cells = bad_cells;

    log_debug(HLD, "%s: done, dram_buffer=0x%x, out_error={%s}", __func__, dram_buffer, silicon_one::to_string(out_error).c_str());

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::check_dram_buffer_cell(const dram_buffer_cell& cell, bool& out_has_error)
{
    // write all 1s then all 0s to check cell
    la_status rc = dram_buffer_write(cell, 0);
    return_on_error(rc);

    bit_vector rd_data;
    rc = dram_buffer_read(cell, rd_data);
    return_on_error(rc);

    if (!rd_data.is_zero()) {
        log_err(HLD, "%s: %s, didn't read back all 0s", __func__, silicon_one::to_string(cell).c_str());
        out_has_error = true;
        return LA_STATUS_SUCCESS;
    }

    bit_vector ones1K = bit_vector::ones(1024);
    rc = dram_buffer_write(cell, ones1K);
    return_on_error(rc);

    rc = dram_buffer_read(cell, rd_data);
    return_on_error(rc);

    if (rd_data != ones1K) {
        log_err(HLD, "%s: %s, didn't read back all 1s", __func__, silicon_one::to_string(cell).c_str());
        out_has_error = true;
        return LA_STATUS_SUCCESS;
    }

    // After writing all 0s then all 1s the DRAM buffer is not corrupted anymore.
    // TODO: may want to return it back to the pool.
    log_err(HLD, "%s: %s, no corruption", __func__, silicon_one::to_string(cell).c_str());
    out_has_error = false;

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::dram_buffer_write(const dram_buffer_cell& cell, const bit_vector& in_bv)
{
    bit_vector bv = in_bv;

    bv.resize(hbm_chnl_4x_wide_cpu_mem_access_register::fields::CPU_DATA_WIDTH);

    return do_dram_buffer_read_write(false /* is_read */, cell, bv);
}

la_status
la_hbm_handler_impl::dram_buffer_read(const dram_buffer_cell& cell, bit_vector& out_bv)
{
    out_bv.resize(hbm_chnl_4x_wide_cpu_mem_access_register::fields::CPU_DATA_WIDTH);

    return do_dram_buffer_read_write(true /* is_read */, cell, out_bv);
}

la_status
la_hbm_handler_impl::do_dram_buffer_read_write(bool is_read, const dram_buffer_cell& cell, bit_vector& bv)
{
    if (!is_channel_valid(cell.channel)) {
        log_err(HLD, "%s: cell=%s, channel is out of range", __func__, silicon_one::to_string(cell).c_str());
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t lbr_num = cell.channel / 2;
    size_t lbr_channel = cell.channel % 2;

    hbm_chnl_4x_wide_cpu_mem_access_register val;

    val.fields.send_command = 1; // Execute. Interface is ready for next command when cleared to 0.
    val.fields.cpu_channel = lbr_channel;
    val.fields.cpu_bank = cell.bank;
    val.fields.cpu_rd_wr = is_read; // 1 for read, 0 for write
    val.fields.cpu_row_addr = cell.row;
    val.fields.cpu_col_addr = cell.column;
    if (!is_read) {
        val.fields.set_cpu_data((const uint64_t*)bv.byte_array());
    }

    lld_register_scptr cpu_mem_access
        = (is_tall_channel(lbr_num) ? m_device->m_pacific_tree->hbm->chnl[lbr_num]->tall->cpu_mem_access
                                    : m_device->m_pacific_tree->hbm->chnl[lbr_num]->wide->cpu_mem_access);

    // Issue read/write command
    la_status rc = m_device->m_ll_device->write_register(*cpu_mem_access, val);
    return_on_error(rc);

    // Wait 250 core cycles
    m_device->m_ll_device->delay(250);

    if (!is_read) {
        return LA_STATUS_SUCCESS;
    }

    // Read data from "read" command
    rc = m_device->m_ll_device->read_register(*cpu_mem_access, val);
    return_on_error(rc);

    val.fields.get_cpu_data((uint64_t*)bv.byte_array());

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_hbm_handler_impl::type() const
{
    return object_type_e::HBM_HANDLER;
}

std::string
la_hbm_handler_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_hbm_handler_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_hbm_handler_impl::oid() const
{
    return m_oid;
}

const la_device*
la_hbm_handler_impl::get_device() const
{
    return m_device.get();
}

} // namespace silicon_one
