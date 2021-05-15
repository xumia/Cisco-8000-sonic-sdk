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

#include "la_hbm_handler_impl.h"
#include "apb/apb.h"
#include "api/types/la_tm_types.h"
#include "api_tracer.h"
#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "cpu2jtag/cpu2jtag.h"
#include "hld_utils.h"
#include "la_device_impl.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/gibraltar_tree.h"
#include "lld/lld_utils.h"

#include "esilicon/apbDefs.h" // HBM-PHY vendor

#include <math.h>

#include <chrono>

using namespace std;

namespace silicon_one
{

enum hbm_e {
    HBM_APB_CLK_DIV = 6,     // clock divider for HBM APB interface, apb_clock = core_clock / divider
    HBM_NUM_OF_CHANNELS = 8, // Number of channels in HBM interface

    PLL_LOCK_MAX_RETRY = 100, // Max number of times to poll for PLL lock.
    ZQCAL_MAX_RETRY = 100,    // Max number of times to poll for completion of ZQCALIBRATION.

    HBM_TRAIN_POLL_MAX_RETRY = 20,              // Max number of times to poll for completion of HBM training.
    HBM_TRAIN_POLL_INTERVAL_MILLISECONDS = 100, // Interval between polls

    HBM_RATE_DEFAULT = 1900,          // HBM rate in Gbps
    HBM_EVICTION_RATE_DEFAULT = 1600, // HBM eviction rate in Gbps

    DEFAULT_STABLE_TRFCB_VALUE = 180, // According to the CSCvv89607 this value does't lead to mmu errors

    DEFAULT_HBM_DLL_RDQS = 64,
    DLL_RDQS_BASE = 0x805,
    HBM_FIFO_RESET_BASE = 0xB00,
    HBM_ID_0 = 0,
    HBM_ID_1 = 1,

    MAX_COUNTER_TIMER_CYCLES = 1UL << 32,
};

std::map<size_t, uint32_t> allowed_core_dfi_freq_pairs = {
    {950000, 900},
    {1050000, 1000},
    {1150000, 1100},
    {1200000, 1100},
    {1250000, 1200},
    {1350000, 1200},
};

la_hbm_handler_impl::la_hbm_handler_impl(la_device_impl_wptr device)
    : m_device(device), m_rate_limit(LA_RATE_UNLIMITED), m_measured_rate(0), m_is_completed(true), m_on_done_cb(nullptr)
{
    m_ll_device = m_device->get_ll_device_sptr();
    m_gb_tree = m_ll_device->get_gibraltar_tree_scptr();
    m_device_revision = m_ll_device->get_device_revision();
    m_does_hbm_exist = false;
}

la_hbm_handler_impl::~la_hbm_handler_impl()
{
}

la_status
la_hbm_handler_impl::destroy()
{
    m_task_scheduler.terminate();
    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::initialize(la_object_id_t oid)
{
    m_oid = oid;
    la_status rc = m_device->hbm_exists(m_does_hbm_exist);
    return_on_error(rc);

    log_debug(HLD, "%s: hbm_exists=%d", __func__, m_does_hbm_exist);

    // Check HBM exists
    if (!m_does_hbm_exist) {
        return LA_STATUS_SUCCESS;
    }

    apb_sptr apb;
    rc = m_device->get_apb_handler_sptr(apb_interface_type_e::HBM, apb);
    return_on_error(rc);

    m_apb = apb;

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::get_dfi_frequency(uint32_t& out_dfi_freq_mhz)
{
    if (allowed_core_dfi_freq_pairs.count(m_device->m_device_frequency_int_khz) > 0) {
        out_dfi_freq_mhz = allowed_core_dfi_freq_pairs[m_device->m_device_frequency_int_khz];
        return LA_STATUS_SUCCESS;
    }

    log_err(HLD, "%s: The Core frequency %ld KHz doesn't support DFI frequency.", __func__, m_device->m_device_frequency_int_khz);

    return LA_STATUS_EINVAL;
}

la_status
la_hbm_handler_impl::activate()
{
    if (!m_does_hbm_exist) {
        return LA_STATUS_SUCCESS;
    }

    uint32_t dfi_freq_mhz;
    la_status stat = get_dfi_frequency(dfi_freq_mhz);
    return_on_error(stat);

    configure_clocks_and_resets();
    set_use_traffic_gen(true);
    bringup_hbm(dfi_freq_mhz, false /*power_stable*/);
    bringup_hbm_part2();
    configure_samsung_timing_params(dfi_freq_mhz);
    configure_rd_wr_arbitration(true /* time_only */);

    // rc = rc ?: configure_lpm();
    // rc = rc ?: configure_buffer_alloc(use_lpm);
    // rc = rc ?: configure_buffer_alloc_post_reset(use_lpm);

    take_hbm_channels_out_of_reset();

    set_phy_to_mission_mode(false); // phy_apb_cfg_io_mission_mode, put drivers into mission mode

    // SHLOMO: Here the LPM is OK
    //   (the use_traffic_gen does NOT mask data to LPM)
    bool skip_hbm_training = false;
    m_device->get_bool_property(la_device_property_e::HBM_SKIP_TRAINING, skip_hbm_training);
    do_hbm_training(skip_hbm_training);

    print_values(HBM_ID_0);
    print_values(HBM_ID_1);

    set_use_traffic_gen(false);

    // NEW : Reset the entire HBM ecosystem and re-do the init with manual training and the values that
    //       we got from the real training.

    // read out values from training
    vector<uint32_t> dll_vals;
    read_hbm_training_values(dll_vals);

    // This leaves channels in soft reset
    reset_hbm_ecosystem(false /*in_soft_reset*/);

    bringup_hbm(dfi_freq_mhz, false /*power_stable*/);
    configure_samsung_timing_params(dfi_freq_mhz);
    configure_rd_wr_arbitration(true /* time_only */);
    // configure_lpm ();
    // take_mmu_out_of_reset ();
    // configure_buffer_alloc ();
    // configure_buffer_alloc_post_reset ();
    take_hbm_channels_out_of_reset();
    set_phy_to_mission_mode(0);

    give_control_to_ieee();
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x12, 19, 0x180);
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x2f, 12, 0xf10);
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x2e, 128, 0xbe8c79377);
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x12, 19, 0);
    give_control_to_apb();

    do_hbm_training_manual(1, dll_vals);

    clear_hbm_error_counters();
    clear_hbm_channel_interrupts();
    clear_mmu_error_counters();
    clear_mmu_interrupts();
    take_mmu_out_of_reset();

    set_dll_rdqs(DEFAULT_HBM_DLL_RDQS);
    reset_phy_fifo();

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::read_device_model_id()
{
    log_debug(HLD, "Start read device ID");
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::soft_reset()
{
    uint32_t dfi_freq_mhz;
    la_status stat = get_dfi_frequency(dfi_freq_mhz);
    return_on_error(stat);

    m_ll_device->write_register(m_gb_tree->mmu->soft_reset_configuration, 0);
    m_ll_device->write_register(m_gb_tree->mmu_buff->soft_reset_configuration, 0);

    gibraltar::sbif_cpu_jtag_cfg_reg_register jtag_cfg;
    m_ll_device->read_register(m_gb_tree->sbif->cpu_jtag_cfg_reg, jtag_cfg);
    jtag_cfg.fields.cpu_jtag_tck_clock_divider = 29; // default is 30
    m_ll_device->write_register(m_gb_tree->sbif->cpu_jtag_cfg_reg, jtag_cfg);

    // read out values from training
    vector<uint32_t> dll_vals;
    read_hbm_training_values(dll_vals);

    reset_hbm_ecosystem(true /*in_soft_reset*/);
    bringup_hbm(dfi_freq_mhz, true /*power_stable*/);
    take_hbm_channels_out_of_reset();
    set_phy_to_mission_mode(0);

    give_control_to_ieee();
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x12, 19, 0x180);
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x2f, 12, 0xf10);
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x2e, 128, 0xbe8c79377);
    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x12, 19, 0);
    give_control_to_apb();

    do_hbm_training_manual(1, dll_vals);

    clear_hbm_error_counters();
    clear_hbm_channel_interrupts();

    clear_mmu_error_counters();

    gibraltar::mmu_general_interrupt_register_register mmu_gir;
    m_ll_device->read_register(m_gb_tree->mmu->general_interrupt_register, mmu_gir);
    m_ll_device->write_register(m_gb_tree->mmu->general_interrupt_register, mmu_gir);

    gibraltar::mmu_lpm_debug_counters_register mmu_ldc;
    m_ll_device->read_register((*m_gb_tree->mmu->lpm_debug_counters)[0], mmu_ldc);
    m_ll_device->read_register((*m_gb_tree->mmu->lpm_debug_counters)[1], mmu_ldc);

    take_mmu_out_of_reset();

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::read_hbm_training_values(std::vector<uint32_t>& dll_vals)
{
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        for (size_t ch = 0; ch < 8; ++ch) {
            for (size_t ad = 0; ad < 9; ++ad) {
                bit_vector addr(ad);
                addr.set_bits(11, 8, 8);
                addr.set_bits(7, 4, ch * 2);
                bit_vector bv;
                m_apb->read(1 << hbm, (uint32_t)addr.get_value(), bv);
                dll_vals.push_back(bv.bits(15, 7).get_value());
            }
        }
    }
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

    // Reset HBM
    bit_vector tdo;
    la_status rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X12, 19, 0x000, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xe00, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 3, 0x0, tdo);
    return_on_error(rc);

    // Take APB out of reset
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 3, 0x4, tdo);
    return_on_error(rc);

    // Config PLL (to 800 MHz)
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0x01f, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 65, 0x80808fe, tdo);
    return_on_error(rc);

    // refclk of 50 MHz. Try 100 MHz  (divq 48, divf 48)
    bit_vector a(0);
    a.set_bits(10, 1, 47);
    a.set_bits(18, 11, 12);
    a.set_bits(27, 25, 4);
    // cpu2jtag.load_ir_dr(0x2e,65, a)
    // bit 10:1 divf  (div 32 for 800 MHz)
    // bit 18:11 divq
    // bit 24:19 divr
    // bit 27:25 range

    // write PLL CAP [PLL config capture]
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0x01e, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 1, 0x1, tdo);
    return_on_error(rc);

    this_thread::sleep_for(chrono::milliseconds(1));

    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0x01e, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 1, 0x0, tdo);
    return_on_error(rc);

    // take PLL out of reset
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xe00, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 3, 0x6, tdo);
    return_on_error(rc);

    // Enable PHY clocks (this is ESI_IEEE_CLK_DISABLE_CFG. Enables all clocks to toggle)
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0x010, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 72, 0x0, tdo);
    return_on_error(rc);

    // PHY DLL cfg (write 0)
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xf04, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x2e, 279, 0, tdo);
    return_on_error(rc);

    // PHY I/O Config
    // global config
    //(drive strength 0, no internal loopback, MS I/O config
    bit_vector global_cfg("0x1ff700");
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xf09, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 65, global_cfg, tdo);
    return_on_error(rc);

    // PHY I/O Config (same as pre-loopback)

    bit_vector ioAw("0x13ff00");
    bit_vector ioDw("0x5c1700");

    bit_vector ieee_data(0);
    ieee_data.set_bits(23, 0, ioDw);
    ieee_data.set_bits(47, 24, ioDw);
    ieee_data.set_bits(92, 69, ioDw);
    ieee_data.set_bits(116, 93, ioDw);
    ieee_data.set_bits(68, 48, ioAw);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xf03, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 117, ieee_data, tdo);
    return_on_error(rc);

    // Enable CK control for all channels. Set low for all channels, toggle for channel 0
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xf11, tdo);
    return_on_error(rc);

    // ieee_data = 1
    ieee_data = 0x1FFFFFFFF9F;
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 41, ieee_data, tdo);
    return_on_error(rc);

    // ch 0
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0x11, tdo);
    return_on_error(rc);

    // ieee_data = set_bits(ieee_data,4,3,1)
    ieee_data = 0x1FFFFFFFF8F;
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 41, ieee_data, tdo);
    return_on_error(rc);

    // Take PHY out of reset
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xe00, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 3, 0x7, tdo);
    return_on_error(rc);

    // ZQCAL norm
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0x008, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 25, 0xfc2, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 25, 0xfc6, tdo);
    return_on_error(rc);

    this_thread::sleep_for(chrono::milliseconds(100));

    // check is done
    rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x32, 25, 0xfc6, a);
    return_on_error(rc);
    bit_vector b = bit_vector(a & bit_vector(0x3));
    if (b.get_value() != 1) {
        log_err(HLD, "HBM_MBIST: timed out");
        return LA_STATUS_EUNKNOWN;
    }

    rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x30, 25, 0xfc6, a);
    return_on_error(rc);
    b = a & bit_vector(0x3);
    if (b.get_value() != 1) {
        log_err(HLD, "HBM_MBIST: timed out");
        return LA_STATUS_EUNKNOWN;
    }

    this_thread::sleep_for(chrono::milliseconds(100));

    // Check results
    rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x32, 25, 0, a);
    return_on_error(rc);

    b = a & bit_vector(0x3);
    if (b.get_value() != 1) {
        log_err(HLD, "HBM_MBIST: wrong results");
        return LA_STATUS_EUNKNOWN;
    }
    rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x30, 25, 0, a);
    return_on_error(rc);

    b = a & bit_vector(0x3);
    if (b.get_value() != 1) {
        log_err(HLD, "HBM_MBIST: wrong results");
        return LA_STATUS_EUNKNOWN;
    }
    this_thread::sleep_for(chrono::milliseconds(100));

    // do_hbm_die_reset_seq
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xf05, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 3, 0x1, tdo);
    return_on_error(rc);

    // wait tINIT1
    this_thread::sleep_for(chrono::milliseconds(100));
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 3, 0x3, tdo);
    return_on_error(rc);
    this_thread::sleep_for(chrono::milliseconds(100));
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 3, 0x7, tdo);
    return_on_error(rc);
    this_thread::sleep_for(chrono::milliseconds(100));

    // Set CKE=1 for channel 0
    //(ieee_data is kept from above)
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0x11, tdo);
    return_on_error(rc);

    ieee_data = 0x1FFFFFFFFEF;
    // ieee_data = set_bits(ieee_data,6,5,3)
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 41, ieee_data, tdo);
    return_on_error(rc);

    // NOTE: A6H is width 2029, A7H is width 301 (But A6H is only 363 wide in read)

    // Set A7H (only needed if using 800 MHz clock)
    // default value is all 0, so change only this bit
    // channel bits are don't-care
    ieee_data = 0;
    ieee_data.set_bit(292, 1);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x12, 19, 0x180, tdo);
    return_on_error(rc);

    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xfa7, tdo);
    return_on_error(rc);

    m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 301, ieee_data, tdo);
    return_on_error(rc);

    ieee_data = bit_vector("0x10210806080001cc00000000000000000000000000000000000200000000000000000000000e70000000000000022cc1400c0"
                           "06009ce0000000000000045986801800c0139c01601000210000000000000000007ba0130200401000108100000000000f74000"
                           "0001fffff9e000000000714c40100000003fffff3cffff00000e29880200000087ffffef8000000001c5310040000010fffffdf"
                           "3fffc000038a620080000041fffffde000000000714c40100000083fffffbcffff00000e29880200000187ffffff8000000001c"
                           "5310040000030fffffff3fffc000038a620080000000000000000000000000000000000000000000000000000000000000");

    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, 0xfa6, tdo);
    return_on_error(rc);
    rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2E, 2029, ieee_data, tdo);
    return_on_error(rc);

    this_thread::sleep_for(chrono::seconds(5));

    for (uint64_t ch = 0; ch < 8; ++ch) {
        bit_vector ad(0xa6);
        ad.set_bits(11, 8, ch);
        rc = m_device->m_cpu2jtag_handler->load_ir_dr((uint64_t)cpu2jtag::jtag_ir_e::HBM_X2F, 12, ad, tdo);
        return_on_error(rc);
        rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x30, 364, 0, a);
        return_on_error(rc);

        b = a.bits(363, 1);
        if (b.bits(6, 0).get_value() != 0) {
            log_err(HLD, "HBM_MBIST: MBIST FAILED for HBM 0, channel %lu", ch);
        }

        rc = m_device->m_cpu2jtag_handler->load_ir_dr(0x32, 364, 0, a);
        return_on_error(rc);

        b = a.bits(363, 1);
        if (b.bits(6, 0).get_value() != 0) {
            log_err(HLD, "HBM_MBIST: MBIST FAILED for HBM 1, channel %lu", ch);
        } else {
            log_info(HLD, "HBM_MBIST: passed for channel %lu", ch);
        }
    }
    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::read_error_counters(size_t hbm_interface,
                                         size_t channel_id,
                                         la_hbm_handler::error_counters& out_err_counters) const
{
    if (channel_id >= HBM_NUM_OF_CHANNELS) {
        return LA_STATUS_EINVAL;
    }

    if (channel_id >= NUM_HBM_CHANNELS) {
        return LA_STATUS_EINVAL;
    }

    gibraltar::hbm_hbm_error_counters_register error_counters_reg;
    la_status status = m_device->m_ll_device->read_register((*m_gb_tree->hbm->db[hbm_interface]->hbm_error_counters)[channel_id],
                                                            error_counters_reg);
    return_on_error(status);

    out_err_counters.write_data_parity_per_dword[0] = error_counters_reg.fields.derr_cntr_dw0;
    out_err_counters.write_data_parity_per_dword[1] = error_counters_reg.fields.derr_cntr_dw1;
    out_err_counters.write_data_parity_per_dword[2] = error_counters_reg.fields.derr_cntr_dw2;
    out_err_counters.write_data_parity_per_dword[3] = error_counters_reg.fields.derr_cntr_dw3;

    out_err_counters.addr_parity = error_counters_reg.fields.aerr_cntr;

    // Pseudo-channels fields
    out_err_counters.pseudo_channel_one_bit_ecc[0] = error_counters_reg.fields.one_bit_ecc_error_cntr_pc0;
    out_err_counters.pseudo_channel_one_bit_ecc[1] = error_counters_reg.fields.one_bit_ecc_error_cntr_pc1;

    out_err_counters.pseudo_channel_read_data_parity[0] = error_counters_reg.fields.rd_data_parity_error_cntr_pc0;
    out_err_counters.pseudo_channel_read_data_parity[1] = error_counters_reg.fields.rd_data_parity_error_cntr_pc1;

    out_err_counters.pseudo_channel_crc_error[0] = error_counters_reg.fields.crc_error_cntr_pc0;
    out_err_counters.pseudo_channel_crc_error[1] = error_counters_reg.fields.crc_error_cntr_pc1;

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::upload_firmware(const char* file_path)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::get_firmware_version_id(la_uint_t& out_fw_id)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::get_firmware_build_id(la_uint_t& out_build_id)
{
    return LA_STATUS_ENOTIMPLEMENTED;
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
    start_api_call("rate_limit=", rate_limit);

    if (m_rate_limit == rate_limit) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = set_dram_meter(rate_limit, HBM_EVICTION_RATE_DEFAULT * 1e9);
    return_on_error(status);

    m_rate_limit = rate_limit;

    return status;
}

void
la_hbm_handler_impl::get_rate_limit(la_rate_t& out_rate_limit) const
{
    start_api_getter_call();

    out_rate_limit = m_rate_limit;

    return;
}

la_status
la_hbm_handler_impl::start_rate_measurement(const std::chrono::seconds duration)
{
    start_api_call("duration=", duration);

    if (duration <= std::chrono::seconds::zero()) {
        return LA_STATUS_SUCCESS;
    }

    int64_t integrated_timer_capacity = MAX_COUNTER_TIMER_CYCLES / (m_device->m_device_frequency_float_ghz * 1e9);

    if (duration.count() > integrated_timer_capacity) {
        la_status status = start_sw_rate_measurement(duration);
        return_on_error(status);
    } else {
        la_status status = start_hw_rate_measurement(duration);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

bool
la_hbm_handler_impl::is_rate_measurement_completed() const
{
    start_api_getter_call();

    return m_is_completed;
}

la_status
la_hbm_handler_impl::read_rate(bool clear_on_read, la_rate_t& out_rate)
{
    start_api_call("clear_on_read=", clear_on_read);

    out_rate = m_measured_rate;

    if (clear_on_read) {
        m_is_completed = false;
        m_measured_rate = 0;
    }

    return LA_STATUS_SUCCESS;
}

void
la_hbm_handler_impl::register_read_cb(on_done_function_t on_done_cb)
{
    // Not implemented
}

la_status
la_hbm_handler_impl::start_sw_rate_measurement(const std::chrono::seconds duration)
{
    log_xdebug(HLD, "%s", __func__);

    // Clear
    uint64_t value0;
    la_status status = read_undropped_bytes_passed_to_dram(value0);
    return_on_error(status);
    log_debug(HLD, "%s : Undropped bytes passed to dram (%lu bytes) cleared", __func__, value0);

    auto t0 = std::chrono::high_resolution_clock::now();
    status = register_rate_measurement_task_completed_cb(
        [=]() {
            uint64_t value;
            read_undropped_bytes_passed_to_dram(value);
            auto d = std::chrono::duration_cast<std::chrono::seconds>(std::chrono::high_resolution_clock::now() - t0);
            m_measured_rate = value * 8 / d.count(); // bps
            m_is_completed = true;
        },
        duration);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::start_hw_rate_measurement(const std::chrono::seconds duration)
{
    log_xdebug(HLD, "%s", __func__);

    float frequency_ghz = m_device->m_device_frequency_float_ghz;
    uint64_t clock_cycles = duration.count() * 1e9 * frequency_ghz;

    if (clock_cycles > MAX_COUNTER_TIMER_CYCLES) {
        log_err(HLD,
                "%s: Invalid number of counter timer clock cycles, clock_cycles=%ld, max_counter_timer_cycles=%ld",
                __func__,
                clock_cycles,
                MAX_COUNTER_TIMER_CYCLES);
        return LA_STATUS_EINVAL;
    }

    la_status status = setup_counter_timer(true, clock_cycles);
    return_on_error(status);

    status = register_rate_measurement_task_completed_cb(
        [=]() {
            setup_counter_timer(false, clock_cycles);
            uint64_t value;
            read_undropped_bytes_passed_to_dram(value);
            m_measured_rate = value * 8 / duration.count();
            m_is_completed = true;
        },
        duration + std::chrono::seconds(1) // To make sure that mesuring is completed
        );
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::read_undropped_bytes_passed_to_dram(uint64_t& out_bytes) const
{
    gibraltar::pdoq_shared_mem_dram_slice_counters_register counters{{0}};
    la_status status = m_device->m_ll_device->read_register(*m_gb_tree->pdoq_shared_mem->dram_slice_counters, counters);
    return_on_error(status);

    out_bytes = counters.fields.good_bytes_counter + counters.fields.good_packets_counter * 8;

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::setup_counter_timer(bool enable, size_t clock_cycles) const
{
    gibraltar::pdoq_shared_mem_counter_timer_register counter_timer_reg{{0}};

    auto& lld = m_device->m_ll_device;

    counter_timer_reg.fields.counter_timer_cycle = clock_cycles;
    counter_timer_reg.fields.counter_timer_enable = enable ? clock_cycles : 0;

    la_status status = lld->write_register(*m_gb_tree->pdoq_shared_mem->counter_timer, counter_timer_reg);
    return_on_error(status);

    if (enable) {
        gibraltar::pdoq_shared_mem_counter_timer_trigger_reg_register trigger_reg{{0}};

        trigger_reg.fields.counter_timer_trigger = 1;
        status = lld->write_register(*m_gb_tree->pdoq_shared_mem->counter_timer_trigger_reg, trigger_reg);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::register_rate_measurement_task_completed_cb(task_completed_cb cb, std::chrono::seconds delay)
{
    log_xdebug(HLD, "%s", __func__);

    m_task_scheduler.spawn([]() {}); // Lazy - spawn TS only when needed

    if (m_task_scheduler.get_num_tasks() > 0) {
        m_task_scheduler.unschedule_task(m_task_handle); // Cancel ongoing measurement if any
    }

    m_is_completed = false;

    if (delay <= std::chrono::seconds::zero()) {
        return LA_STATUS_SUCCESS;
    }

    m_task_handle = m_task_scheduler.schedule_task(
        [&, cb]() {
            api_lock_guard<std::recursive_mutex> lock(m_device, __func__);
            cb();
        },
        std::chrono::duration_cast<std::chrono::milliseconds>(delay));

    if (m_task_handle == task_scheduler::INVALID_TASK_HANDLE) {
        log_err(HLD, "%s: unable to schedule collect counter cb for delay  %ld seconds.", __func__, delay.count());
        return LA_STATUS_ENOTINITIALIZED;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::dram_buffer_write(const dram_buffer_cell& cell, const bit_vector& in_bv)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::dram_buffer_read(const dram_buffer_cell& cell, bit_vector& out_bv)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::check_dram_buffer_errors(vector<dram_corrupted_buffer>& out_errors)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::check_dram_buffer_error(uint32_t dram_buffer, dram_corrupted_buffer& out_error)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::check_dram_buffer_cell(const dram_buffer_cell& cell, bool& out_has_error)
{
    return LA_STATUS_ENOTIMPLEMENTED;
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

// TODO: move to shared/include/lld/lld_utils.h
#define lld_rmw_read_internal(m_ll_device, reg, reg_val_type)                                                                      \
    reg_val_type val;                                                                                                              \
    la_status rc = m_ll_device->read_register(reg, val);                                                                           \
    return_on_error(rc)

#define lld_rmw_write_internal(m_ll_device, reg)                                                                                   \
    rc = m_ll_device->write_register(reg, val);                                                                                    \
    return_on_error(rc)

// read-modify-write 1 field
#define lld_rmw(m_ll_device, reg, reg_val_type, name, value)                                                                       \
    do {                                                                                                                           \
        lld_rmw_read_internal(m_ll_device, reg, reg_val_type);                                                                     \
        val.fields.name = value;                                                                                                   \
        lld_rmw_write_internal(m_ll_device, reg);                                                                                  \
    } while (0)

// read-modify-write 2 fields
#define lld_rmw_2(m_ll_device, reg, reg_val_type, name0, value0, name1, value1)                                                    \
    do {                                                                                                                           \
        lld_rmw_read_internal(m_ll_device, reg, reg_val_type);                                                                     \
        val.fields.name0 = value0;                                                                                                 \
        val.fields.name1 = value1;                                                                                                 \
        lld_rmw_write_internal(m_ll_device, reg);                                                                                  \
    } while (0)

// read-modify-write 3 fields
#define lld_rmw_3(m_ll_device, reg, reg_val_type, name0, value0, name1, value1, name2, value2)                                     \
    do {                                                                                                                           \
        lld_rmw_read_internal(m_ll_device, reg, reg_val_type);                                                                     \
        val.fields.name0 = value0;                                                                                                 \
        val.fields.name1 = value1;                                                                                                 \
        val.fields.name2 = value2;                                                                                                 \
        lld_rmw_write_internal(m_ll_device, reg);                                                                                  \
    } while (0)

// read-modify-write 4 fields
#define lld_rmw_4(m_ll_device, reg, reg_val_type, name0, value0, name1, value1, name2, value2, name3, value3)                      \
    do {                                                                                                                           \
        lld_rmw_read_internal(m_ll_device, reg, reg_val_type);                                                                     \
        val.fields.name0 = value0;                                                                                                 \
        val.fields.name1 = value1;                                                                                                 \
        val.fields.name2 = value2;                                                                                                 \
        val.fields.name3 = value3;                                                                                                 \
        lld_rmw_write_internal(m_ll_device, reg);                                                                                  \
    } while (0)

// read-modify-write 5 fields
#define lld_rmw_5(m_ll_device, reg, reg_val_type, name0, value0, name1, value1, name2, value2, name3, value3, name4, value4)       \
    do {                                                                                                                           \
        lld_rmw_read_internal(m_ll_device, reg, reg_val_type);                                                                     \
        val.fields.name0 = value0;                                                                                                 \
        val.fields.name1 = value1;                                                                                                 \
        val.fields.name2 = value2;                                                                                                 \
        val.fields.name3 = value3;                                                                                                 \
        val.fields.name4 = value4;                                                                                                 \
        lld_rmw_write_internal(m_ll_device, reg);                                                                                  \
    } while (0)

la_status
la_hbm_handler_impl::apb_write(uint32_t reg, uint32_t val)
{
    uint32_t apb_select = 0x3; // both HBM dies

    return m_apb->write(apb_select, reg, val);
}

la_status
la_hbm_handler_impl::configure_clocks_and_resets()
{
    log_debug(HLD, "%s", __func__);

    const auto& hbm = m_gb_tree->hbm;

    gibraltar::hbm_hbm_clock_config_register hbm_clock_config;
    m_ll_device->read_register(m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);

    gibraltar::hbm_memory_access_timeout_register memory_access_timeout;
    m_ll_device->read_register(m_gb_tree->hbm->db[0]->memory_access_timeout, memory_access_timeout);

    gibraltar::hbm_hbm_resets_register hbm_resets;
    m_ll_device->read_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);

    for (size_t ch = 0; ch < 2; ch++) {
        hbm_clock_config.fields.apb_clock_division = 12;
        m_ll_device->write_register(m_gb_tree->hbm->db[ch]->hbm_clock_config, hbm_clock_config);

        // a = debug_device.read_register(m_gb_tree->sbif.cpu_jtag_cfg_reg)
        // a.cpu_jtag_tck_clock_divider = 29 # default is 30
        // debug_device.write_register(m_gb_tree->sbif.cpu_jtag_cfg_reg,a)

        memory_access_timeout.fields.timeout_counter_thr = 0xffff;
        m_ll_device->write_register(m_gb_tree->hbm->db[ch]->memory_access_timeout, memory_access_timeout);

        m_ll_device->write_register(hbm->db[ch]->soft_reset_configuration, 1);

        hbm_clock_config.fields.use_ieee_bridge = 1;
        m_ll_device->write_register(m_gb_tree->hbm->db[ch]->hbm_clock_config, hbm_clock_config);

        this_thread::sleep_for(chrono::microseconds(10));

        hbm_resets.fields.ieee_wrstn = 1;
        m_ll_device->write_register(m_gb_tree->hbm->db[ch]->hbm_resets, hbm_resets);
        m_ll_device->write_memory(hbm->db[ch]->ieee1500, 0xc, 0);

        bit_vector tmp;
        m_ll_device->read_memory(hbm->db[ch]->ieee1500, 0xc, tmp);

        hbm_resets.fields.ieee_wrstn = 0;
        m_ll_device->write_register(m_gb_tree->hbm->db[ch]->hbm_resets, hbm_resets);

        hbm_clock_config.fields.ieee_clock_division = 40;
        m_ll_device->write_register(m_gb_tree->hbm->db[ch]->hbm_clock_config, hbm_clock_config);

        hbm_clock_config.fields.use_ieee_bridge = 0;
        m_ll_device->write_register(m_gb_tree->hbm->db[ch]->hbm_clock_config, hbm_clock_config);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::reset_hbm_ecosystem(bool in_soft_reset)
{
    log_debug(HLD, "%s", __func__);

    apb_write(0x80, 0);

    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x12, 19, 0);

    gibraltar::hbm_hbm_resets_register hbm_resets{.u8 = {0}};
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->soft_reset_configuration, 0);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->soft_reset_configuration, 0);
    for (const auto& hbm_chnl : m_gb_tree->hbm->chnl) {
        m_ll_device->write_register(hbm_chnl->hbm_training_done, 0);
        m_ll_device->write_register(hbm_chnl->soft_reset_configuration, 0);
    }

    m_ll_device->write_register(m_gb_tree->hbm->db[1]->soft_reset_configuration, 1);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->soft_reset_configuration, 1);

    gibraltar::hbm_hbm_clock_config_register hbm_clock_config;
    m_ll_device->read_register(m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);
    hbm_clock_config.fields.use_ieee_bridge = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);

    if (!in_soft_reset) {
        this_thread::sleep_for(chrono::milliseconds(10));
    }

    hbm_resets.fields.ieee_wrstn = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    m_ll_device->write_memory(m_gb_tree->hbm->db[1]->ieee1500, 0xc, 0);
    m_ll_device->write_memory(m_gb_tree->hbm->db[0]->ieee1500, 0xc, 0);
    bit_vector tmp;
    m_ll_device->read_memory(m_gb_tree->hbm->db[1]->ieee1500, 0xc, tmp);
    m_ll_device->read_memory(m_gb_tree->hbm->db[0]->ieee1500, 0xc, tmp);

    hbm_resets.fields.ieee_wrstn = 0;
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);

    if (!in_soft_reset) {
        hbm_clock_config.fields.ieee_clock_division = 40;
        m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);
        m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);
    }

    hbm_clock_config.fields.use_ieee_bridge = 0;
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);

    m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo(0x12, 19, 0);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::set_use_traffic_gen(bool use_traffic_gen)
{
    log_debug(HLD, "%s %d", __func__, use_traffic_gen);

    if (use_traffic_gen) {
        m_device->m_cpu2jtag_handler->load_ir_dr_no_tdo((uint16_t)cpu2jtag::jtag_ir_e::HBM_X12, 19, 0);
    }

    gibraltar::hbm_chnl_4x_tall_traffic_gen_trans_ctrl_register val;
    m_ll_device->read_register((*m_gb_tree->hbm->chnl[0]->traffic_gen_trans_ctrl)[0], val);
    val.fields.use_traffic_gen = use_traffic_gen;
    for (const auto& hbm_chnl : m_device->m_gb_tree->hbm->chnl) {
        for (size_t i = 0; i < hbm_chnl->traffic_gen_trans_ctrl->size(); ++i) {
            m_ll_device->write_register((*hbm_chnl->traffic_gen_trans_ctrl)[i], val);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::bringup_hbm(uint32_t dfi_freq_mhz, bool power_stable)
{
    log_debug(HLD, "%s: dfi_freq_mhz=%d", __func__, dfi_freq_mhz);

    gibraltar::hbm_hbm_resets_register hbm_resets;
    m_ll_device->read_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);

    // raise APB reset
    hbm_resets.fields.apb_rstn = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);

    // raise IEEE reset
    hbm_resets.fields.ieee_wrstn = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);

    // give control to APB
    gibraltar::hbm_apb_ctrl_register apb_ctrl{.u8 = {0}};
    apb_ctrl.fields.apb_ctrl_req = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->apb_ctrl, apb_ctrl);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->apb_ctrl, apb_ctrl);
    this_thread::sleep_for(chrono::microseconds(10));
    apb_ctrl.fields.apb_ctrl_req = 0;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->apb_ctrl, apb_ctrl);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->apb_ctrl, apb_ctrl);

    uint32_t dfi_freq;
    if (dfi_freq_mhz == 1200) {
        dfi_freq = 0x800005e;
    } else if (dfi_freq_mhz == 1100) {
        dfi_freq = 0x8000056;
    } else if (dfi_freq_mhz == 1000) {
        // 1000 MHZ
        dfi_freq = 0x800004e;
    } else {
        // 900 MHZ
        dfi_freq = 0x8000046;
    }

    apb_write(0, dfi_freq);
    apb_write(3, 1);
    this_thread::sleep_for(chrono::milliseconds(1));
    apb_write(3, 0);

    log_debug(HLD, "%s: take PLL out of reset", __func__);

    // TODO: take ESI_... values from  program_hbm_plls()
    hbm_resets.fields.pll_rstn = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);

    // Poll for PLL lock on die 0 and 1.
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        bool pll_locked = false;
        for (size_t retry = 0; !pll_locked && retry < PLL_LOCK_MAX_RETRY; ++retry) {
            this_thread::sleep_for(chrono::microseconds(1));
            bit_vector rd_data;
            m_apb->read(1 << hbm, 2, rd_data);
            pll_locked = rd_data.bit(0);
            if (pll_locked) {
                log_debug(HLD, "%s: PLL[%ld] lock after %ld retries", __func__, hbm, retry);
            }
        }

        if (!pll_locked) {
            // Either PLL didn't lock, or could also mean that the ASIC does not have HBM IP.
            log_err(HLD, "%s: PLL[%ld] couldn't lock", __func__, hbm);
            return LA_STATUS_EUNKNOWN;
        }
    }

    // ENABLE CLOCKS FOR ALL CHANELS
    uint32_t clk_disable_regs[8] = {0xd0f, 0xd2f, 0xd4f, 0xd6f, 0xd8f, 0xdaf, 0xdcf, 0xdef};
    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(clk_disable_regs[ch], 0);
    }

    // de-assert PHY reset
    hbm_resets.fields.phy_rstn = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);

    // ZQCALIBRATION
    uint32_t ext_resistor_enab = 1;
    // uint32_t override_cal_driv_enab = 0;
    // uint32_t get_trim_res_from_reg_enab = 1;
    uint32_t trim_res = 0xf;
    uint32_t zqcal_write_data = (ext_resistor_enab << 11) | (trim_res << 7) | 0x42;
    apb_write(0x10, zqcal_write_data);

    zqcal_write_data = (ext_resistor_enab << 11) | (trim_res << 7) | 0x46;
    apb_write(0x10, zqcal_write_data);

    for (size_t hbm = 0; hbm < 2; ++hbm) {
        bool zqcal_done = false;
        bool zqcal_failed = false;
        for (size_t retry = 0; !zqcal_done && retry < ZQCAL_MAX_RETRY; ++retry) {
            this_thread::sleep_for(chrono::microseconds(1));
            bit_vector rd_data;
            m_apb->read(1 << hbm, 0x11, rd_data);
            zqcal_done = rd_data.bit(0);
            zqcal_failed = rd_data.bit(1);

            if (zqcal_done && !zqcal_failed) {
                log_debug(HLD, "%s: ZQCALIBRATION[%ld] pass after %ld retries", __func__, hbm, retry);
            }
        }

        if (!zqcal_done || zqcal_failed) {
            log_err(HLD, "%s: ZQCALIBRATION[%ld] failed, done=%d, failed=%d", __func__, hbm, zqcal_done, zqcal_failed);
            return LA_STATUS_EUNKNOWN;
        }
    }

    // DISABLE AW, DW FIFOS FOR ENABLED CHANNELS
    uint32_t fifo_reset_base_regs[8] = {0xb00, 0xb20, 0xb40, 0xb60, 0xb80, 0xba0, 0xbc0, 0xbe0};
    for (size_t ch = 0; ch < 8; ++ch) {
        for (uint32_t dw = 0; dw < 4; ++dw) {
            apb_write(fifo_reset_base_regs[ch] + dw, 1);
        }
    }

    uint32_t match_ck = 4;
    uint32_t match_wdqs = 4;
    // uint32_t match_rdqs = 4;
    uint32_t ext_adj_ck = 0x3c;
    uint32_t ext_adj_wdqs = 0x3c;
    // uint32_t ext_adj_rdqs = 0x3c;

    uint32_t dll_slv_ck = (((match_ck & 0xf) << 25 | (ext_adj_ck & 0x1ff) << 7) | (0x40));
    uint32_t dll_slv_wdqs = (((match_wdqs & 0xf) << 25 | (ext_adj_wdqs & 0x1ff) << 7) | (0x40));
    // uint32_t dll_slv_rdqs = (((match_rdqs & 0xf) << 25 | (ext_adj_rdqs & 0x1ff) << 7) | (0x40));

    uint32_t dll_cfg_base_regs[8] = {0x800, 0x820, 0x840, 0x860, 0x880, 0x8a0, 0x8c0, 0x8e0};

    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(dll_cfg_base_regs[ch], dll_slv_ck);
        for (uint32_t dw = 1; dw < 9; ++dw) {
            apb_write(dll_cfg_base_regs[ch] + dw, dll_slv_wdqs);
        }
    }

    // ENABLE AW, DW FIFOS FOR ENABLED CHANNELS
    for (size_t ch = 0; ch < 8; ++ch) {
        for (uint32_t dw = 0; dw < 4; ++dw) {
            apb_write(fifo_reset_base_regs[ch] + dw, 0);
        }
    }

    apb_write(ESI_TRAINING_CHANNEL_ENAB, 0xff);
    apb_write(0x40, 0); // DRIVE_STRENGTH = 0 (max)
    // apb_write(0x40,0x24);
    apb_write(0x43, 0x7fdc);
    apb_write(0x14, 1);

    // IO CONFIGURATION FOR ENABLED CHANNELS
    uint32_t io_cfg_base_regs[8] = {0x900, 0x920, 0x940, 0x960, 0x980, 0x9a0, 0x9c0, 0x9e0};
    uint32_t read_delay_base_regs[8] = {0xc00, 0xc20, 0xc40, 0xc60, 0xc80, 0xca0, 0xcc0, 0xce0};
    uint32_t par_lat_base_regs[8] = {0xc04, 0xc24, 0xc44, 0xc64, 0xc84, 0xca4, 0xcc4, 0xce4};
    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(io_cfg_base_regs[ch], 0x20f00);
        for (size_t i = 1; i < 5; ++i) {
            uint32_t addr = io_cfg_base_regs[ch] + i;
            apb_write(addr, 0xbe1700);
            for (size_t j = 0; j < 4; ++j) {
                addr = read_delay_base_regs[ch] + j;
                // This is read_delay (i.e. RL) + rdsel_offset (==4)
                // We use RL of 26 (write 24 into MR2)
                apb_write(addr, 30);
                apb_write(par_lat_base_regs[ch], 0xaa);
            }
        }
    }

    // RESET DRAM, GET IT TO INIT3 STAGE
    if (power_stable) {
        apb_write(0x80, 1);
        this_thread::sleep_for(chrono::microseconds(1));
        apb_write(0x80, 3);
        this_thread::sleep_for(chrono::milliseconds(1));
        apb_write(0x80, 7);
    } else {
        this_thread::sleep_for(chrono::milliseconds(100));
        apb_write(0x80, 1);
        this_thread::sleep_for(chrono::microseconds(200));
        apb_write(0x80, 3);
        this_thread::sleep_for(chrono::milliseconds(1));
        apb_write(0x80, 7);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::bringup_hbm_part2()
{
    uint32_t runtime = 3;

    uint32_t misrlb_runtime_base_reg[8] = {0xe00, 0xe20, 0xe40, 0xe60, 0xe80, 0xea0, 0xec0, 0xee0};
    uint32_t misrlb_cfg_aw_base_reg[8] = {0xe02, 0xe22, 0xe42, 0xe62, 0xe82, 0xea2, 0xec2, 0xee2};
    uint32_t training_minrange_ck_base_reg[8] = {0x600, 0x620, 0x640, 0x660, 0x680, 0x6a0, 0x6c0, 0x6e0};
    uint32_t training_minrange_wdqs_base_reg[8] = {0x601, 0x621, 0x641, 0x661, 0x681, 0x6a1, 0x6c1, 0x6e1};
    // uint32_t training_minrange_rdqs_base_reg[8] = {0x602, 0x622, 0x642, 0x662, 0x682, 0x6a2, 0x6c2, 0x6e2};
    // uint32_t training_minrange_rdsel_base_reg[8] = {0x603, 0x623, 0x643, 0x663, 0x683, 0x6a3, 0x6c3, 0x6e3};
    uint32_t misrlb_cfg_dw_base_reg[8] = {0xe07, 0xe27, 0xe47, 0xe67, 0xe87, 0xea7, 0xec7, 0xee7};
    // uint32_t repair_dw_base_reg[8] = {0xa01, 0xa21, 0xa41, 0xa61, 0xa81, 0xaa1, 0xac1, 0xae1};

    for (size_t ch = 0; ch < 8; ++ch) {
        // apb_write (misrlb_runtime_base_reg[ch] ,0x1ff)
        apb_write(misrlb_runtime_base_reg[ch], runtime);
        apb_write(misrlb_runtime_base_reg[ch] + 1, 0);
        apb_write(misrlb_cfg_aw_base_reg[ch], 4); // This is dw_test_cfg
        apb_write(misrlb_cfg_aw_base_reg[ch] + 1, 0x14);
        apb_write(training_minrange_ck_base_reg[ch], 0xa);
    }

    // MRS config
    uint32_t mr[8];
    mr[0] = 0x77;
    mr[1] = 19 | (4 << 5);
    mr[2] = 7 | (24 << 3);
    mr[3] = 40 | (3 << 6);
    // mr[3] = 0x9d
    mr[4] = 3 | (2 << 2);
    mr[5] = 0;
    mr[6] = 0;
    mr[7] = 0;

    // mr = [0x3,0x93,0xc7,0xe8,0xb,0,0,0]
    // mr = [0x73,0x90,0xc7,0x9d,0xb,0,0,0]
    for (size_t ch = 0; ch < 8; ++ch) {
        for (size_t mrs = 0; mrs < 8; ++mrs) {
            bit_vector mrs_reg_addr(mrs);
            mrs_reg_addr.set_bit(4, 0);
            mrs_reg_addr.set_bits(7, 5, ch);
            mrs_reg_addr.set_bits(11, 8, 5);
            apb_write((uint32_t)mrs_reg_addr.get_value(), mr[mrs]);
        }
    }

    uint32_t write_latency = 8;
    uint32_t start_delay = 11;
    uint32_t cmd2cmd_latency = 0;
    // cmd2cmd_latency = 3
    uint32_t cfg_dly = start_delay | (write_latency << 8) | (cmd2cmd_latency << 16);

    for (size_t ch = 0; ch < 8; ++ch) {
        // do_apb_write (hbm,misrlb_runtime_base_reg[ch] ,0x1ff)
        apb_write(misrlb_runtime_base_reg[ch], runtime);
        apb_write(misrlb_runtime_base_reg[ch] + 1, 0);
        apb_write(misrlb_cfg_aw_base_reg[ch], 4);           // This is dw_test_cfg
        apb_write(misrlb_cfg_aw_base_reg[ch] + 1, cfg_dly); // This is aw_misr_data
        // apb_write(training_minrange_wdqs_base_reg [ch],0x4);
        apb_write(training_minrange_wdqs_base_reg[ch], 0xa);
        for (size_t dw = 0; dw < 4; ++dw) {
            apb_write(misrlb_cfg_dw_base_reg[ch] + (dw * 6), 4);
            apb_write(misrlb_cfg_dw_base_reg[ch] + (dw * 6) + 1, cfg_dly);
        }
    }

    uint32_t wdqs_dll_start = 30;
    uint32_t wdqs_dll_end = 90;
    size_t ch = 0; // TODO: training only on ch==0 ???
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        m_apb->write(1 << hbm, ESI_TRAINING_DOREPAIR, 1);
        m_apb->write(1 << hbm, ESI_TRAINING_DONE, 0);
        m_apb->write(1 << hbm, ESI_TRAINING_TYPE, 1);
        // do_apb_write (hbm,ESI_TRAINING_CHANNEL_ENAB, 0xff)
        m_apb->write(1 << hbm, ESI_TRAINING_CHANNEL_ENAB, 1 << ch);
        m_apb->write(1 << hbm, ESI_TRAINING_DLL_RANGE, (wdqs_dll_end << 16) | wdqs_dll_start);
        m_apb->write(1 << hbm, ESI_TRAINING_GO, 1);

        la_status rc = poll_training_completion(hbm);
        log_debug(HLD,
                  "%s: HBM %ld, channel %ld, poll_training_completion result => %d. Expected to fail",
                  __func__,
                  hbm,
                  ch,
                  rc.value());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::configure_samsung_timing_params(uint32_t dfi_freq_mhz)
{
    log_debug(HLD, "%s: dfi_freq_mhz=%d", __func__, dfi_freq_mhz);

    la_status rc;

    // Fix CBR depth of MMU to be 48 instead of 32
    gibraltar::mmu_mmu_debug_configs_register mmu_debug_configs;
    m_ll_device->read_register(m_gb_tree->mmu->mmu_debug_configs, mmu_debug_configs);
    mmu_debug_configs.fields.sms2_mmu_cbr_depth = 48;
    m_ll_device->write_register(m_gb_tree->mmu->mmu_debug_configs, mmu_debug_configs);

    gibraltar::mmu_mmu_parameters_register mmu_parameters;
    m_ll_device->read_register(m_gb_tree->mmu->mmu_parameters, mmu_parameters);
    mmu_parameters.fields.large_burst_mode = 1;
    m_ll_device->write_register(m_gb_tree->mmu->mmu_parameters, mmu_parameters);

    gibraltar::hbm_chnl_4x_tall_hbm_timing_params_register a_timing{.u8 = {0}};
    gibraltar::hbm_chnl_4x_tall_hbm_more_timing_parameters_register b_timing{.u8 = {0}};
    gibraltar::hbm_chnl_4x_tall_hbm_power_down_register c_power_down{.u8 = {0}};
    uint32_t h_async_fifo_config = 45;

    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->hbm_timing_params, a_timing);
    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->hbm_more_timing_parameters, b_timing);
    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->hbm_power_down, c_power_down);

    a_timing.fields.hbm_wl = 8;
    a_timing.fields.hbm_tccdl = 4;
    a_timing.fields.hbm_tccds = 2;

    if (dfi_freq_mhz >= 1200) { // only for core_clk of > 1.2 GHz
        a_timing.fields.hbm_trcdrd = 17;
        a_timing.fields.hbm_trcdwr = 12;
        a_timing.fields.hbm_trrdl = 5;
        a_timing.fields.hbm_trrds = 5;
        a_timing.fields.hbm_tras = 40;
        a_timing.fields.hbm_trfcsb = DEFAULT_STABLE_TRFCB_VALUE;
        a_timing.fields.hbm_trfc = 314;
        a_timing.fields.hbm_trrefd = 12;
        a_timing.fields.hbm_trp = 17;
        a_timing.fields.hbm_twtrs = 15;
        a_timing.fields.hbm_twtrl = 21;
        a_timing.fields.hbm_trtw = 27;
        a_timing.fields.hbm_refresh_priority_time = 250;
        b_timing.fields.hbm_twr = 19;
        b_timing.fields.hbm_trtp = 5;
        b_timing.fields.hbm_tfaw = 20;
        b_timing.fields.hbm_trefi = 4680;
        c_power_down.fields.hbm_tpd = 8;
        if (m_device->m_device_frequency_int_khz == 1350000) {
            h_async_fifo_config = 18;
        } else if (m_device->m_device_frequency_int_khz == 1250000) {
            h_async_fifo_config = 20;
        } else {
            log_info(HLD,
                     "Device frequency %lu not supported for dfi frequency %ul",
                     m_device->m_device_frequency_int_khz,
                     dfi_freq_mhz);
        }
    } else if (dfi_freq_mhz >= 1100) {
        a_timing.fields.hbm_trcdrd = 16;
        a_timing.fields.hbm_trcdwr = 11;
        a_timing.fields.hbm_trrdl = 5;
        a_timing.fields.hbm_trrds = 5;
        a_timing.fields.hbm_tras = 37;
        a_timing.fields.hbm_trfcsb = DEFAULT_STABLE_TRFCB_VALUE;
        a_timing.fields.hbm_trfc = 286;
        a_timing.fields.hbm_trrefd = 12;
        a_timing.fields.hbm_trp = 16;
        a_timing.fields.hbm_twtrs = 16;
        a_timing.fields.hbm_twtrl = 21;
        a_timing.fields.hbm_trtw = 30;
        a_timing.fields.hbm_refresh_priority_time = 250;
        b_timing.fields.hbm_twr = 18;
        b_timing.fields.hbm_trtp = 5;
        b_timing.fields.hbm_tfaw = 18;
        b_timing.fields.hbm_trefi = 4290;
        c_power_down.fields.hbm_tpd = 8;
        if (m_device->m_device_frequency_int_khz == 1350000) {
            h_async_fifo_config = 17;
        } else if (m_device->m_device_frequency_int_khz == 1200000) {
            h_async_fifo_config = 19;
        } else if (m_device->m_device_frequency_int_khz == 1150000) {
            h_async_fifo_config = 20;
        } else {
            log_info(HLD,
                     "Device frequency %lu not supported for dfi frequency %ul",
                     m_device->m_device_frequency_int_khz,
                     dfi_freq_mhz);
        }
    } else { // 1000 MHz or 900 Mhz
        a_timing.fields.hbm_trcdrd = 14;
        a_timing.fields.hbm_trcdwr = 10;
        a_timing.fields.hbm_trrdl = 4;
        a_timing.fields.hbm_trrds = 4;
        a_timing.fields.hbm_tras = 33;
        a_timing.fields.hbm_trfcsb = DEFAULT_STABLE_TRFCB_VALUE;
        a_timing.fields.hbm_trfc = 260;
        a_timing.fields.hbm_trrefd = 12;
        a_timing.fields.hbm_trp = 14;
        a_timing.fields.hbm_twtrs = 14;
        a_timing.fields.hbm_twtrl = 19;
        a_timing.fields.hbm_trtw = 27;
        a_timing.fields.hbm_refresh_priority_time = 220;
        b_timing.fields.hbm_twr = 16;
        b_timing.fields.hbm_trtp = 5;
        b_timing.fields.hbm_tfaw = 16;
        c_power_down.fields.hbm_tpd = 8;
        if (m_device->m_device_frequency_int_khz == 1050000 || m_device->m_device_frequency_int_khz == 950000) {
            h_async_fifo_config = 20;
        } else {
            log_info(HLD,
                     "Device frequency %lu not supported for dfi frequency %ul",
                     m_device->m_device_frequency_int_khz,
                     dfi_freq_mhz);
        }
    }

    // TODO: does not belong here, move to where hbm.chnl[] is taken out of reset
    gibraltar::hbm_chnl_4x_tall_memory_access_timeout_register d_timeout{.u8 = {0}};
    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->memory_access_timeout, d_timeout);
    d_timeout.fields.timeout_counter_thr = 0xffff;

    gibraltar::hbm_chnl_4x_tall_hbm_die_type_register e_die_type;
    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->hbm_die_type, e_die_type);
    e_die_type.fields.large_burst_mode = 1;

    gibraltar::hbm_chnl_4x_tall_mmu_bank_arbitration_register f_mmu_arbitration;
    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->mmu_bank_arbitration, f_mmu_arbitration);
    f_mmu_arbitration.fields.wr_fifo_priority_threshold = 15;

    gibraltar::hbm_chnl_4x_tall_channel_fifo_sizes_register g_fifo_sizes;
    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->channel_fifo_sizes, g_fifo_sizes);
    g_fifo_sizes.fields.lpm_result_alm_full = 50;

    for (size_t i = 0; i < 8; ++i) {
        m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->hbm_timing_params, a_timing);
        m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->hbm_more_timing_parameters, b_timing);
        m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->hbm_power_down, c_power_down);
        m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->memory_access_timeout, d_timeout);
        m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->hbm_die_type, e_die_type);
        m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->mmu_bank_arbitration, f_mmu_arbitration);
        m_ll_device->write_register(m_gb_tree->hbm->chnl[i]->channel_fifo_sizes, g_fifo_sizes);

        m_ll_device->write_register((*m_gb_tree->hbm->db[0]->async_fifo_config)[i], h_async_fifo_config);
        m_ll_device->write_register((*m_gb_tree->hbm->db[1]->async_fifo_config)[i], h_async_fifo_config);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::configure_rd_wr_arbitration(bool time_only)
{
    log_debug(HLD, "%s", __func__);
    // Rd-to-Wr arbitration
    gibraltar::hbm_chnl_4x_tall_hbm_rd_to_wr_arbitration_config_register rd_to_wr;
    bit_vector rd_to_wr_arbitration_criteria;

    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->hbm_rd_to_wr_arbitration_config, rd_to_wr);

    rd_to_wr.fields.move_to_wr_on_empty = 1;
    rd_to_wr.fields.min_move_to_wr_valid_banks = 0;
    rd_to_wr.fields.rd_total_cycles_threshold0 = 512;
    rd_to_wr.fields.rd_total_cycles_threshold1 = 600;
    rd_to_wr.fields.rd_total_cycles_threshold2 = 600;

    rd_to_wr_arbitration_criteria = bit_vector("0xffffffffffffffff0000000000000000ffffffffffffffff0000000000000000");

    // Wr-to-Rd arbitration
    gibraltar::hbm_chnl_4x_tall_hbm_wr_to_rd_arbitration_config_register wr_to_rd;
    bit_vector wr_to_rd_arbitration_criteria;

    m_ll_device->read_register(m_gb_tree->hbm->chnl[0]->hbm_wr_to_rd_arbitration_config, wr_to_rd);
    wr_to_rd.fields.move_to_rd_on_empty = 0;
    wr_to_rd.fields.min_move_to_rd_valid_banks = 0;
    wr_to_rd.fields.wr_total_cycles_threshold0 = 512;
    wr_to_rd.fields.wr_total_cycles_threshold1 = 600;
    wr_to_rd.fields.wr_total_cycles_threshold2 = 600;
    wr_to_rd.fields.min_lpm_req_pending_cycles = 256;

    wr_to_rd_arbitration_criteria = bit_vector("0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0"
                                               "000000000000000ffffffffffffffff0000000000000000");

    for (const auto& hbm_chnl : m_gb_tree->hbm->chnl) {
        m_ll_device->write_register(hbm_chnl->hbm_rd_to_wr_arbitration_config, rd_to_wr);
        m_ll_device->write_register(hbm_chnl->hbm_wr_to_rd_arbitration_config, wr_to_rd);

        m_ll_device->write_register(hbm_chnl->hbm_rd_to_wr_arbitration_criteria, rd_to_wr_arbitration_criteria);
        m_ll_device->write_register(hbm_chnl->hbm_wr_to_rd_arbitration_criteria, wr_to_rd_arbitration_criteria);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::configure_lpm()
{
    return configure_lpm(4, // bank_denied_threshold
                         15 // total_denied_threshold
                         );
}

la_status
la_hbm_handler_impl::configure_lpm(int bank_denied_threshold, int total_denied_threshold)
{
    gibraltar::mmu_lpm_bypass_config_register val{.u8 = {0}};
    val.fields.lpm_bypass_single_threshold = bank_denied_threshold;
    val.fields.lpm_bypass_sum_threshold = total_denied_threshold;
    la_status rc = m_ll_device->write_register(m_gb_tree->mmu->lpm_bypass_config, val);
    return_on_error(rc);

    for (size_t i = 0; i < m_gb_tree->mmu->lpm_replication_config->size(); ++i) {
        const auto& reg = (*m_gb_tree->mmu->lpm_replication_config)[i];
        gibraltar::mmu_lpm_replication_config_register val{.u8 = {0}};
        val.fields.lpm_start_bank_channel_offset = i * 4;
        val.fields.lpm_start_row_offset = i * 256;
        la_status rc = m_ll_device->write_register(reg, val);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::take_mmu_out_of_reset()
{
    bool is_hbm_lpm_enabled;
    m_device->get_bool_property(la_device_property_e::ENABLE_HBM_ROUTE_EXTENSION, is_hbm_lpm_enabled);
    if (!is_hbm_lpm_enabled) {
        la_status rc = m_ll_device->write_register(m_gb_tree->mmu->soft_reset_configuration, 1);
        return_on_error(rc);
    }

    la_status rc = m_ll_device->write_register(m_gb_tree->mmu_buff->soft_reset_configuration, 1);
    return rc;
}

la_status
la_hbm_handler_impl::configure_buffer_alloc(bool use_lpm)
{

    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
la_hbm_handler_impl::configure_buffer_alloc_post_reset(bool use_lpm)
{
    // THIS FUNCTION IS OUT OF DATE.
    // Make sure the FBM mapping is correct before calling it.
    auto valid_row_vector = bit_vector::ones(512);
    int total_buffers = 0x10000;

    if (use_lpm) {
        for (int row = 0; row < 512; ++row) {
            if ((row % 32) <= 1) {
                valid_row_vector.set_bit(row, 0);
            }
        }
        total_buffers = total_buffers - (32 * 128);
    }

    gibraltar::mmu_buff_cpu_occupy_buffers_register val{.u8 = {0}};
    // TODO: val.fields.valid_memory_lines = valid_row_vector;
    val.fields.total_free_buffers = total_buffers;
    for (size_t i = 0; i < m_gb_tree->mmu_buff->cpu_occupy_buffers->size(); ++i) {
        la_status rc = m_ll_device->write_register((*m_gb_tree->mmu_buff->cpu_occupy_buffers)[i], val);
        return_on_error(rc);
    }

    // remove last buffer
    val.fields.total_free_buffers = total_buffers - 1;
    la_status rc = m_ll_device->write_register((*m_gb_tree->mmu_buff->cpu_occupy_buffers)[15], val);

    return rc;
}

la_status
la_hbm_handler_impl::give_control_to_apb()
{
    gibraltar::hbm_hbm_clock_config_register hbm_clock_config;
    m_ll_device->read_register(m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);
    hbm_clock_config.fields.apb_clock_division = 6;
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_clock_config, hbm_clock_config);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_clock_config, hbm_clock_config);

    gibraltar::hbm_hbm_resets_register hbm_resets;
    m_ll_device->read_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);
    hbm_resets.fields.apb_rstn = 1;
    hbm_resets.fields.phy_rstn = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);

    gibraltar::hbm_apb_ctrl_register apb_ctrl{.u8 = {0}};
    apb_ctrl.fields.apb_ctrl_req = 1;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->apb_ctrl, apb_ctrl);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->apb_ctrl, apb_ctrl);
    this_thread::sleep_for(chrono::microseconds(10));
    apb_ctrl.fields.apb_ctrl_req = 0;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->apb_ctrl, apb_ctrl);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->apb_ctrl, apb_ctrl);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::give_control_to_ieee()
{
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->apb_ctrl, 3);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->apb_ctrl, 3);
    this_thread::sleep_for(chrono::microseconds(10));
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->apb_ctrl, 2);
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->apb_ctrl, 2);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::program_hbm_plls()
{
    uint32_t wr_data = 0;

    // program HBM PLLs (done here for 1.2 GHz)
    bit_utils::set_bits(wr_data, 10, 1, 47); // divf (=48)
    bit_utils::set_bits(wr_data, 18, 11, 0); // divq (=0)
    bit_utils::set_bits(wr_data, 24, 19, 0); // divr (=0)
    bit_utils::set_bits(wr_data, 27, 25, 4);

    la_status rc = apb_write(ESI_PLL_CFG_0, wr_data);
    return_on_error(rc);

    // allow PLL config
    rc = apb_write(ESI_PLL_CAP, 1);
    return_on_error(rc);

    // take PLL out of reset
    gibraltar::hbm_hbm_resets_register hbm_resets;
    m_ll_device->read_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);
    hbm_resets.fields.pll_rstn = 1;
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        m_ll_device->write_register(m_gb_tree->hbm->db[hbm]->hbm_resets, hbm_resets);
    }

    // wait for PLL lock
    this_thread::sleep_for(chrono::milliseconds(1));

    // Make sure PLL locked indication is up
    rc = apb_write(ESI_PLL_CAP, 0);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::take_hbm_channels_out_of_reset()
{
    for (const auto& hbm_chnl : m_gb_tree->hbm->chnl) {
        la_status rc = m_ll_device->write_register(hbm_chnl->soft_reset_configuration, 1);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::set_phy_to_mission_mode(bool set_wrstn_to_0)
{
    log_debug(HLD, "%s: set_wrstn_to_0=%d", __func__, set_wrstn_to_0);

    uint32_t force_cke_base_regs[8] = {ESI_AW_MAN_CFG_CK_CKE_A,
                                       ESI_AW_MAN_CFG_CK_CKE_B,
                                       ESI_AW_MAN_CFG_CK_CKE_C,
                                       ESI_AW_MAN_CFG_CK_CKE_D,
                                       ESI_AW_MAN_CFG_CK_CKE_E,
                                       ESI_AW_MAN_CFG_CK_CKE_F,
                                       ESI_AW_MAN_CFG_CK_CKE_G,
                                       ESI_AW_MAN_CFG_CK_CKE_H};
    uint32_t fifo_reset_base_regs[8] = {ESI_FIFO_RESET_AW_A,
                                        ESI_FIFO_RESET_AW_B,
                                        ESI_FIFO_RESET_AW_C,
                                        ESI_FIFO_RESET_AW_D,
                                        ESI_FIFO_RESET_AW_E,
                                        ESI_FIFO_RESET_AW_F,
                                        ESI_FIFO_RESET_AW_G,
                                        ESI_FIFO_RESET_AW_H};

    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(force_cke_base_regs[ch], 8);
    }

    // Set WRSTN to 0
    if (set_wrstn_to_0) {
        apb_write(0x80, 0x3);
    }

    // reset_phy_fifos
    for (size_t ch = 0; ch < 8; ++ch) {
        for (uint32_t dw = 0; dw < 5; ++dw) {
            apb_write(fifo_reset_base_regs[ch] + dw, 0);
        }
    }

    // remove dfi_rstn
    gibraltar::hbm_hbm_resets_register hbm_resets;
    m_ll_device->read_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    hbm_resets.fields.dfi_rstn = 0xff;
    m_ll_device->write_register(m_gb_tree->hbm->db[0]->hbm_resets, hbm_resets);
    m_ll_device->write_register(m_gb_tree->hbm->db[1]->hbm_resets, hbm_resets);

    this_thread::sleep_for(chrono::milliseconds(1));

    // write training done to MMU
    for (const auto& hbm_chnl : m_gb_tree->hbm->chnl) {
        m_ll_device->write_register(hbm_chnl->hbm_training_done, 1);
    }

    log_debug(HLD, "%s: done", __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::set_dll_rdqs(uint64_t value)
{
    la_status status = LA_STATUS_SUCCESS;

    for (int hbm = 0; hbm < 2; hbm++) {
        for (int ch = 0; ch < 8; ch++) {
            for (int dw = 0; dw < 4; dw++) {
                bit_vector bv;
                uint32_t reg_addr = DLL_RDQS_BASE + 0x20 * ch + dw;
                status = m_apb->read(1 << hbm, reg_addr, bv);
                return_on_error(status);
                bv.set_bits(15, 7, value);
                status = m_apb->write(1 << hbm, reg_addr, bv.get_value());
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::reset_phy_fifo()
{
    la_status status = LA_STATUS_SUCCESS;

    for (int hbm = 0; hbm < 2; hbm++) {
        for (int ch = 0; ch < 8; ch++) {
            for (int dw = 0; dw < 5; dw++) {
                uint32_t reg_addr = HBM_FIFO_RESET_BASE + 0x20 * ch + dw;
                status = m_apb->write(1 << hbm, reg_addr, 1);
                return_on_error(status);
                status = m_apb->write(1 << hbm, reg_addr, 0);
                return_on_error(status);
            }
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::print_values(uint32_t hbm_id)
{
    uint32_t addrs[] = {0x602, 0x622, 0x642, 0x662, 0x682, 0x6A2, 0x6C2, 0x6E2, 0x705, 0x706, 0x609, 0x629, 0x649, 0x669,
                        0x689, 0x6A9, 0x6C9, 0x6E9, 0x60A, 0x62A, 0x64A, 0x66A, 0x68A, 0x6AA, 0x6CA, 0x6EA, 0x60B, 0x62B,
                        0x64B, 0x66B, 0x68B, 0x6AB, 0x6CB, 0x6EB, 0x60D, 0x62D, 0x64D, 0x66D, 0x68D, 0x6AD, 0x6CD, 0x6ED};
    la_status status = LA_STATUS_SUCCESS;
    for (uint32_t reg_addr : addrs) {
        bit_vector bv;
        status = m_apb->read(1 << hbm_id, reg_addr, bv);
        return_on_error(status);
        log_debug(HLD, "%s: hbm_id=%u reg_addr=%u, reg_val=%lu", __func__, hbm_id, reg_addr, bv.get_value());
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::do_hbm_training(bool skip_training)
{
    log_debug(HLD, "%s: skip_training=%d", __func__, skip_training);

    uint32_t misrlb_runtime_base_reg[8] = {0xe00, 0xe20, 0xe40, 0xe60, 0xe80, 0xea0, 0xec0, 0xee0};
    uint32_t misrlb_cfg_aw_base_reg[8] = {0xe02, 0xe22, 0xe42, 0xe62, 0xe82, 0xea2, 0xec2, 0xee2};
    // uint32_t training_minrange_ck_base_reg[8] = {0x600, 0x620, 0x640, 0x660, 0x680, 0x6a0, 0x6c0, 0x6e0};
    uint32_t training_minrange_wdqs_base_reg[8] = {0x601, 0x621, 0x641, 0x661, 0x681, 0x6a1, 0x6c1, 0x6e1};
    uint32_t training_minrange_rdqs_base_reg[8] = {0x602, 0x622, 0x642, 0x662, 0x682, 0x6a2, 0x6c2, 0x6e2};
    uint32_t training_minrange_rdsel_base_reg[8] = {0x603, 0x623, 0x643, 0x663, 0x683, 0x6a3, 0x6c3, 0x6e3};
    uint32_t misrlb_cfg_dw_base_reg[8] = {0xe07, 0xe27, 0xe47, 0xe67, 0xe87, 0xea7, 0xec7, 0xee7};
    // uint32_t repair_dw_base_reg[8] = {0xa01, 0xa21, 0xa41, 0xa61, 0xa81, 0xaa1, 0xac1, 0xae1};
    uint32_t aw_man_cfg_base_reg[8] = {0xd00, 0xd20, 0xd40, 0xd60, 0xd80, 0xda0, 0xdc0, 0xde0};
    uint32_t fifo_reset_base_regs[8] = {0xb01, 0xb21, 0xb41, 0xb61, 0xb81, 0xba1, 0xbc1, 0xbe1};
    uint32_t runtime = 2000;

    if (skip_training) {
        // Leave all DLL values at 60
        // Must set RDSEL value to 33
        for (size_t ch = 0; ch < 8; ++ch) {
            for (uint32_t ad = 0; ad < 4; ++ad) {
                bit_vector bv;
                m_apb->read(1 << 0, 0xc00 + ad, bv);
                bv.set_bits(5, 0, 33);
                apb_write(0xc00 + ad, bv.get_value());
            }
        }
        return LA_STATUS_SUCCESS;
    }

    uint32_t cdk_dll_start = 0;
    uint32_t cdk_dll_end = 0x1ff;
    // uint32_t user_cfg_phy_train_repair_en = 1;
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        m_apb->write(1 << hbm, ESI_TRAINING_DOREPAIR, 1);
        m_apb->write(1 << hbm, ESI_TRAINING_DONE, 0);
        m_apb->write(1 << hbm, ESI_TRAINING_TYPE, 0);
        m_apb->write(1 << hbm, ESI_TRAINING_CHANNEL_ENAB, 0xff);
        m_apb->write(1 << hbm, ESI_TRAINING_DLL_RANGE, ((cdk_dll_end << 16) | cdk_dll_start));
        m_apb->write(1 << hbm, ESI_TRAINING_GO, 1);

        la_status rc = poll_training_completion(hbm);
        return_on_error_log(rc, HLD, ERROR, "%s 1: HBM %ld, poll_training_completion result => %d", __func__, hbm, rc.value());
    }

    uint32_t write_latency = 8;
    uint32_t start_delay = 11;
    uint32_t cmd2cmd_latency = 0;
    uint32_t cfg_dly = start_delay | (write_latency << 8) | (cmd2cmd_latency << 16);
    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(misrlb_runtime_base_reg[ch], runtime);
        apb_write(misrlb_runtime_base_reg[ch] + 1, 0);
        apb_write(misrlb_cfg_aw_base_reg[ch], 4);           // This is dw_test_cfg
        apb_write(misrlb_cfg_aw_base_reg[ch] + 1, cfg_dly); // This is aw_misr_data
        apb_write(training_minrange_wdqs_base_reg[ch], 0xa);
        for (uint32_t dw = 0; dw < 4; ++dw) {
            apb_write(misrlb_cfg_dw_base_reg[ch] + (dw * 6), 4);
            apb_write(misrlb_cfg_dw_base_reg[ch] + (dw * 6) + 1, cfg_dly);
        }
    }

    uint32_t wdqs_dll_start = 0;
    uint32_t wdqs_dll_end = 150;
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        m_apb->write(1 << hbm, ESI_TRAINING_DOREPAIR, 1);
        m_apb->write(1 << hbm, ESI_TRAINING_DONE, 0);
        m_apb->write(1 << hbm, ESI_TRAINING_TYPE, 1);
        m_apb->write(1 << hbm, ESI_TRAINING_CHANNEL_ENAB, 0xff);
        m_apb->write(1 << hbm, ESI_TRAINING_DLL_RANGE, ((wdqs_dll_end << 16) | wdqs_dll_start));
        m_apb->write(1 << hbm, ESI_TRAINING_GO, 1);

        la_status rc = poll_training_completion(hbm);
        return_on_error_log(rc, HLD, ERROR, "%s 2: HBM %ld, poll_training_completion result => %d", __func__, hbm, rc.value());
    }

    ////////
    // RDQS training
    ////////

    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(misrlb_runtime_base_reg[ch], 0x1ff);
        apb_write(misrlb_runtime_base_reg[ch] + 1, 0);
        apb_write(misrlb_cfg_aw_base_reg[ch], 4);
        apb_write(misrlb_cfg_aw_base_reg[ch] + 1, cfg_dly);
        apb_write(training_minrange_rdqs_base_reg[ch], 0xa);
        for (uint32_t dw = 0; dw < 4; ++dw) {
            apb_write(misrlb_cfg_dw_base_reg[ch] + (dw * 6), 4);
            apb_write(misrlb_cfg_dw_base_reg[ch] + (dw * 6) + 1, cfg_dly);
        }
    }

    uint32_t rdqs_dll_start = 0;
    uint32_t rdqs_dll_end = 160;
    uint32_t rd_sel_start = 30;
    uint32_t rd_sel_end = 38;
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        m_apb->write(1 << hbm, ESI_TRAINING_DOREPAIR, 1);
        m_apb->write(1 << hbm, ESI_TRAINING_DONE, 0);
        m_apb->write(1 << hbm, ESI_TRAINING_TYPE, 2);
        m_apb->write(1 << hbm, ESI_TRAINING_CHANNEL_ENAB, 0xff);
        m_apb->write(1 << hbm, ESI_TRAINING_DLL_RANGE, ((rdqs_dll_end << 16) | rdqs_dll_start));
        m_apb->write(1 << hbm, 0x706, ((rd_sel_end << 16) | rd_sel_start));
        m_apb->write(1 << hbm, ESI_TRAINING_GO, 1);

        la_status rc = poll_training_completion(hbm);
        return_on_error_log(rc, HLD, ERROR, "%s RDQS: HBM %ld, poll_training_completion result => %d", __func__, hbm, rc.value());
    }

    ////////
    // RDSEL training
    ////////
    rd_sel_start = 30;
    rd_sel_end = 38;
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        m_apb->write(1 << hbm, ESI_TRAINING_DONE, 0);
        m_apb->write(1 << hbm, ESI_TRAINING_TYPE, 3);
        m_apb->write(1 << hbm, ESI_TRAINING_CHANNEL_ENAB, 0xff);
        m_apb->write(1 << hbm, 0x706, (rd_sel_end << 16) | rd_sel_start);
        m_apb->write(1 << hbm, 0x70a, 2); // use PL value here
        for (size_t ch = 0; ch < 8; ++ch) {
            m_apb->write(1 << hbm, training_minrange_rdsel_base_reg[ch], 2);
            m_apb->write(1 << hbm, ESI_TRAINING_GO, 1);
        }

        la_status rc = poll_training_completion(hbm);
        return_on_error_log(rc, HLD, ERROR, "%s RDSEL: HBM %ld, poll_training_completion result => %d", __func__, hbm, rc.value());
    }

    // Return control to M/C
    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(aw_man_cfg_base_reg[ch], 8);
    }

    // Assert WRSTN
    apb_write(0x80, 3);

    // Reset FIFO
    for (size_t ch = 0; ch < 8; ++ch) {
        for (uint32_t dw = 0; dw < 4; ++dw) {
            apb_write(fifo_reset_base_regs[ch] + dw, 1);
            apb_write(fifo_reset_base_regs[ch] + dw, 0);
        }
    }

    log_debug(HLD, "%s: done", __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::do_hbm_training_manual(bool override_vals, vector<uint32_t>& dll_vals)
{
    log_debug(HLD, "%s: override_vals=%d", __func__, override_vals);

    uint32_t aw_man_cfg_base_reg[8] = {0xd00, 0xd20, 0xd40, 0xd60, 0xd80, 0xda0, 0xdc0, 0xde0};
    uint32_t fifo_reset_base_regs[8] = {0xb01, 0xb21, 0xb41, 0xb61, 0xb81, 0xba1, 0xbc1, 0xbe1};

    size_t i = 0;
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        for (size_t ch = 0; ch < 8; ++ch) {
            for (size_t ad = 0; ad < 9; ++ad) {
                bit_vector addr(ad);
                addr.set_bits(11, 8, 8);
                addr.set_bits(7, 4, ch * 2);
                bit_vector bv;
                m_apb->read(1 << hbm, addr.get_value(), bv);
                if (override_vals == false) {
                    bv.set_bits(15, 7, 60);
                } else {
                    bv.set_bits(15, 7, dll_vals[i]);
                }
                m_apb->write(1 << hbm, addr.get_value(), bv);
                i++;
            }

            // RDSEL setting
            for (size_t ad = 0; ad < 4; ++ad) {
                bit_vector addr(ad);
                addr.set_bits(11, 8, 0xc);
                addr.set_bits(7, 4, ch * 2);
                bit_vector bv;
                m_apb->read(1 << hbm, addr.get_value(), bv);
                bv.set_bits(5, 0, 33);
                m_apb->write(1 << hbm, addr.get_value(), bv);
            }
        }
    }

    // Return control to M/C
    for (size_t ch = 0; ch < 8; ++ch) {
        apb_write(aw_man_cfg_base_reg[ch], 8);
    }

    // Assert WRSTN
    apb_write(0x80, 3);

    // Reset FIFO
    for (size_t ch = 0; ch < 8; ++ch) {
        for (uint32_t dw = 0; dw < 4; ++dw) {
            apb_write(fifo_reset_base_regs[ch] + dw, 1);
            apb_write(fifo_reset_base_regs[ch] + dw, 0);
        }
    }

    log_debug(HLD, "%s: done", __func__);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::apply_post_init_config_workaround()
{
    // This should move to LBR init once frequency dependent expressions are supported.
    return set_dram_meter(HBM_RATE_DEFAULT * 1e9, HBM_EVICTION_RATE_DEFAULT * 1e9);
}

la_status
la_hbm_handler_impl::set_dram_meter(la_rate_t rate, la_rate_t eviction_rate)
{
    float frequency_ghz = m_device->m_device_frequency_float_ghz;
    float capacity = frequency_ghz * 8 * 1e9;

    if (rate < capacity || eviction_rate < capacity) {
        log_err(HLD,
                "%s: frequency_ghz=%f, rate=%llu bps, eviction_rate=%llu - rate too low",
                __func__,
                frequency_ghz,
                rate,
                eviction_rate);
        return LA_STATUS_EOUTOFRANGE;
    }

    log_debug(HLD, "%s: frequency_ghz=%f, rate=%llu bps, eviction_rate=%llu", __func__, frequency_ghz, rate, eviction_rate);

    // Initialize only frequency-dependent fields. The rest are set in LBR init.

    gibraltar::ics_top_dram_write_eligible_meter_register val0;
    la_status rc = m_ll_device->read_register(m_gb_tree->ics_top->dram_write_eligible_meter, val0);
    return_on_error(rc);

    val0.fields.dram_write_elig_meter_inc_value = int(rate / capacity);
    rc = m_ll_device->write_register(m_gb_tree->ics_top->dram_write_eligible_meter, val0);
    return_on_error(rc);

    gibraltar::ics_top_dram_write_meter_register val1;
    rc = m_ll_device->read_register(m_gb_tree->ics_top->dram_write_meter, val1);
    return_on_error(rc);

    val1.fields.dram_write_meter_inc_value = int(eviction_rate / capacity);
    rc = m_ll_device->write_register(m_gb_tree->ics_top->dram_write_meter, val1);
    return_on_error(rc);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::clear_hbm_error_counters()
{
    bit_vector bv;

    // Counters are cleared on read.
    for (size_t hbm = 0; hbm < 2; ++hbm) {
        for (size_t ch = 0; ch < 8; ++ch) {
            m_ll_device->read_register((*m_gb_tree->hbm->db[hbm]->hbm_error_counters)[ch], bv);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::clear_hbm_channel_interrupts()
{
    gibraltar::hbm_channel_interrupts_register channel_interrupts_val{
        .fields = {.async_fifo_underflow = 1, .async_fifo_overflow = 1, .address_parity_error = 1, .one_bit_ecc_error = 1}};

    gibraltar::hbm_general_interrupt_register_register gen_interrupt_val{.fields = {.cattrip_interrupt = 1}};

    for (size_t hbm = 0; hbm < 2; ++hbm) {
        for (size_t ch = 0; ch < 8; ++ch) {
            m_ll_device->write_register((*m_gb_tree->hbm->db[hbm]->channel_interrupts)[ch], channel_interrupts_val);
        }
        m_ll_device->write_register(m_gb_tree->hbm->db[hbm]->general_interrupt_register, gen_interrupt_val);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::clear_mmu_error_counters()
{
    bit_vector bv;

    // counters are cleared on read
    m_ll_device->read_register(m_gb_tree->mmu->debug_counters, bv);
    m_ll_device->read_register(m_gb_tree->mmu->error_counters, bv);
    m_ll_device->read_register(m_gb_tree->mmu->error_buffer_valids, bv);
    m_ll_device->read_register(m_gb_tree->mmu->lpm_error_buffer_valids, bv);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::clear_mmu_interrupts()
{
    gibraltar::mmu_general_interrupt_register_register val{.u8 = {0}};
    val.fields.mmu_has_error_buffer_interrupt = 1;
    val.fields.lpm_has_error_buffer_interrupt = 1;
    m_ll_device->write_register(m_gb_tree->mmu->general_interrupt_register, val);

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::reset_dram()
{
    la_status rc;
    uint32_t force_cke_base_regs[8] = {ESI_AW_MAN_CFG_CK_CKE_H,
                                       ESI_AW_MAN_CFG_CK_CKE_G,
                                       ESI_AW_MAN_CFG_CK_CKE_F,
                                       ESI_AW_MAN_CFG_CK_CKE_E,
                                       ESI_AW_MAN_CFG_CK_CKE_D,
                                       ESI_AW_MAN_CFG_CK_CKE_C,
                                       ESI_AW_MAN_CFG_CK_CKE_B,
                                       ESI_AW_MAN_CFG_CK_CKE_A};

    // phy_force_cke_low
    for (int ch = 0; ch < 8; ++ch) {
        rc = apb_write(force_cke_base_regs[ch], 0x2);
        return_on_error(rc);
    }

    // wait tINIT2 before raising reset (only 10ns)
    this_thread::sleep_for(chrono::nanoseconds(10));

    // RESET_N output to HBM die
    rc = apb_write(ESI_HBM_RESET_CONTROL, 0x3); // RESET_N force
    return_on_error(rc);

    rc = apb_write(ESI_HBM_RESET_CONTROL, 0x7); // raise WRSTN
    return_on_error(rc);

    // wait tINIT3 before raising CKE (will be high due to async FIFO reads)
    this_thread::sleep_for(chrono::microseconds(500));

    // phy_release_cke
    for (int ch = 0; ch < 8; ch++) {
        rc = apb_write(force_cke_base_regs[ch], 0x0);
        return_on_error(rc);
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_hbm_handler_impl::poll_training_completion(size_t hbm_i)
{
    log_debug(HLD, "%s: HBM index=%ld", __func__, hbm_i);

    bool train_done = false;
    for (size_t retry = 0; !train_done && retry < HBM_TRAIN_POLL_MAX_RETRY; ++retry) {
        this_thread::sleep_for(chrono::milliseconds(HBM_TRAIN_POLL_INTERVAL_MILLISECONDS));
        bit_vector rd_data;
        m_apb->read(1 << hbm_i, ESI_TRAINING_DONE, rd_data);
        train_done = rd_data.bit(0);
        if (train_done) {
            log_debug(HLD, "%s: HBM index=%ld, training done after %ld retries", __func__, hbm_i, retry);
        }
    }

    bit_vector rd_data;
    m_apb->read(1 << hbm_i, ESI_TRAINING_OK, rd_data);
    if (!train_done || rd_data.get_value() != 0xff) {
        log_debug(
            HLD, "%s: HBM index=%ld, training failed, done=%d, rd_data=0x%lx", __func__, hbm_i, train_done, rd_data.get_value());
        return LA_STATUS_EUNKNOWN;
    }

    log_debug(HLD, "%s: training passed", __func__);
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
