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

#include "cpu2jtag_drive_signals.h"
#include "common/gen_utils.h"
#include "common/la_lock_guard.h"
#include "common/logger.h"
#include "lld/ll_device.h"
#include "lld/pacific_reg_structs.h"

#include <chrono>
#include <thread>

using namespace std;

namespace silicon_one
{

// TAP clock (TCK) high/low setup time
static constexpr auto TAP_WAIT_TCK_LOW = chrono::microseconds(1);
static constexpr auto TAP_WAIT_TCK_HIGH = chrono::microseconds(1);

cpu2jtag_drive_signals::cpu2jtag_drive_signals(ll_device_sptr ldev, uint8_t ir_width_bits)
    : cpu2jtag_impl(ldev, ir_width_bits), m_sbif(ldev->get_pacific_tree() ? ldev->get_pacific_tree()->sbif : nullptr)
{
}

la_status
cpu2jtag_drive_signals::enable(uint32_t core_frequency_khz, uint32_t tck_frequency_mhz)
{
    start_cpu2jtag_call("%s: core_frequency_khz=%d, tck_frequency_mhz=%d", __func__, core_frequency_khz, tck_frequency_mhz);

    if (m_ll_device->is_asic5()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    sbif_tap_control_reg_register val{{0}};
    val.fields.tap_override_en = 1;
    la_status rc = m_ll_device->write_register(*m_sbif->tap_control_reg, val);
    return_on_error(rc);

    rc = reset();

    return rc;
}

la_status
cpu2jtag_drive_signals::disable()
{
    start_cpu2jtag_call("%s", __func__);

    if (m_ll_device->is_asic5()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    sbif_tap_control_reg_register val{{0}}; // zero
    la_status rc = m_ll_device->write_register(*m_sbif->tap_control_reg, val);

    return rc;
}

la_status
cpu2jtag_drive_signals::reset()
{
    log_debug(CPU2JTAG, "%s", __func__);

    la_status rc = deassert_reset();
    rc = rc ?: assert_reset();
    rc = rc ?: deassert_reset();

    return rc;
}

la_status
cpu2jtag_drive_signals::deassert_reset()
{
    return exec_jtag_cycle({.tms = 0, .tdi = 0, .trst = 1, .tck = 1}, nullptr);
}

la_status
cpu2jtag_drive_signals::assert_reset()
{
    return exec_jtag_cycle({.tms = 0, .tdi = 0, .trst = 0, .tck = 1}, nullptr);
}

la_status
cpu2jtag_drive_signals::drive_tms_tdi_seq(const tap1149::tms_tdi_seq& tms_tdi, bit_vector& out_tdo)
{
    if (tms_tdi.empty()) {
        return LA_STATUS_EINVAL;
    }

    bit_vector tdo(0, tms_tdi.size());
    bool prev_tdo;

    size_t i;
    exec_jtag_cycle({.tms = tms_tdi[0].tms, .tdi = tms_tdi[0].tdi, .trst = 1, .tck = 1}, &prev_tdo);
    for (i = 1; i < tms_tdi.size(); ++i) {
        exec_jtag_cycle({.tms = tms_tdi[i].tms, .tdi = tms_tdi[i].tdi, .trst = 1, .tck = 1}, &prev_tdo);
        tdo.set_bit(i - 1, prev_tdo);
    }
    exec_jtag_cycle({.tms = tms_tdi[i - 1].tms, .tdi = tms_tdi[i - 1].tdi, .trst = 1, .tck = 0}, &prev_tdo);
    tdo.set_bit(i - 1, prev_tdo);

    out_tdo = tdo;

    return LA_STATUS_SUCCESS;
}

la_status
cpu2jtag_drive_signals::exec_jtag_cycle(cpu2jtag_drive_signals::tap_signals_in in, bool* out_tdo)
{
    if (m_ll_device->is_asic5()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    sbif_tap_override_cfg_reg_register cfg{.fields = {.tap_override_mode = 0,
                                                      .tap_override_tck = 0,
                                                      .tap_override_tdi = in.tdi,
                                                      .tap_override_tms = in.tms,
                                                      .tap_override_trst_l = in.trst}};
    m_ll_device->write_register(*m_sbif->tap_override_cfg_reg, cfg);

    this_thread::sleep_for(TAP_WAIT_TCK_LOW);

    if (out_tdo) {
        sbif_tap_override_status_reg_register val;
        m_ll_device->read_register(*m_sbif->tap_override_status_reg, val);
        *out_tdo = (bool)val.fields.tap_override_tdo;
    }

    if (in.tck) {
        cfg.fields.tap_override_tck = 1;
        m_ll_device->write_register(*m_sbif->tap_override_cfg_reg, cfg);
    }

    this_thread::sleep_for(TAP_WAIT_TCK_HIGH);

    return LA_STATUS_SUCCESS;
}

la_status
cpu2jtag_drive_signals::do_load_ir(const bit_vector& ir)
{
    auto seq = tap1149::get_tms_tdi_seq_set_ir(m_ir_width_bits, ir);

    log_xdebug(CPU2JTAG, "%s: bits=%d, ir=0x%s", __func__, m_ir_width_bits, ir.to_string().c_str());
    tap1149::dump_tms_tdi_seq(seq);

    bit_vector tdo;
    la_status rc = drive_tms_tdi_seq(seq, tdo);
    return_on_error(rc);

    log_debug(CPU2JTAG, "%s: ir_tdo=0x%s", __func__, tdo.to_string().c_str());

    return LA_STATUS_SUCCESS;
}

la_status
cpu2jtag_drive_signals::do_load_ir_dr(const bit_vector& ir, size_t dr_width_bits, const bit_vector& dr, bit_vector* out_tdo)
{
    la_status rc = do_load_ir(ir);
    return_on_error(rc);

    auto seq = tap1149::get_tms_tdi_seq_set_dr(dr_width_bits, dr);
    log_xdebug(CPU2JTAG, "%s: bits=%ld, dr=0x%s", __func__, dr_width_bits, dr.to_string().c_str());
    tap1149::dump_tms_tdi_seq(seq);

    bit_vector dr_tdo_full;
    rc = drive_tms_tdi_seq(seq, dr_tdo_full);
    return_on_error(rc);

    bit_vector dr_tdo = dr_tdo_full.bits(dr_width_bits + 1, 2);
    log_debug(CPU2JTAG, "%s: dr_tdo=0x%s", __func__, dr_tdo.to_string().c_str());

    if (out_tdo) {
        *out_tdo = dr_tdo;
    }

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
