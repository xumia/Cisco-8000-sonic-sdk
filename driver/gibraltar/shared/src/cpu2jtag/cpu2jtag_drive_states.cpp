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

#include "cpu2jtag_drive_states.h"
#include "common/gen_utils.h"
#include "common/la_lock_guard.h"
#include "common/logger.h"
#include "lld/gibraltar_reg_structs.h"
#include "lld/ll_device.h"

#include <chrono>
#include <thread>

using namespace std;

namespace silicon_one
{

// JTAG TAP states
enum jtag_tap_state_e {
    TAP_STATE_LOAD_IR = 0x2, ///< TAP Load Instruction Register state.
    TAP_STATE_LOAD_DR = 0x3, ///< TAP Load Data Register state.
};

// JTAG WRCK opcode
enum jtag_dr_wrck_e {
    WRCK_BITS = 2,              ///< width in bits
    WRCK_OVERRIDE = 1 << 0,     ///< WRCK override
    WRCK_GATE_DISABLE = 1 << 1, ///< WRCK gate disable
};

// Maximum polling count on CPU2JTAG completion.
enum { CPU2JTAG_POLL_COMPLETION_MAX = 1000 };

cpu2jtag_drive_states::cpu2jtag_drive_states(ll_device_sptr ldev, uint8_t ir_width_bits) : cpu2jtag_impl(ldev, ir_width_bits)
{
    gibraltar_tree_scptr gibraltar_tree = ldev->get_gibraltar_tree_scptr();

    m_cpu_jtag_cfg_reg = gibraltar_tree->sbif->cpu_jtag_cfg_reg;
    m_cpu_jtag_ctrl_reg = gibraltar_tree->sbif->cpu_jtag_control_reg;
    m_cpu_jtag_override_reg = gibraltar_tree->top_regfile->jtag_override_reg;
    m_cpu_jtag_status_reg = gibraltar_tree->sbif->cpu_jtag_status_reg;
    m_cpu_jtag_ir_dr_len_reg = gibraltar_tree->sbif->cpu_jtag_ir_dr_length_reg;
    m_cpu_jtag_ir_dr_val_reg = gibraltar_tree->sbif->cpu_jtag_ir_dr_value_reg;
    m_cpu_jtag_data_out_reg0 = gibraltar_tree->sbif->cpu_jtag_test_data_out_reg0;
    m_cpu_jtag_data_out_reg1 = gibraltar_tree->sbif->cpu_jtag_test_data_out_reg1;
}

la_status
cpu2jtag_drive_states::enable(uint32_t core_frequency_khz, uint32_t tck_frequency_mhz)
{
    start_cpu2jtag_call("%s: core_frequency_khz=%d, tck_frequency_mhz=%d", __func__, core_frequency_khz, tck_frequency_mhz);

    la_status rc = configure(core_frequency_khz, tck_frequency_mhz);
    return_on_error(rc);

    rc = reset();
    return_on_error(rc);

    rc = set_jtag_pads_override(true);
    return_on_error(rc);

    rc = set_wrck_gate_override(true);
    return_on_error(rc);

    return rc;
}

la_status
cpu2jtag_drive_states::disable()
{
    start_cpu2jtag_call("%s", __func__);

    la_status rc = set_wrck_gate_override(false);
    rc = rc ?: set_jtag_pads_override(false);

    return_on_error(rc);

    return rc;
}

enum cpu2jtag_constants_e {
    CORE_TO_CSS_CLOCK_DIVIDER = 2, // CSS frequency = CORE frequency / CORE_TO_CSS_CLOCK_DIVIDER
};

la_status
cpu2jtag_drive_states::configure(uint32_t core_frequency_khz, uint32_t tck_frequency)
{
    uint32_t css_frequency = core_frequency_khz / 1000
                             / CORE_TO_CSS_CLOCK_DIVIDER; // Added division by 1000 so units will be MHz same as tck_frequency
    uint16_t tck_clock_divider = (uint16_t)((css_frequency / tck_frequency / 2) - 1);

    // Temporary fix
    if (m_ll_device->is_asic3()) {
        tck_clock_divider = 6; // Set TCK frequency to 8.33MHz
    }

    log_debug(CPU2JTAG, "%s: core_frequency_khz=%d, tck_clock_divider=%hd", __func__, core_frequency_khz, tck_clock_divider);

    if (m_ll_device->is_asic5() || m_ll_device->is_asic4()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    // All zeros, including cpu_jtag_reset
    la_status rc = m_ll_device->write_register(*m_cpu_jtag_cfg_reg, 0);
    return_on_error(rc);
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, 0);
    return_on_error(rc);

    // Let the "reset" propagate
    this_thread::sleep_for(chrono::microseconds(1));

    // GR's top_cpu_jtag_cfg_reg_register is exactly the same struct
    gibraltar::sbif_cpu_jtag_cfg_reg_register jtag_cfg{{0}};

    jtag_cfg.fields.cpu_jtag_switch_mode = 0;
    jtag_cfg.fields.cpu_jtag_free_run_tck_mode = 1;
    jtag_cfg.fields.cpu_jtag_config_done = 0;
    jtag_cfg.fields.cpu_jtag_debug_enable = 0;
    jtag_cfg.fields.cpu_jtag_tdo_enable_type = 1;
    jtag_cfg.fields.cpu_jtag_disable_tdo_enable_type = 0;
    jtag_cfg.fields.cpu_jtag_tck_clock_divider = tck_clock_divider;
    jtag_cfg.fields.cpu_jtag_reset = 0;

    // config done == 0
    rc = m_ll_device->write_register(*m_cpu_jtag_cfg_reg, jtag_cfg);
    return_on_error(rc);

    // config done == 1
    jtag_cfg.fields.cpu_jtag_config_done = 1;
    jtag_cfg.fields.cpu_jtag_reset = 1;
    rc = m_ll_device->write_register(*m_cpu_jtag_cfg_reg, jtag_cfg);
    return_on_error(rc);

    // Let the "out-of-reset" propagate
    this_thread::sleep_for(chrono::microseconds(1));

    return rc;
}

la_status
cpu2jtag_drive_states::reset()
{
    log_debug(CPU2JTAG, "%s", __func__);

    if (m_ll_device->is_asic5() || m_ll_device->is_asic4()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    la_status rc;
    // GR's top_cpu_jtag_cfg_reg_register is exactly the same struct
    gibraltar::sbif_cpu_jtag_control_reg_register jtag_control{{0}};

    jtag_control.fields.cpu_jtag_execute = 0;
    jtag_control.fields.cpu_jtag_go_to_tap_state = 4; // ASSERT_TRST
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
    return_on_error(rc);

    jtag_control.fields.cpu_jtag_execute = 1;
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
    return_on_error(rc);

    rc = wait_for_done("ASSERT_TRST");
    return_on_error(rc);

    jtag_control.fields.cpu_jtag_execute = 0;
    jtag_control.fields.cpu_jtag_go_to_tap_state = 5; // DEASSERT_TRST
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
    return_on_error(rc);

    jtag_control.fields.cpu_jtag_execute = 1;
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
    return_on_error(rc);

    rc = wait_for_done("DEASSERT_TRST");
    return_on_error(rc);

    jtag_control.fields.cpu_jtag_execute = 0;
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);

    return rc;
}

la_status
cpu2jtag_drive_states::set_jtag_pads_override(bool en)
{
    lld_register_sptr override_reg;

    log_debug(CPU2JTAG, "%s: enable=%d", __func__, en);

    if (m_ll_device->is_asic5() || m_ll_device->is_asic4()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    gibraltar::top_jtag_override_reg_register val{{0}};
    val.fields.cpu_jtag_override = (int)en;
    // what about mcu_jtag_mode which is only in GB? not the exact same struct
    la_status rc = m_ll_device->write_register(*m_cpu_jtag_override_reg, val);
    return_on_error(rc);

    return rc;
}

la_status
cpu2jtag_drive_states::set_wrck_gate_override(bool en)
{
    bit_vector ir_wrck((uint64_t)jtag_ir_e::WRCK);
    bit_vector tdo;
    la_status rc;

    if (en) {
        log_debug(CPU2JTAG, "%s: setting wrck_gate_disable = 1, wrck_override = 0", __func__);
        rc = load_ir_dr(ir_wrck, WRCK_BITS, WRCK_GATE_DISABLE, tdo);
        return_on_error(rc);

        log_debug(CPU2JTAG, "%s: setting wrck_gate_disable = 1, wrck_override = 1", __func__);
        rc = load_ir_dr(ir_wrck, WRCK_BITS, WRCK_GATE_DISABLE | WRCK_OVERRIDE, tdo);
        return_on_error(rc);

        log_debug(CPU2JTAG, "%s: setting wrck_gate_disable = 0, wrck_override = 1", __func__);
        rc = load_ir_dr(ir_wrck, WRCK_BITS, WRCK_OVERRIDE, tdo);
        return_on_error(rc);
    } else {
        log_debug(CPU2JTAG, "%s: setting wrck_gate_disable = 1, wrck_override = 1", __func__);
        rc = load_ir_dr(ir_wrck, WRCK_BITS, WRCK_GATE_DISABLE | WRCK_OVERRIDE, tdo);

        log_debug(CPU2JTAG, "%s: setting wrck_gate_disable = 1, wrck_override = 0", __func__);
        rc = load_ir_dr(ir_wrck, WRCK_BITS, WRCK_GATE_DISABLE, tdo);

        log_debug(CPU2JTAG, "%s: setting wrck_gate_disable = 0, wrck_override = 0", __func__);
        rc = load_ir_dr(ir_wrck, WRCK_BITS, 0, tdo);
        return_on_error(rc);
    }

    return rc;
}

la_status
cpu2jtag_drive_states::do_load_ir(const bit_vector& ir)
{
    if (m_ll_device->is_asic5() || m_ll_device->is_asic4()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    la_status rc;
    gibraltar::sbif_cpu_jtag_control_reg_register jtag_control{{0}};

    jtag_control.fields.cpu_jtag_execute = 0;
    jtag_control.fields.cpu_jtag_go_to_tap_state = TAP_STATE_LOAD_IR;
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
    return_on_error(rc);

    rc = m_ll_device->write_register(*m_cpu_jtag_ir_dr_len_reg, m_ir_width_bits);
    return_on_error(rc);

    rc = m_ll_device->write_register(*m_cpu_jtag_ir_dr_val_reg, ir);
    return_on_error(rc);

    jtag_control.fields.cpu_jtag_execute = 1;
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
    return_on_error(rc);

    rc = wait_for_done("LOAD_IR");
    return_on_error(rc);

    jtag_control.fields.cpu_jtag_execute = 0;
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);

    return rc;
}

la_status
cpu2jtag_drive_states::do_load_ir_dr(const bit_vector& ir, size_t dr_width_bits, const bit_vector& dr, bit_vector* out_bv)
{
    size_t count = bit_utils::width_bits_to_dwords(dr_width_bits);

    log_debug(CPU2JTAG,
              "%s: ir=0x%s, bits=%ld, dwords=%ld, dr=0x%s",
              __func__,
              ir.to_string().c_str(),
              dr_width_bits,
              count,
              dr.to_string().c_str());

    if (m_ll_device->is_asic5() || m_ll_device->is_asic4()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    la_status rc = do_load_ir(ir);
    return_on_error(rc);

    gibraltar::sbif_cpu_jtag_control_reg_register jtag_control{{0}};

    jtag_control.fields.cpu_jtag_execute = 0;
    jtag_control.fields.cpu_jtag_go_to_tap_state = TAP_STATE_LOAD_DR;
    rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
    return_on_error(rc);

    rc = m_ll_device->write_register(*m_cpu_jtag_ir_dr_len_reg, dr_width_bits);
    return_on_error(rc);

    bit_vector tdo;
    for (size_t write_lsb = 0; write_lsb < count * 32; write_lsb += 32) {
        bit_vector write_value = dr.bits(write_lsb + 31, write_lsb);

        log_xdebug(CPU2JTAG, "%s: write_lsb=%ld, write_value=0x%s", __func__, write_lsb, write_value.to_string().c_str());
        rc = m_ll_device->write_register(*m_cpu_jtag_ir_dr_val_reg, write_value);
        return_on_error(rc);

        jtag_control.fields.cpu_jtag_execute = 1;
        rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
        return_on_error(rc);

        // At this point jtag_status "busy" toggles 0->1

        if ((write_lsb + 32) == count * 32) {
            // A full dr_value has been pushed.
            // Wait for the JTAG to become non-busy + "done".
            rc = wait_for_done("LOAD_DR");
            return_on_error(rc);
        } else {
            // Intermediate dword of dr_value has been pushed.
            // Wait for the JTAG to become non-busy, but without "done".
            bool done_tmp;
            rc = wait_for_non_busy("LOAD_DR", done_tmp);
            return_on_error(rc);
        }

        if (out_bv) {
            bit_vector bv;
            rc = read_tdo(bv);
            return_on_error(rc);

            // Accumulate test-data-out
            tdo = (bv << tdo.get_width()) | tdo;
        }

        jtag_control.fields.cpu_jtag_execute = 0;
        rc = m_ll_device->write_register(*m_cpu_jtag_ctrl_reg, jtag_control);
        return_on_error(rc);
    }

    if (out_bv) {
        *out_bv = tdo;
        log_debug(CPU2JTAG, "%s: bits=%ld, TDO=0x%s", __func__, out_bv->get_width(), out_bv->to_string().c_str());
    }

    return LA_STATUS_SUCCESS;
}

la_status
cpu2jtag_drive_states::read_tdo(bit_vector& out_bv) const
{
    if (m_ll_device->is_asic5() || m_ll_device->is_asic4()) {
        // ASIC5::FIXME
        return LA_STATUS_SUCCESS;
    }

    // Lower 32 bits
    // same struct in GR
    gibraltar::sbif_cpu_jtag_test_data_out_reg0_register reg0{{0}};
    la_status rc = m_ll_device->read_register(*m_cpu_jtag_data_out_reg0, reg0);
    return_on_error(rc);

    // Higher 26 bits + the index of the most significant valid bit.
    // same struct in GR
    gibraltar::sbif_cpu_jtag_test_data_out_reg1_register reg1{{0}};
    rc = m_ll_device->read_register(*m_cpu_jtag_data_out_reg1, reg1);

    return_on_error(rc);

    uint64_t val = ((uint64_t)reg1.fields.cpu_jtag_tdo_data_value_high << 32) | reg0.fields.cpu_jtag_tdo_data_value_low;
    size_t msb = reg1.fields.cpu_jtag_tdo_data_bit_valid;
    out_bv = bit_vector(val, msb + 1);

    log_xdebug(CPU2JTAG, "%s: msb=%ld, val=0x%lx", __func__, msb, val);

    return LA_STATUS_SUCCESS;
}

la_status
cpu2jtag_drive_states::wait_for_done(const char* operation) const
{
    bool done_normal;

    la_status rc = wait_for_non_busy(operation, done_normal);
    return_on_error(rc);

    if (!done_normal) {
        log_err(CPU2JTAG, "%s: %s, not done", __func__, operation);
        return LA_STATUS_EUNKNOWN;
    }

    return LA_STATUS_SUCCESS;
}

la_status
cpu2jtag_drive_states::wait_for_non_busy(const char* operation, bool& done_normal) const
{
    if (m_ll_device->is_simulated_device()) {
        done_normal = true;
        return LA_STATUS_SUCCESS;
    }

    if (m_ll_device->is_asic5() || m_ll_device->is_asic4()) {
        // ASIC5::FIXME
        done_normal = true;
        return LA_STATUS_SUCCESS;
    }

    // same struct in GR
    gibraltar::sbif_cpu_jtag_status_reg_register jtag_status{{0}};

    size_t retry = 0;

    do {
        // cpu2jtag clk is slower than PCIe by an order of magnitude.
        // We can safely "yield" before reading jtag status.
        this_thread::yield();

        la_status rc = m_ll_device->read_register(*m_cpu_jtag_status_reg, jtag_status);
        return_on_error(rc);
    } while (jtag_status.fields.cpu_jtag_busy && ++retry < CPU2JTAG_POLL_COMPLETION_MAX);

    done_normal = jtag_status.fields.cpu_jtag_done_normal;

    if (!jtag_status.fields.cpu_jtag_busy) {
        log_debug(CPU2JTAG, "%s: %s, ok, retries=%ld", __func__, operation, retry);
        return LA_STATUS_SUCCESS;
    }

    log_err(CPU2JTAG,
            "%s: op=%s, still busy, done_normal=%ld, done_abort=%ld, debug_data_valid=%ld, debug_others=0x%lx, retries=%ld/%d",
            __func__,
            operation,
            jtag_status.fields.cpu_jtag_done_normal,
            jtag_status.fields.cpu_jtag_done_abort,
            jtag_status.fields.cpu_jtag_debug_data_valid,
            jtag_status.fields.cpu_jtag_debug_others,
            retry,
            CPU2JTAG_POLL_COMPLETION_MAX);

    return LA_STATUS_EUNKNOWN;
}

} // namespace silicon_one
