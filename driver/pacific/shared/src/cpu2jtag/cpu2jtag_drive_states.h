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

#ifndef __LEABA_CPU2JTAG_DRIVE_STATE_MACHINE_H__
#define __LEABA_CPU2JTAG_DRIVE_STATE_MACHINE_H__

/// @file
/// @brief Access JTAG by driving the device's JTAG state machine through CPU2JTAG registers.
///        IR and DR are pushed through device registers.
///        TDO is read from device register.
///        TAP state machine and TAP clock are managed internaly by the device.

#include "cpu2jtag_impl.h"
#include "lld/gibraltar_tree.h"
#include "lld/lld_fwd.h"

namespace silicon_one
{

class ll_device;

class cpu2jtag_drive_states : public cpu2jtag_impl
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    cpu2jtag_drive_states(ll_device_sptr ldev, uint8_t ir_width_bits);
    virtual ~cpu2jtag_drive_states() = default;

    // API overrides
    la_status enable(uint32_t core_frequency_khz, uint32_t tck_frequency_mhz) override;
    la_status disable() override;

protected:
    cpu2jtag_drive_states() = default; // For serialization purposes only

    lld_register_sptr m_cpu_jtag_cfg_reg;
    lld_register_sptr m_cpu_jtag_ctrl_reg;
    lld_register_sptr m_cpu_jtag_override_reg;
    lld_register_sptr m_cpu_jtag_ir_dr_len_reg;
    lld_register_sptr m_cpu_jtag_ir_dr_val_reg;
    lld_register_sptr m_cpu_jtag_data_out_reg0;
    lld_register_sptr m_cpu_jtag_data_out_reg1;
    lld_register_sptr m_cpu_jtag_status_reg;

    la_status configure(uint32_t core_frequency_khz, uint32_t tck_frequency_mhz);
    la_status reset();
    la_status set_jtag_pads_override(bool en);
    la_status set_wrck_gate_override(bool en);

    // Internal overrides
    la_status do_load_ir(const bit_vector& ir) override;
    la_status do_load_ir_dr(const bit_vector& ir, size_t dr_width_bits, const bit_vector& dr, bit_vector* out_tdo) override;

    la_status read_tdo(bit_vector& out_tdo) const;
    la_status wait_for_done(const char* operation) const;
    la_status wait_for_non_busy(const char* operation, bool& done_normal) const;
};

} // namespace silicon_one

#endif
