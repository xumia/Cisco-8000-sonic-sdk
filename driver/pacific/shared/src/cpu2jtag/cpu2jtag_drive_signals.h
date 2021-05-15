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

#ifndef __LEABA_CPU2JTAG_DRIVE_SIGNALS_H__
#define __LEABA_CPU2JTAG_DRIVE_SIGNALS_H__

/// @file
/// @brief Access JTAG by driving TAP signals - TCK, TDI, TDO, TMS, TRST_N.
///        In this mode, CPU drives all TAP signals, including the clock (TCK).

#include "cpu2jtag_impl.h"
#include "lld/pacific_tree.h"
#include "tap1149.h"

namespace silicon_one
{

class ll_device;

class cpu2jtag_drive_signals : public cpu2jtag_impl
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    cpu2jtag_drive_signals(ll_device_sptr ldev, uint8_t ir_width_bits);
    virtual ~cpu2jtag_drive_signals() = default;

    // API overrides
    la_status enable(uint32_t core_frequency_khz, uint32_t tck_frequency_mhz) override;
    la_status disable() override;

protected:
    cpu2jtag_drive_signals() = default; // For serialization purposes only

    std::shared_ptr<const pacific_tree_sbif> m_sbif;

    la_status reset();

    // Internal overrides
    la_status do_load_ir(const bit_vector& ir) override;
    la_status do_load_ir_dr(const bit_vector& ir, size_t dr_length_bits, const bit_vector& dr, bit_vector* out_tdo) override;

    la_status read_tdo(bit_vector& out_bv) const;
    la_status wait_for_done(const char* operation) const;
    la_status wait_for_non_busy(const char* operation, bool& done_normal) const;

    la_status deassert_reset();
    la_status assert_reset();

    la_status drive_tms_tdi_seq(const tap1149::tms_tdi_seq& seq, bit_vector& out_tdo);

    struct tap_signals_in {
        bool tms;
        bool tdi;
        bool trst;
        bool tck;
    };
    la_status exec_jtag_cycle(tap_signals_in in, bool* out_tdo);
};

} // namespace silicon_one

#endif
