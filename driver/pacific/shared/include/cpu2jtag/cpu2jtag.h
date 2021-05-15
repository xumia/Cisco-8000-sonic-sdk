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

#ifndef __LEABA_CPU2JTAG_H__
#define __LEABA_CPU2JTAG_H__

#include "api/types/la_common_types.h"
#include "common/bit_vector.h"
#include "common/la_status.h"

#include "lld/lld_fwd.h"

/// @file
/// @brief Leaba CPU2JTAG API.
///
/// Defines API for accessing CPU2JTAG interface.

namespace silicon_one
{

class cpu2jtag
{
public:
#ifndef SWIG
    /// @name Initialization and life-cycle.
    /// @{

    /// @brief      Create cpu2jtag instance.
    ///
    /// @param[in]  ldev    Low-level device.
    ///
    /// @return     cpu2jtag object or nullptr.
    static cpu2jtag* create(ll_device_sptr ldev);
#endif

    /// @brief      D'tor
    virtual ~cpu2jtag() = default;

    /// @}
    /// @name JTAG operations.
    /// @{

    /// @brief      Enable CPU2TAG with a specified frequency.
    ///
    /// @param[in]  core_frequency_khz  Core frequency in KHz.
    /// @param[in]  tck_frequency_mhz   TCK frequency in MHz.
    ///
    /// @retval     Status code.
    virtual la_status enable(uint32_t core_frequency_khz, uint32_t tck_frequency_mhz) = 0;

    /// @brief      Disable CPU2TAG.
    ///
    /// @retval     Status code.
    virtual la_status disable() = 0;

    /// @brief JTAG Instruction Register values (opcodes).
    enum class jtag_ir_e {
        PVT = 0x3,          ///< Load data to PVT-sensors register.
        WRCK = 0x5,         ///< Load data to WRCK-override register.
        HBM_X6 = 0x6,       ///< HBM code 0x6.
        HBM_X12 = 0x12,     ///< HBM code 0x12.
        HBM_X2E = 0x2e,     ///< HBM code 0x2e.
        HBM_X2F = 0x2f,     ///< HBM code 0x2f.
        SEL_SMS_WIR = 0x28, ///< Load data to SMS_WIR register.
        SEL_SMS_WDR = 0x29, ///< Load data to SMS_WDR register.
        SEL_JPC_WDR = 0x2a, ///< Load data to JPC_WDR register.
        SEL_JPC_WIR = 0x35, ///< Load data to JPC_WIR register.

        FUSE_WRITE_TO_BUFFER = 0x200,    ///< Write to the 4Kbit buffer of the fuse.
        FUSE_CONFIGURE_TEST_REG = 0x2b4, ///< Configure the TAP's TEST_REG.
        FUSE_BURN = 0x2d1,               ///< Burn fuse.
        FUSE_READ_TO_BUFFER = 0x2d2,     ///< Read fuse into its 4Kbit buffer.
    };

    /// @brief ASIC-specific width of JTAG IR
    static constexpr uint8_t GIBRALTAR_JTAG_IR_WIDTH_BITS = 6;
    static constexpr uint8_t ASIC3_JTAG_IR_WIDTH_BITS = 6;
    static constexpr uint8_t PACIFIC_JTAG_IR_WIDTH_BITS = 10;

    /// @brief      Load JTAG instruction.
    ///
    /// @param[in]  in_bv   Instruction payload.
    ///
    /// @retval     Status code.
    virtual la_status load_ir(const bit_vector& in_bv) = 0;

    /// @brief      Load JTAG instruction and data, and read test data output (JTAG TDO).
    ///
    /// @param[in]  in_ir           IR input data, see #silicon_one::cpu2jtag::jtag_ir_e .
    /// @param[in]  dr_length_bits  Length of DR input data in bits.
    /// @param[in]  in_dr           DR input data.
    /// @param[out] out_bv          Test output data (JTAG TDO).
    ///
    /// @retval     Status code.
    virtual la_status load_ir_dr(const bit_vector& in_ir, size_t dr_length_bits, const bit_vector& in_dr, bit_vector& out_bv) = 0;

    /// @brief      Load JTAG instruction and data.
    ///
    /// @param[in]  in_ir           IR input data, see #silicon_one::cpu2jtag::jtag_ir_e .
    /// @param[in]  dr_length_bits  Length of DR input data in bits.
    /// @param[in]  in_dr           DR input data.
    ///
    /// @retval     Status code.
    virtual la_status load_ir_dr_no_tdo(const bit_vector& in_ir, size_t dr_length_bits, const bit_vector& in_dr) = 0;

    /// @}
};

} // namespace silicon_one

#endif
