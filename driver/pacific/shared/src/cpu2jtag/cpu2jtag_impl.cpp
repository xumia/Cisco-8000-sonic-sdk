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

#include "cpu2jtag_impl.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "cpu2jtag_drive_signals.h"
#include "cpu2jtag_drive_states.h"
#include "lld/ll_device.h"

/// @file
/// @brief Base class for cpu2jtag implementations.

namespace silicon_one
{

cpu2jtag*
cpu2jtag::create(ll_device_sptr ldev)
{
    if (!ldev) {
        return nullptr;
    }

    cpu2jtag* obj;
    if (ldev->is_gibraltar()) {
        obj = new cpu2jtag_drive_states(ldev, GIBRALTAR_JTAG_IR_WIDTH_BITS);
    } else if (ldev->is_pacific() || ldev->is_asic5()) { // ASIC5 is not supported currently
        obj = new cpu2jtag_drive_signals(ldev, PACIFIC_JTAG_IR_WIDTH_BITS);
    } else { // for GR and PL
        obj = new cpu2jtag_drive_states(ldev, ASIC3_JTAG_IR_WIDTH_BITS);
    }

    return obj;
}

cpu2jtag_impl::cpu2jtag_impl(ll_device_sptr ll_device, uint8_t ir_width_bits)
    : m_ll_device(ll_device), m_ir_width_bits(ir_width_bits)
{
}

cpu2jtag_impl::cpu2jtag_impl() : m_ir_width_bits(0)
{
}

la_status
cpu2jtag_impl::load_ir(const bit_vector& ir_in)
{
    // zero-pad MSBs
    bit_vector ir = ir_in;
    ir.resize(m_ir_width_bits);

    start_cpu2jtag_call("%s: ir=%s", __func__, ir.to_string().c_str());

    return do_load_ir(ir);
}

la_status
cpu2jtag_impl::load_ir_dr(const bit_vector& ir_in, size_t dr_width_bits, const bit_vector& dr_in, bit_vector& out_tdo)
{
    // zero-pad MSBs
    bit_vector ir = ir_in;
    ir.resize(m_ir_width_bits);
    bit_vector dr = dr_in;
    dr.resize(dr_width_bits);

    start_cpu2jtag_call("%s: ir=%s, dr_bits=%ld, dr=%s", __func__, ir.to_string().c_str(), dr_width_bits, dr.to_string().c_str());

    return do_load_ir_dr(ir, dr_width_bits, dr, &out_tdo);
}

la_status
cpu2jtag_impl::load_ir_dr_no_tdo(const bit_vector& ir_in, size_t dr_width_bits, const bit_vector& dr_in)
{
    // zero-pad MSBs
    bit_vector ir = ir_in;
    ir.resize(m_ir_width_bits);
    bit_vector dr = dr_in;
    dr.resize(dr_width_bits);

    start_cpu2jtag_call("%s: ir=%s, dr_bits=%ld, dr=%s", __func__, ir.to_string().c_str(), dr_width_bits, dr.to_string().c_str());

    return do_load_ir_dr(ir, dr_width_bits, dr, nullptr);
}

} // namespace silicon_one
