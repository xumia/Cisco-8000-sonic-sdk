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

#ifndef __LEABA_CPU2JTAG_IMPL_H__
#define __LEABA_CPU2JTAG_IMPL_H__

#include "common/cereal_utils.h"
#include "common/la_lock_guard.h"
#include "cpu2jtag/cpu2jtag.h"

namespace silicon_one
{

class cpu2jtag_impl : public cpu2jtag
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    cpu2jtag_impl(ll_device_sptr ldev, uint8_t ir_width_bits);
    virtual ~cpu2jtag_impl() = default;

    // Overrides
    la_status load_ir(const bit_vector& ir) override;
    la_status load_ir_dr(const bit_vector& ir, size_t dr_length_bits, const bit_vector& dr, bit_vector& out_tdo) override;
    la_status load_ir_dr_no_tdo(const bit_vector& ir, size_t dr_length_bits, const bit_vector& dr) override;

protected:
    cpu2jtag_impl(); // For serialization purposes only

    ll_device_sptr m_ll_device;
    mutable std::recursive_mutex m_mutex;
    const uint8_t m_ir_width_bits;

    virtual la_status do_load_ir(const bit_vector& ir) = 0;
    virtual la_status do_load_ir_dr(const bit_vector& ir, size_t dr_length_bits, const bit_vector& dr, bit_vector* out_tdo) = 0;
};

} // namespace silicon_one

#define start_cpu2jtag_call(...)                                                                                                   \
    silicon_one::la_lock_guard<std::recursive_mutex> lock(m_mutex, m_ll_device->get_device_id());                                  \
    log_debug(CPU2JTAG, __VA_ARGS__)

#endif
