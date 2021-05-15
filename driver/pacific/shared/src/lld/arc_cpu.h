// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LLD_ARC_CPU_H__
#define __LEABA_LLD_ARC_CPU_H__

#include <stdint.h>
#include <stdlib.h>
#include <string>

#include "lld/ll_device.h"
#include "lld_types_internal.h"

#include <memory>
#include <vector>

namespace silicon_one
{

class arc_cpu;
class ll_device_impl;

class arc_cpu
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    arc_cpu(ll_device_impl_wptr lld, const arc_cpu_info& arc_info, uint8_t arc_id);

    // Disallow copy c'tor. Default construct is private, in order to support serialization
    arc_cpu(const arc_cpu&) = delete;

    // _lbr_tree is either 'class pacific_tree' or 'class gibraltar_tree'
    void initialize(const arc_cpu_info& arc_info);

    /// @brief Get access engine id
    ///
    /// @retval Ending ID
    uint8_t get_arc_id() const;

    /// @brief Start ARC CPU
    ///
    /// @retval     LA_STATUS_SUCCESS   Completed successfully.
    la_status go();

    /// @brief Stop ARC CPU
    ///
    /// @retval     LA_STATUS_SUCCESS   Completed successfully.
    la_status halt();

    /// @brief Reset ARC CPU
    ///
    /// @retval     LA_STATUS_SUCCESS   Completed successfully.
    la_status reset();

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    arc_cpu() = default;

    ll_device_impl_wptr m_ll_device;
    uint8_t m_arc_id;
    la_entry_addr_t m_arc_run_halt_reg;
    la_entry_addr_t m_arc_status_reg;
    la_entry_addr_t m_reset_reg;

}; // class arc_cpu

using arc_cpu_uptr = std::unique_ptr<arc_cpu>;

} // namespace silicon_one

#endif // __LEABA_LLD_ARC_CPU_H__
