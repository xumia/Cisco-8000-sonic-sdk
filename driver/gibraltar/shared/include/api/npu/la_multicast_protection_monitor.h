// BEGIN_LEGAL
//
// Copyright (c) 2015-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_MULTICAST_PROTECTION_MONITOR_H__
#define __LA_MULTICAST_PROTECTION_MONITOR_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba Protection Monitor API-s.
///
/// Defines API-s for managing Multicast Protection Monitors.
///
/// Multicast protection monitors are used to select primary/protection paths on egress multicast protection groups.
/// Currently only used for MPLS multicast path protection. State can be any of the following:
/// 1. Both paths disabled.
/// 2. Primary active, backup disabled.
/// 3. Backup active, primary disabled.
/// 4. Both paths active.
///
/// One monitor can be used for multiple destination protection groups.

/// @addtogroup MULTICAST_PROTECT_MONITOR
/// @{

namespace silicon_one
{

class la_multicast_protection_monitor : public la_object
{
public:
    /// @brief Set protection monitor state.
    ///
    /// @param[in]  primary_active       True if primary path active, false otherwise.
    /// @param[in]  backup_active        True if backup path active, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Monitor state set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_state(bool primary_active, bool backup_active) = 0;

    /// @brief Get protection monitor state.
    ///
    /// @param[out] out_primary_active     Primary active state to be populated.
    /// @param[out] out_backup_active      Backup active state to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Monitor state retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_state(bool& out_primary_active, bool& out_backup_active) const = 0;

protected:
    ~la_multicast_protection_monitor() override = default;
};
}
/// @}
#endif
