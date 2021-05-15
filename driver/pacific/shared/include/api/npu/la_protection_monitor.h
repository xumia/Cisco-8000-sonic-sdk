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

#ifndef __LA_PROTECTION_MONITOR_H__
#define __LA_PROTECTION_MONITOR_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba Protection Monitor API-s.
///
/// Defines API-s for managing Protection Monitors.
///
/// Protection monitors are used to select primary/protection paths on L2/L3/MPLS protection groups.
/// A triggered monitor state means the protection path is currently used.
///
/// One monitor can be used for multiple protection groups.

/// @addtogroup PROTECT_MONITOR
/// @{

namespace silicon_one
{

class la_protection_monitor : public la_object
{
public:
    /// @brief Protection monitor states.
    enum class monitor_state_e {
        UNTRIGGERED = 0, ///< Monitor is untriggered. Primary destination is usable.
        TRIGGERED,       ///< Monitor is triggered. Primary destination is unusable, and traffic should flow to the
                         ///< secondary destination.
    };

    /// @brief Set protection monitor state.
    ///
    /// @param[in]  state               Monitor state to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Monitor state set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_state(monitor_state_e state) = 0;

    /// @brief Get protection monitor state.
    ///
    /// @param[out] out_state           #monitor_state_e object to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Monitor state retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_state(monitor_state_e& out_state) const = 0;

protected:
    ~la_protection_monitor() override = default;
};
}
/// @}
#endif
