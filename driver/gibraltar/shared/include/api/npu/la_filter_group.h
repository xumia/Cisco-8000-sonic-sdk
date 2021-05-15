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

#ifndef __LA_FILTER_GROUP_H__
#define __LA_FILTER_GROUP_H__

#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba Filter Group API-s.
///
/// Defines API-s for managing Filter groups.

namespace silicon_one
{

/// @addtogroup L2SWITCH_FILTER
/// @{

/// @brief      An Ethernet Filter group.
///
/// @details    Filter groups are used to permit/deny traffic between given ports.
///             For each pair of (source, destination) filter groups, an application can define whether the source group can
///             send traffic to the destination group.
class la_filter_group : public la_object
{
public:
    enum class filtering_mode_e {
        PERMIT = 0, ///< Permit packets to pass from source to destination.
        DENY,       ///< Drop packets from source to destination.
    };

    /// @brief Get filtering mode to the given destination group.
    ///
    /// @param[in]  dest_group          Destination group.
    /// @param[in]  out_filtering_mode  #silicon_one::la_filter_group::filtering_mode_e to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mode contains the filtering mode.
    /// @retval     LA_STATUS_EINVAL    Destination group is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_filtering_mode(const la_filter_group* dest_group, filtering_mode_e& out_filtering_mode) = 0;

    /// @brief Set filtering mode to the given destination group.
    ///
    /// @param[in]  dest_group          Destination group.
    /// @param[in]  filtering_mode      Filtering mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Filtering mode has been set.
    /// @retval     LA_STATUS_EINVAL    Destination group is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_filtering_mode(const la_filter_group* dest_group, filtering_mode_e filtering_mode) = 0;
};

/// @}
}

#endif
