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

#ifndef __LA_L2_PROTECTION_GROUP_H__
#define __LA_L2_PROTECTION_GROUP_H__

#include "api/npu/la_l2_destination.h"
#include "api/types/la_common_types.h"

/// @file
/// @brief Leaba Layer 2 protection group API-s.
///
/// Defines API-s for managing L2 protection groups.

/// @addtogroup L2DEST_PROTECT
/// @{

namespace silicon_one
{

class la_l2_protection_group : public la_l2_destination
{
public:
    /// @brief Get the L2 protection group's monitor.
    ///
    /// @param[out] out_protection_monitor  Pointer to #silicon_one::la_protection_monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Protection group is corrupt/invalid, or out_monitor is NULL.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_monitor(const la_protection_monitor*& out_protection_monitor) const = 0;

    /// @brief Set the L2 protection group's monitor.
    ///
    /// @param[in]  protection_monitor  Monitor to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EINVAL    Protection group or monitor are corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_monitor(const la_protection_monitor* protection_monitor) = 0;

    /// @brief Get L2 protection group's global ID.
    ///
    /// @return L2 protection group's global ID.
    virtual la_l2_port_gid_t get_gid() const = 0;

    /// @brief Get the L2 primary destination.
    ///
    /// @param[out] out_destination     L2 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_primary_destination(const la_l2_destination*& out_destination) const = 0;

    /// @brief Get the L2 backup destination.
    ///
    /// @param[out] out_destination     L2 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_backup_destination(const la_l2_destination*& out_destination) const = 0;
};
}
/// @}
#endif
