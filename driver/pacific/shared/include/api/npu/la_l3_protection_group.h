// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_L3_PROTECTION_GROUP_H__
#define __LA_L3_PROTECTION_GROUP_H__

#include "api/npu/la_l3_destination.h"
#include "api/types/la_common_types.h"

/// @file
/// @brief Leaba Layer 3 protection group API-s.
///
/// Defines API-s for managing L3 protection groups.

/// @addtogroup L3DEST_PROTECT
/// @{

namespace silicon_one
{

class la_l3_protection_group : public la_l3_destination
{
public:
    /// @brief Get the L3 protection group's monitor.
    ///
    /// @param[out] out_protection_monitor  Pointer to #silicon_one::la_protection_monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Protection group is corrupt/invalid, or out_monitor is NULL.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_monitor(const la_protection_monitor*& out_protection_monitor) const = 0;

    /// @brief Set the L3 protection group's monitor.
    ///
    /// @param[in]  protection_monitor  Monitor to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EINVAL    Protection group or monitor are corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_monitor(const la_protection_monitor* protection_monitor) = 0;

    /// @brief Get L3 protection group's global ID.
    ///
    /// @return L3 protection group's global ID.
    virtual la_l3_protection_group_gid_t get_gid() const = 0;

    /// @brief Get the L3 primary destination.
    ///
    /// @param[out] out_l3_destination     L3 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_primary_destination(const la_l3_destination*& out_l3_destination) const = 0;

    /// @brief Get the L3 backup destination.
    ///
    /// @param[out] out_l3_destination     L3 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_backup_destination(const la_l3_destination*& out_l3_destination) const = 0;

    /// @brief Update the primary and backup destinations and the assoicated protection monitor for this L3 Protection group.
    ///
    /// @param[in]  primary_destination Primary L3 destination for this L3 Protection group.
    /// @param[in]  backup_destination  Backup L3 destination for this L3 Protection group.
    /// @param[in]  protection_monitor  Backup L3 destination for this L3 Protection group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_protection_group(const la_l3_destination* primary_destination,
                                              const la_l3_destination* backup_destination,
                                              const la_protection_monitor* protection_monitor)
        = 0;
};
}
/// @}
#endif
