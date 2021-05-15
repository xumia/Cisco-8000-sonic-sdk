// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_MULTICAST_PROTECTION_GROUP_H__
#define __LA_MULTICAST_PROTECTION_GROUP_H__

#include "api/npu/la_l3_destination.h"
#include "api/npu/la_multicast_protection_monitor.h"
#include "api/types/la_common_types.h"

/// @file
/// @brief Leaba Multicast Protection Group API-s.
///
/// Defines API-s for managing multicast protection groups, for use with MPLS multicast path protection.

/// @addtogroup MULTICAST_PROTECT_GRP
/// @{

namespace silicon_one
{

class la_multicast_protection_group : public la_l3_destination
{
public:
    /// @brief Get the multicast protection group's monitor.
    ///
    /// @param[out] out_protection_monitor  Pointer to #silicon_one::la_multicast_protection_monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Protection group is corrupt/invalid, or out_monitor is NULL.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_monitor(const la_multicast_protection_monitor*& out_protection_monitor) const = 0;

    /// @brief Get the primary destination NH.
    ///
    /// @param[out] out_next_hop     NH to populate.
    /// @param[out] out_system_port  System port to populate
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_primary_destination(const la_next_hop*& out_next_hop, const la_system_port*& out_system_port) const = 0;

    /// @brief Get the backup destination NH.
    ///
    /// @param[out] out_next_hop           NH to populate.
    /// @param[out] out_system_port        System port to populate
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_backup_destination(const la_next_hop*& out_next_hop, const la_system_port*& out_system_port) const = 0;

    /// @brief Update the primary and backup destinations and the assoicated protection monitor for this multicast protection group.
    ///
    /// @param[in]  primary_destination Primary next hop for this Multicast Protection Group.
    /// @param[in]  primary_system_port System port to use for the primary destination.
    /// @param[in]  backup_destination  Backup next hop for this Multicast Protection Group.
    /// @param[in]  backup_system_port  System port to use for backup destination.
    /// @param[in]  protection_monitor  Protection monitor to use for this Multicast Protection Group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Group updated successfully.
    /// @retval     LA_STATUS_EINVAL    Parameters are invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_protection_group(const la_next_hop* primary_destination,
                                              const la_system_port* primary_system_port,
                                              const la_next_hop* backup_destination,
                                              const la_system_port* backup_system_port,
                                              const la_multicast_protection_monitor* protection_monitor)
        = 0;
};
}
/// @}
#endif
