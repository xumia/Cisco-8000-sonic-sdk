// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_FABRIC_MULTICAST_GROUP_H__
#define __LA_FABRIC_MULTICAST_GROUP_H__

#include "api/types/la_object.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Fabric Multicast Group API-s.
///
/// Defines API-s for managing a Fabric Multicast group.

/// @addtogroup MULTICAST_FABRIC
/// @{

namespace silicon_one
{
/// @brief      A fabric multicast group.
///
/// @details    Group of #silicon_one::la_device-s representing a fabric multicast group.

class la_fabric_multicast_group : public la_object
{
public:
    /// @brief   Get the group's global ID.
    ///
    /// @retval  Group's global ID.
    virtual la_multicast_group_gid_t get_gid() const = 0;

    /// @brief Get all destination devices for this MC group.
    ///
    /// @param[out] out_device_id_vec     List of devices that were set to this fabric multicast group.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_devices(la_device_id_vec_t& out_device_id_vec) const = 0;

    /// @brief Set destination devices for this MC group.
    ///
    /// @param[in]  device_id_vec      List of devices to set to this fabric multicast group.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_devices(const la_device_id_vec_t& device_id_vec) = 0;

    /// @brief Get the replication paradigm.
    ///
    /// @param[out] out_replication_paradigm    Replication paradigm to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const = 0;

protected:
    virtual ~la_fabric_multicast_group() = default;
};
}
/// @}

#endif
