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

#ifndef __LA_MPLS_MULTICAST_GROUP_H__
#define __LA_MPLS_MULTICAST_GROUP_H__

#include "api/npu/la_l3_destination.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba MPLS Multicast Group API-s.
///
/// Defines API-s for managing MPLS multicast group.

/// @addtogroup MULTICAST_MPLS
/// @{

namespace silicon_one
{

/// @brief      An MPLS multicast group.
///
/// @details    Group of #silicon_one::la_prefix_object objects representing an MPLS multicast group.\n
class la_mpls_multicast_group : public la_l3_destination
{
public:
    struct la_mpls_multicast_group_member_info {
        const la_prefix_object* prefix_object;
        const la_l3_port* l3_port;
    };

    /// @brief   Get the group's global ID.
    ///
    /// @retval  Group's global ID.
    virtual la_multicast_group_gid_t get_gid() const = 0;

    /// @brief Add a prefix object to the MPLS Multicast group.
    ///
    /// @param[in]  prefix_object                A prefix object to add.
    /// @param[in]  dsp                 Destination system port, null in protection.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Prefix object or DSP are invalid.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE No room for more prefix object.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_prefix_object* prefix_object, const la_system_port* dsp) = 0;

    /// @brief Add a recycle port to the MPLS Multicast group.
    ///
    /// @param[in]  recycle_port        recycle port to add.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    recyle port is invalid.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_l3_port* recycle_port) = 0;

    /// @brief Remove a prefix object from MPLS Multicast group.
    ///
    /// @param[in]  prefix_object               A prefix object to remove.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Prefix object is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Prefix object not found in given multicast group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_prefix_object* prefix_object) = 0;

    /// @brief Remove a recycle port from the MPLS Multicast group.
    ///
    /// @param[in]  recycle_port        recycle port to remove
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    recycle port is invalid.
    /// @retval     LA_STATUS_ENOTFOUND recycle port not found in given multicast group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_l3_port* recycle_port) = 0;

    /// @brief Set the destination system port of a group member. Invalid in cases of protection.
    ///
    /// @param[in]  prefix_object               Member's prefix object.
    /// @param[in]  dsp                         Destination system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    The given prefix object is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination_system_port(const la_prefix_object* prefix_object, const la_system_port* dsp) = 0;

    /// @brief Get the destination system port of a group member. Invalid in cases of protection
    ///
    /// @param[in]  prefix_object               Member's prefix object.
    /// @param[out] out_dsp                     Destination system port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    The given prefix object is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_destination_system_port(const la_prefix_object* prefix_object, const la_system_port*& out_dsp) const = 0;

    /// @brief Get destination by index.
    ///
    /// @param[in]  member_idx               Member's idx.
    /// @param[out] out_member               Member info to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Member index is out-of-range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_member(size_t member_idx, la_mpls_multicast_group_member_info& out_member) const = 0;

    /// @brief Get the group's size.
    ///
    /// The size of the group doesn't include the punt member if there is one.
    ///
    /// @param[out] out_size                Size of the group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_size(size_t& out_size) const = 0;

    /// @brief Get the replication paradigm.
    ///
    /// @param[out] out_replication_paradigm    Replication paradigm to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const = 0;

    /// @brief Add/remove punt-destination member to IP Multicast group.
    ///
    /// Punt destination is set by configuring #LA_EVENT_L3_IP_MC_G_PUNT_MEMBER and #LA_EVENT_L3_IP_MC_S_G_PUNT_MEMBER,
    /// using #silicon_one::la_device::set_trap_configuration.
    ///
    /// @param[in]  enabled             True if punting should be enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTINITIALIZED   No system port over recycle port.
    /// @retval     LA_STATUS_ERESOURCE         No resources to add IP multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_punt_enabled(bool enabled) = 0;

    /// @brief Check whether the punt-destination is enabled.
    ///
    /// @param[out] out_enabled         True if punting is enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_punt_enabled(bool& out_enabled) const = 0;

protected:
    virtual ~la_mpls_multicast_group() = default;
};
}

/// @}
#endif // __LA_MPLS_MULTICAST_GROUP_H__
