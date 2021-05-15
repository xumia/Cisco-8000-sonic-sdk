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

#ifndef __LA_ECMP_GROUP_H__
#define __LA_ECMP_GROUP_H__

#include "api/npu/la_l3_destination.h"

/// @file
/// @brief Leaba Equal-Cost Multi-Path group API-s.
///
/// Defines API-s for managing ECMP groups.

/// @addtogroup L3DEST_ECMP
/// @{

namespace silicon_one
{

/// @name General
/// @{

/// @brief Equal-cost multipath group.
///
/// An ECMP group enables load-balancing traffic to a given destination.
/// Different packets can be transmitted through different group members, depending on the group's hash settings.
class la_ecmp_group : public la_l3_destination
{
public:
    /// @brief ECMP Level.
    enum class level_e {
        LEVEL_1 = 1, ///< ECMP Level 1.
        LEVEL_2 = 2, ///< ECMP Level 2.
    };

    /// @brief Add a member to an ECMP group.
    ///
    /// @param[in]  l3_destination      L3 destination to add.
    ///
    /// @retval     LA_STATUS_SUCCESS   Layer 3 destination added successfully.
    /// @retval     LA_STATUS_EINVAL    Layer 3 destination is corrupt/invalid.
    /// @retval     LA_STATUS_EBUSY     Layer 3 destination is already a member of the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add_member(la_l3_destination* l3_destination) = 0;

    /// @brief Remove a member from an ECMP group.
    ///
    /// @param[in]  l3_destination      L3 destination to remove.
    ///
    /// @retval     LA_STATUS_SUCCESS   Layer 3 destination removed successfully.
    /// @retval     LA_STATUS_EINVAL    Layer 3 destination is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND Layer 3 destination is not a member of the ECMP group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove_member(const la_l3_destination* l3_destination) = 0;

    /// @brief Get member of the ECMP group by its index.
    ///
    /// @param[in]  member_idx              Member's index.
    /// @param[out] out_member              L3 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Member index is out-of-range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_member(size_t member_idx, const la_l3_destination*& out_member) const = 0;

    /// @brief Get members of the ECMP group.
    ///
    /// @param[out] out_members         L3 destination members of the ECMP group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_members contains L3 destinations.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_members(la_l3_destination_vec_t& out_members) const = 0;

    /// @brief Set members of the ECMP group.
    ///
    /// @param[in]  members             New set of L3 destinations for the ECMP group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. ECMP group updated with the L3 destinations.
    /// @retval     LA_STATUS_EINVAL    Set of L3 destinations is empty or one of the members is corrupt/invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_members(const la_l3_destination_vec_t& members) = 0;

    /// @}
    /// @name Load Balancing
    /// @{

    /// @brief Set load balancing mode.
    ///
    /// @param[in]  lb_mode             Load balancing mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Load balancing mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_lb_mode(la_lb_mode_e lb_mode) = 0;

    /// @brief Set packet fields used for load-balancing hash calculation.
    ///
    /// @param[in]  lb_fields           Load balancing fields to use for hash.
    ///
    /// @retval     LA_STATUS_SUCCESS   Load balancing fields set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_lb_fields(la_lb_fields_t lb_fields) = 0;

    /// @brief Set the load balancing hash function.
    ///
    /// @param[in]  lb_hash             Load balancing hash function.
    ///
    /// @retval     LA_STATUS_SUCCESS   Load balancing hash function set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_lb_hash(la_lb_hash_e lb_hash) = 0;

    /// @brief Enable/Disable segment load balancing.
    ///
    /// @param[in]  enabled             true if SLB enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   SLB mode enabled successfully.
    /// @retval     LA_STATUS_ERESOURCE No free SLB contexts are available.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_slb_mode(bool enabled) = 0;

    /// @}
};
}
/// @}

#endif
