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

#ifndef __LA_SWITCH_MULTICAST_GROUP_H__
#define __LA_SWITCH_MULTICAST_GROUP_H__

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_next_hop.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_tm_types.h"

#include "api/npu/la_l2_destination.h"

/// @file
/// @brief Leaba Switch Multicast Group API-s.
///
/// Defines API-s for managing a Switch Multicast group.

/// @addtogroup MULTICAST_L2
/// @{

namespace silicon_one
{
/// @brief      A layer 2 multicast group.
///
/// @details    Group of #silicon_one::la_l2_destination-s representing a multicast group.\n
///             A #silicon_one::la_switch can direct traffic to a multicast group.\n
///             A multicast group should not contain other multicast groups as members.

class la_l2_multicast_group : public la_l2_destination
{
public:
    /// @brief   Get the group's global ID.
    ///
    /// @retval  Group's global ID.
    virtual la_multicast_group_gid_t get_gid() const = 0;

    /// @brief Add Layer 2 destination.
    ///
    /// @param[in]  destination              Layer 2 destination to add.\n
    ///                                      Can be any layer 2 destination type except a multicast group.
    /// @param[in]  dsp                      Destination system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination or destination-system-port are invalid.
    /// @retval     LA_STATUS_EINVAL    Destination is a multicast group.
    /// @retval     LA_STATUS_ERESOURCE No room for more switch multicast entries.
    /// @retval     LA_STATUS_EEXIST    Destination is already part of the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_l2_destination* destination, const la_system_port* dsp) = 0;

    /// @brief Add stack port member to Layer 2 Multicast group.
    ///
    /// Add stack port to the layer 2 multicast group to expand the remote multicast members.
    ///
    /// @param[in]  stackport                Stack port to add.
    /// @param[in]  dsp                      Destination system port of stack port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    The given destination-system-port is invalid.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE No resources to add multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_stack_port* stackport, const la_system_port* dsp) = 0;

    /// @brief Add VXLAN port as member.
    ///
    /// @param[in]  vxlan_port               VXLAN tunnel port that packet will go through.
    /// @param[in]  next_hop                 Next hop that VXLAN tunnel port to reach to the endpoint.
    /// @param[in]  dsp                      Destination system port of the next hop.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL         Destination or destination-system-port are invalid.
    /// @retval     LA_STATUS_EINVAL         Destination is a multicast group.
    /// @retval     LA_STATUS_ERESOURCE      No room for more switch multicast entries.
    /// @retval     LA_STATUS_EEXIST         Destination is already part of the group.
    /// @retval     LA_STATUS_EUNKNOWN       An unknown error occurred.
    virtual la_status add(const la_l2_destination* vxlan_port, la_next_hop* next_hop, const la_system_port* dsp) = 0;

    /// @brief Remove Layer 2 destination.
    ///
    /// @param[in]  destination         Layer 2 destination to remove from multicast group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_l2_destination* destination) = 0;

    /// @brief Remove stack member from layer 2 Multicast group.
    ///
    /// @param[in]  stackport           Stack port to remove.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Given stack port is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_stack_port* stackport) = 0;

    /// @brief Set the destination system port of a group member.
    ///
    /// @param[in]  destination              Member's L2 destination.
    /// @param[in]  dsp                      Destination system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination or destination-system-port are invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination_system_port(const la_l2_destination* destination, const la_system_port* dsp) = 0;

    /// @brief Get the destination system port of a group member.
    ///
    /// @param[in]  l2_destination               Member's L2 destination.
    /// @param[out] out_dsp                      Destination system port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_destination_system_port(const la_l2_destination* l2_destination,
                                                  const la_system_port*& out_dsp) const = 0;

    /// @brief Get Layer 2 destination by its index.
    ///
    /// @param[in]  member_idx              Member's idx.
    /// @param[out] out_destination         L2 destination to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Member index is out-of-range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_member(size_t member_idx, const la_l2_destination*& out_destination) const = 0;

    /// @brief Get Layer 2 destinations.
    ///
    /// @param[out] out_l2_mcg_members      L2 destinations to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_members(la_l2_destination_vec_t& out_l2_mcg_members) const = 0;

    /// @brief Get the groups size.
    ///
    /// @param[out] out_size                Size of the la_l2_multicast_group to populate.
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

protected:
    ~la_l2_multicast_group() override = default;
};
}
/// @}

#endif
