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

#ifndef __LA_IP_MULTICAST_GROUP_H__
#define __LA_IP_MULTICAST_GROUP_H__

#include "api/npu/la_l3_destination.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba IP Multicast Group API-s.
///
/// Defines API-s for managing IP multicast group.

/// @addtogroup MULTICAST_IP
/// @{

namespace silicon_one
{

class la_l2_multicast_group;
class la_mpls_multicast_group;

/// @brief      A layer 3 multicast group.
///
/// @details    Group of #silicon_one::la_l3_destination-s representing a multicast group.\n
///             A #silicon_one::la_vrf can route traffic to IP multicast group.\n
///             An IP multicast group may contain other multicast groups as members in case of\n
///             ingress replication paradigm.

class la_ip_multicast_group : public la_l3_destination
{
public:
    struct member_info {
        const la_l3_port* l3_port;
        const la_l2_port* l2_port;
        const la_l2_multicast_group* l2_mcg;
        const la_ip_multicast_group* ip_mcg;
        const la_mpls_multicast_group* mpls_mcg;
    };

    /// @brief   Get the group's global ID.
    ///
    /// @retval  Group's global ID.
    virtual la_multicast_group_gid_t get_gid() const = 0;

    /// @brief Add L3 port member to IP Multicast group.
    ///
    /// Add L3 port to the IP multicast group. If L3 port is an #silicon_one::la_svi_port, L2 port must be supplied as well.
    ///
    /// @param[in]  l3_port                  L3 port to add.
    /// @param[in]  l2_port                  L2 port to add to use if L3 port is of type #silicon_one::la_svi_port, NULL otherwise.
    /// @param[in]  dsp                      Destination system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the given ports is invalid.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE No resources to add IP multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_l3_port* l3_port, const la_l2_port* l2_port, const la_system_port* dsp) = 0;

    /// @brief Add stack port member to IP Multicast group.
    ///
    /// Add stack port to the IP multicast group to expand the remote multicast members.
    ///
    /// @param[in]  stackport                Stack port to add.
    /// @param[in]  dsp                      Destination system port of stack port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    The given destination-system-port is invalid.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE No resources to add IP multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_stack_port* stackport, const la_system_port* dsp) = 0;

    /// @brief Add VXLAN port member to IP Multicast group.
    ///
    /// @param[in]  l3_port                  SVI port created for L3VXLAN.
    /// @param[in]  vxlan_port               VXLAN tunnel port that packet will go through.
    /// @param[in]  next_hop                 Next hop that VXLAN tunnel port to reach to the endpoint
    /// @param[in]  dsp                      Destination system port of the nexthop.
    ///
    /// @retval     LA_STATUS_SUCCESS        Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL         One of the given ports is invalid.
    /// @retval     LA_STATUS_EEXIST         Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE      No resources to add IP multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN       An unknown error occurred.
    virtual la_status add(const la_l3_port* l3_port, const la_l2_port* vxlan_port, la_next_hop* next_hop, const la_system_port* dsp)
        = 0;

    /// @brief Remove member from IP Multicast group.
    ///
    /// @param[in]  l3_port             L3 port to remove.
    /// @param[in]  l2_port             L2 port to remove, if L3 port is of type #silicon_one::la_svi_port, NULL otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the given ports is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_l3_port* l3_port, const la_l2_port* l2_port) = 0;

    /// @brief Remove stack member from IP Multicast group.
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
    /// @param[in]  l3_port                  Member's L3 port.
    /// @param[in]  l2_port                  Member's L2 port if L3 port is of type #silicon_one::la_svi_port, NULL otherwise.
    /// @param[in]  dsp                      Destination system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the given ports is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination_system_port(const la_l3_port* l3_port, const la_l2_port* l2_port, const la_system_port* dsp)
        = 0;

    /// @brief Get the destination system port of a group member.
    ///
    /// @param[in]  l3_port                      Member's L3 port.
    /// @param[in]  l2_port                      Member's L2 port if L3 port is of type #silicon_one::la_svi_port, NULL otherwise.
    /// @param[out] out_dsp                      Destination system port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the given ports is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_destination_system_port(const la_l3_port* l3_port,
                                                  const la_l2_port* l2_port,
                                                  const la_system_port*& out_dsp) const = 0;

    /// @brief Get destination by index.
    ///
    /// @param[in]  member_idx              Member's idx.
    /// @param[out] out_member              IP-MCG Member info to populate
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Member index is out-of-range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_member(size_t member_idx, member_info& out_member) const = 0;

    /// @brief Get the group's size.
    ///
    /// The size of the group doesn't include the punt and counter members if there are any.
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

    /// @brief Set the replication paradigm.
    ///
    /// @param      replication_paradigm        Change to Replication paradigm.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            Operation is invalid.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_replication_paradigm(la_replication_paradigm_e replication_paradigm) = 0;

    /// @brief Enable/disable punting when forwarding to a multicast member.
    ///
    /// If L3 port is an #silicon_one::la_svi_port, L2 port must be supplied as well.
    /// If punting is enabled, the packet will be punted on event #LA_EVENT_L3_IP_MC_EGRESS_PUNT
    ///
    /// @param[in]  l3_port             L3 port to punt on.
    /// @param[in]  l2_port             L2 port to punt on if L3 port is of type #silicon_one::la_svi_port, NULL otherwise.
    /// @param[in]  punt_enabled        True if punting should be enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            The given event or one of the given ports is invalid.
    /// @retval     LA_STATUS_ENOTFOUND         Member not found in the group.
    /// @retval     LA_STATUS_ERESOURCE         No resources to enable punt.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_punt_enabled(const la_l3_port* l3_port, const la_l2_port* l2_port, bool punt_enabled) = 0;

    /// @brief Check whether punting is enabled when forwarding to a multicast member.
    ///
    /// @param[in]  l3_port                  L3 port to punt on.
    /// @param[in]  l2_port                  L2 port to punt on.
    /// @param[out] out_punt_enabled         True if punting is enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the given ports is invalid.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_punt_enabled(const la_l3_port* l3_port, const la_l2_port* l2_port, bool& out_punt_enabled) const = 0;

    /// @brief Attach a counter to the multicast group.
    ///
    /// @param[in]  device_id       Device ID that should count the traffic of this MCG.
    /// @param[in]  counter_set     Counter set to attach to the MCG.
    ///
    /// @note If counter_set == nullptr, then the MCG egress counter will be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS   The counter_set object was created by a different device.
    /// @retval     LA_STATUS_EINVAL            Given counter_set parameter is invalid.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_egress_counter(la_device_id_t device_id, la_counter_set* counter_set) = 0;

    /// @brief Returns the MCG egress counter_set.
    ///
    /// @param[out]  out_device_id          Device ID that should count the traffic of this MCG.
    /// @param[out]  out_counter            MCG egress Counter set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_egress_counter(la_device_id_t& out_device_id, la_counter_set*& out_counter) const = 0;

    /// @brief Add L2 Multicast group to IP Multicast group.
    ///
    /// This API is used to add L2-MCG with egress replication paradigm as a
    /// member to IP-MCG with ingress replication paradigm
    ///
    /// @param[in]  svi_port            L3-SVI port to add
    /// @param[in]  l2_mcg              L2 MC Group to add
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE No resources to add IP multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_svi_port* svi_port, la_l2_multicast_group* l2_mcg) = 0;

    /// @brief Remove L2 Multicast group member from IP Multicast group.
    ///
    /// @param[in]  svi_port    L3-SVI port to remove
    /// @param[in]  l2_mcg      L2 MC Group to remove
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_svi_port* svi_port, la_l2_multicast_group* l2_mcg) = 0;

    /// @brief Add IP Multicast group as member to IP Multicast group
    ///
    /// This API is used to add IP-MCG with egress replication paradigm as a member
    /// to another IP-MCG with ingress replication paradigm
    ///
    /// @param[in]  ip_mcg              IP MC Group to add
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE No resources to add IP multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_ip_multicast_group* ip_mcg) = 0;

    /// @brief Remove IP Multicast group member from IP Multicast group.
    ///
    /// @param[in]  ip_mcg              IP MC Group to remove
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_ip_multicast_group* ip_mcg) = 0;

    /// @brief Add MPLS Multicast group as member to IP Multicast group
    ///
    /// This API is used to add MPLS-MCG with egress replication paradigm as a member
    /// to IP-MCG with ingress replication paradigm
    ///
    /// @param[in]  mpls_mcg            MPLS MC Group to add
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter.
    /// @retval     LA_STATUS_EEXIST    Member already exists in the group.
    /// @retval     LA_STATUS_ERESOURCE No resources to add IP multicast entries.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_mpls_multicast_group* mpls_mcg) = 0;

    /// @brief Remove MPLS Multicast group member from IP Multicast group.
    ///
    /// @param[in]  mpls_mcg              MPLS MC Group to remove
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter.
    /// @retval     LA_STATUS_ENOTFOUND Member not found in the group.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_mpls_multicast_group* mpls_mcg) = 0;

protected:
    virtual ~la_ip_multicast_group() = default;
};
}

/// @}

#endif // __LA_IP_MULTICAST_GROUP_H__
