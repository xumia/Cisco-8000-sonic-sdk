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

#ifndef __LA_SPA_H__
#define __LA_SPA_H__

#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"
#include "api/types/la_system_types.h"

/// @file
/// @brief Leaba System Port Aggregate (SPA) port API-s.
///
/// Defines API-s for managing a System Port Aggregate (SPA) port #la_spa_port object.

/// @addtogroup PORT_SPA
/// @{

namespace silicon_one
{
/// @name General
/// @{

/// @brief System Port Aggregate Port.
///
/// System Port Aggregate (SPA) is a group of system ports, each attached to a MAC port, behaving like a single port (LAG) or
/// a group of system ports, each connected to a recycle port performing the same action (e.g. encryption).
class la_spa_port : public la_object
{
public:
    /// @brief Add system port to System Port Aggregate port.
    /// Traffic is not immediately transmitted on this port.
    /// Call #set_member_transmit_enabled to enable.
    ///
    /// @param[in]  system_port     System port to add.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port added successfully.
    /// @retval     LA_STATUS_EINVAL    System port is corrupt/invalid.
    /// @retval     LA_STATUS_EBUSY     System port is already part of a different SPA port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status add(const la_system_port* system_port) = 0;

    /// @brief Remove system port from System Port Aggregate port.
    ///
    /// @param[in]  system_port     System port to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port removed successfully.
    /// @retval     LA_STATUS_EINVAL    System port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND System port is not part of the SPA port.
    /// @retval     LA_STATUS_EBUSY     System port is transmit enabled.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status remove(const la_system_port* system_port) = 0;

    /// @brief Get system port by its index.
    ///
    /// @param[in]  member_idx              Member's idx.
    /// @param[out] out_system_port         System port to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Member index is out-of-range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_member(size_t member_idx, const la_system_port*& out_system_port) const = 0;

    /// @brief Get all system ports.
    ///
    /// @param[out] out_system_ports        System ports vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_members(system_port_vec_t& out_system_ports) const = 0;

    /// @brief Get all system ports that are enabled to transmit data traffic.
    ///
    /// @param[out] out_system_ports        System ports vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_transmit_enabled_members(system_port_vec_t& out_system_ports) const = 0;

    /// @brief Get all system ports in order stored for Member LB resolution
    /// Members may be replicated based on their port speeds.
    ///
    /// @param[out] out_system_ports        System ports vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_dspa_table_members(system_port_vec_t& out_system_ports) const = 0;

    /// @}
    /// @name Load Balancing
    /// @{

    /// @brief Set the load balancing mode.
    ///
    /// @param[in]  lb_mode             Load balancing mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Load balancing mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_lb_mode(la_lb_mode_e lb_mode) = 0;

    /// @brief Get the load balancing mode.
    ///
    /// @param[out] out_lb_mode         Load balancing mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Load balancing mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_lb_mode(la_lb_mode_e& out_lb_mode) const = 0;

    /// @}
    /// @name Multicast
    /// @{

    /// @brief Set system port as SPA port representative for a given multicast group.
    ///
    /// SPA port must be a member of the specific multicast group.
    /// The default behaviour is to add all members in the SPA to the multicast group and filter
    /// members according to hash.
    ///
    /// @param[in]  mc_gid          Mutlicast group GID.
    /// @param[in]  system_port     System port to use for multicast.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rrepresentative multicast member set successfully.
    /// @retval     LA_STATUS_EINVAL    System port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND System port is not a member of the SPA port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_representative_mc(la_multicast_group_gid_t mc_gid, la_system_port* system_port) = 0;

    /// @brief Clear multicast group representative for given SPA port.
    ///
    /// When no representative is set, all system ports are added to the multicast group, and filter members according to the hash.
    ///
    /// @param[in]  mc_gid          Mutlicast group GID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rrepresentative multicast member cleared successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_representative_mc(la_multicast_group_gid_t mc_gid) = 0;

    /// @brief Get SPA port's Global ID.
    ///
    /// @return Global ID of SPA port.
    virtual la_spa_port_gid_t get_gid() const = 0;

    /// @brief Add/Remove System Port to the Load Balancing table enabling/disabling Transmit
    ///
    /// @param[in]  system_port     System port to be acted upon.
    /// @param[in]  enabled         target transmit state. true if transmit enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port added successfully.
    /// @retval     LA_STATUS_EINVAL    System port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND System port is not part of the SPA port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_member_transmit_enabled(const la_system_port* system_port, bool enabled) = 0;

    /// @brief Get transmit state of the System Port in this System Port Aggregate.
    ///
    /// @param[in]  system_port     System port to be queried.
    ///
    /// @param[out]  out_enabled    programmed transmit state. true if transmit enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port transmit state retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_member_transmit_enabled(const la_system_port* system_port, bool& out_enabled) const = 0;

    /// @brief Add/Remove System Port to this SPA group enabling/disabling Receive
    ///
    /// @param[in]  system_port     System port to be acted upon.
    /// @param[in]  enabled         target receive state. true if receive enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port added successfully.
    /// @retval     LA_STATUS_EINVAL    System port is corrupt/invalid.
    /// @retval     LA_STATUS_ENOTFOUND System port is not part of the SPA port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_member_receive_enabled(const la_system_port* system_port, bool enabled) = 0;

    /// @brief Get receive state of the System Port in this System Port Aggregate.
    ///
    /// @param[in]  system_port     System port to be queried.
    ///
    /// @param[out]  out_enabled    programmed receive state. true if receive enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   System port receive state retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_member_receive_enabled(const la_system_port* system_port, bool& out_enabled) const = 0;

protected:
    ~la_spa_port() override = default;
};
}
/// @}

#endif
