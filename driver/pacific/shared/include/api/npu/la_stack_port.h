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

#ifndef __LA_STACK_PORT_H__
#define __LA_STACK_PORT_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Stack Port API-s.
///
/// Defines API-s for managing a Stack port #silicon_one::la_stack_port object.

namespace silicon_one
{

/// @addtogroup STACK
/// @{

/// @brief      A Stack port.
///
/// @details    A Stack port connects the peer switch/router to form a single forwarding plane.
///             It is built on top of a #silicon_one::la_system_port or #silicon_one::la_spa_port object.
class la_stack_port : public la_object
{
public:
    /// @brief Get system port associated with this stack port.
    ///
    /// @return la_system_port* for this stack port.\n
    ///         nullptr if port uses a #silicon_one::la_spa_port.
    virtual const la_system_port* get_system_port() const = 0;

    /// @brief Get SPA port associated with this stack port.
    ///
    /// @return la_spa_port* for this stack port.\n
    ///         nullptr if port uses a #silicon_one::la_system_port.
    virtual const la_spa_port* get_spa_port() const = 0;

    /// @brief When the switch/router is in active mode, set it's local punt system port to deliver the network control traffic
    /// coming from remote switch/router.
    ///
    /// @param[in]  system_port           System port of the stack node's local punt port
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      The system port is invalid
    virtual la_status set_local_punt_system_port(la_system_port* system_port) = 0;

    /// @brief When the switch/router is in non-active mode, set the stack port's system port to send all network control traffic to
    /// reach active.
    ///
    /// @param[in]  system_port           System port of one of the stack links preferred for remote punt
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      The system port is invalid
    virtual la_status set_remote_punt_system_port(la_system_port* system_port) = 0;

    /// @brief When the switch/router is in non-active mode, set the punt port MAC to be used for all network control traffic to be
    /// sent over stack port to reach active.
    ///
    /// @param[in]  mac_addr              MAC address to be used for punt packets
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      The system port is invalid
    virtual la_status set_remote_punt_src_mac(la_mac_addr_t mac_addr) = 0;

    /// @brief Set the peer device which can be reachable via this stack port.  All the traffic destined to this device will be
    /// sent over this stack port.
    ///
    /// @param[in]  peer_device_id        The peer device id of the remote stack port
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL      TBD
    virtual la_status set_peer_device_id(la_device_id_t peer_device_id) = 0;

    /// @brief Get the peer device id which is reachable via this stack port.
    ///
    /// @return la_device_id_t peer_device_id.
    virtual la_device_id_t get_peer_device_id() = 0;

    /// @brief Set queuing behaviour for control protocol traffic.  The control traffic will go over the special VoQ and it gets
    /// linked to high priority OQ.
    ///
    /// @param[in]  system_port            System port of the stack link which is preferred for control traffic.  In case stack link
    ///                                    is created using SPA, one of the preferred link should be passed.
    /// @param[in]  voq_set                Special VoQ set for control traffic.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL       Invalid system_port or voq_set or system_port is not a stack port member.
    /// @retval     LA_STATUS_EBUSY        Different voq_set is already programmed.
    virtual la_status set_control_traffic_queueing(la_system_port* system_port, la_voq_set* voq_set) = 0;

    /// @brief Get BVN destination id for control traffic.
    ///
    /// @param[in]   system_port           System port of the stack link used for control traffic.
    /// @param[in]   voq_offset            VoQ offset.
    ///
    /// @return      uint32_t              BVN destination id if valid system port and offset is passed, otherwise returns
    /// DESTINATION_ID_INVALID value.
    virtual uint32_t get_control_traffic_destination_id(la_system_port* system_port, la_uint_t voq_offset) = 0;

protected:
    ~la_stack_port() override = default;
};
}
/// @}

#endif
