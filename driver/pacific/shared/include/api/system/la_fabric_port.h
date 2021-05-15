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

#ifndef __LA_FABRIC_PORT_H__
#define __LA_FABRIC_PORT_H__

#include "api/types/la_object.h"
#include "api/types/la_system_types.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba fabric port API-s.
///
/// Defines API-s for managing a fabric port #silicon_one::la_fabric_port.

namespace silicon_one
{

/// @addtogroup FABRIC_PORT
/// @{

/// @brief Fabric port.
///
/// @details A fabric port is used for fabric topology discovery, queuing and scheduling over a fabric MAC port.

class la_fabric_port : public la_object
{
public:
    /// @brief Adjacent device peer info.
    struct adjacent_peer_info {
        la_device_id_t device_id; ///< Device ID of the adjacent peer.
        size_t port_num;          ///< This value is provided by the peer and should be deciphered in its context.
    };

    /// @brief Fabric port status information.
    struct port_status {
        bool peer_detected;  ///< True if a peer device is detected.
        bool fabric_link_up; ///< True if link is usable for transmit.
    };

    /// @brief Fabric link-protocols.
    enum class link_protocol_e {
        PEER_DISCOVERY, ///< Peer discovery protocol.
        LINK_KEEPALIVE  ///< Link keepalive protocol.
    };

    /// @brief Get the information of the peer device adjacent on this port.
    ///
    /// @param[out] out_adjacent_peer_info  Information peer info.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     No adjacent peer info exist. Might be due to fabric MAC port state.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_adjacent_peer_info(adjacent_peer_info& out_adjacent_peer_info) const = 0;

    /// @brief Set the device IDs of the LC devices reachable through this port.
    ///
    /// Sets the reachable device ID through this port. Manual configuration of reachable devices should be done if the system
    /// does not use automatic device discovery, and this device is not advertising itself; see
    /// #silicon_one::la_device_property_e::LC_ADVERTISE_DEVICE_ON_FABRIC_MODE.
    ///
    /// @param[in]  device_id_vec               Device ID vector.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED   Manual setting while advertising is not supported.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_reachable_lc_devices(const la_device_id_vec_t& device_id_vec) = 0;

    /// @brief Get the device IDs of the LC devices reachable through this port.
    ///
    /// @param[out] out_device_id_vec       Device ID vector to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     No reachability info exist. Might be due to port fabric MAC state.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_reachable_lc_devices(la_device_id_vec_t& out_device_id_vec) const = 0;

    /// @brief Return fabric port scheduler attached to this port.
    ///
    /// @return Fabric port scheduler object.
    virtual la_fabric_port_scheduler* get_scheduler() const = 0;

    /// @brief Activate a fabric link-protocol on this port.
    ///
    /// @param[in]  link_protocol           Fabric link-protocol.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    /// @retval     LA_STATUS_EAGAIN        Protocol did not start correctly.
    virtual la_status activate(link_protocol_e link_protocol) = 0;

    /// @brief Deactivate a fabric link-protocol on this port.
    ///
    /// @param[in]  link_protocol           Fabric link-protocol.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status deactivate(link_protocol_e link_protocol) = 0;

    /// @brief Check if a fabric link keepalive is activated on this port.
    ///
    /// @param[out] out_activated           True link keepalive is activated, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_link_keepalive_activated(bool& out_activated) const = 0;

    /// @brief Get fabric port status.
    ///
    /// @param[out] out_port_status         Contains fabric port status information.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_status(port_status& out_port_status) const = 0;

    /// @brief Get fabric MAC port associated with this port.
    ///
    /// @return la_mac_port* for this fabric port.
    virtual const la_mac_port* get_mac_port() const = 0;

protected:
    ~la_fabric_port() override = default;
};
}

/// @}

#endif
