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

#ifndef __LA_BFD_SESSION_H__
#define __LA_BFD_SESSION_H__

#include "api/types/la_bfd_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include <chrono>

/// @addtogroup BFD
/// @{

/// @file
/// @brief Leaba BFD Session API.
///
/// Defines API-s for managing a BFD session.
namespace silicon_one
{

class la_bfd_session : public la_object
{
public:
    /// @brief Session type.
    enum class type_e {
        ECHO,       ///< Echo-mode BFD
        MICRO,      ///< BFD over bundle
        MULTI_HOP,  ///< BFD multihop
        SINGLE_HOP, ///< Single-hop BFD
    };

    /// @brief Get the session type.
    ///
    /// @param[out] out_type            BFD session type.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_session_type(type_e& out_type) const = 0;

    /// @brief Get the local discriminator for the BFD session.
    ///
    /// @param[out] out_local_discriminator    Local discriminator.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    virtual la_status get_local_discriminator(la_bfd_discriminator& out_local_discriminator) const = 0;

    /// @brief Set the remote discriminator for the BFD session.
    ///
    /// @param[in]  remote_discriminator       Remote discriminator.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    virtual la_status set_remote_discriminator(la_bfd_discriminator remote_discriminator) = 0;

    /// @brief Get the remote discriminator for the BFD session.
    ///
    /// @param[out] out_remote_discriminator   Remote discriminator.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    virtual la_status get_remote_discriminator(la_bfd_discriminator& out_remote_discriminator) const = 0;

    /// @brief Set the local BFD state to send to the remote peer.
    ///
    /// @param[in]  diag_code           Local diag code.
    /// @param[in]  flags               Local BFD flags.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    virtual la_status set_local_state(la_bfd_diagnostic_code_e diag_code, la_bfd_flags flags) = 0;

    /// @brief Get the local BFD state we are sending to the remote peer.
    ///
    /// @param[out] out_diag_code       Local diag code
    /// @param[out] out_flags           Local BFD flags
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    virtual la_status get_local_state(la_bfd_diagnostic_code_e& out_diag_code, la_bfd_flags& out_flags) const = 0;

    /// @brief Set the BFD state for the remote peer.
    ///
    /// @param[in]  flags               Remote BFD flags.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    virtual la_status set_remote_state(la_bfd_flags flags) = 0;

    /// @brief Get the remote state for this bfd session.
    ///
    /// @param[out] out_flags           Local BFD flags
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_remote_state(la_bfd_flags& out_flags) const = 0;

    /// @brief Set the intervals to send to the remote peer.
    ///
    /// @param[in]  desired_min_tx_interval     Desired min TX interval.
    /// @param[in]  required_min_rx_interval    Required min RX interval.
    /// @param[in]  detection_time_multiplier   Required min RX interval.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE         Out of unique interval values.
    virtual la_status set_intervals(std::chrono::microseconds desired_min_tx_interval,
                                    std::chrono::microseconds required_min_rx_interval,
                                    uint8_t detection_time_multiplier)
        = 0;

    /// @brief Get the intervals we are sending to the remote peer.
    ///
    /// @param[out] out_desired_min_tx_interval     Desired min TX interval.
    /// @param[out] out_required_min_rx_interval    Required min RX interval.
    /// @param[out] out_detection_time_multiplier   Detection time multiplier.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         Intervals not configured.
    virtual la_status get_intervals(std::chrono::microseconds& out_desired_min_tx_interval,
                                    std::chrono::microseconds& out_required_min_rx_interval,
                                    uint8_t& out_detection_time_multiplier) const = 0;

    /// @brief Set the L3 network port for the BFD session.
    ///
    /// Valid only for SINGLE_HOP and ECHO sessions
    ///
    /// @param[in]  l3_port             L3 network port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Session is the wrong type.
    virtual la_status set_l3_port(la_l3_port* l3_port) = 0;

    /// @brief Get the L3 network port for the BFD session.
    ///
    /// @param[out] out_l3_port         Network port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND L3 port not configured for this session.
    virtual la_status get_l3_port(la_l3_port*& out_l3_port) const = 0;

    /// @brief Set the system port for micro-bfd session.
    ///
    /// Valid only MICRO sessions.
    ///
    /// @param[in]  system_port         System port identifying the LAG member for this micro-bfd session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not a micro-bfd session.
    /// @retval     LA_STATUS_EINVAL    System port not a member of system-port aggregate (SPA).
    virtual la_status set_system_port(la_system_port* system_port) = 0;

    /// @brief Get the system port for micro-bfd session.
    ///
    /// @param[out]  out_system_port    System port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND System port not configured for this session.
    virtual la_status get_system_port(la_system_port*& out_system_port) const = 0;

    /// @brief Get the punt destination for this session's packets.
    ///
    /// @param[out] out_destination     Punt destination.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Punt destination not configured for this session
    virtual la_status get_punt_destination(const la_punt_destination*& out_destination) const = 0;

    /// @brief Set the inject destination for this session's packets.
    ///
    /// This api is only for inject-down cases:
    ///   SINGLE_HOP to AC port
    ///   ECHO mode
    ///
    /// @param[in]  next_hop            Inject-down next-hop
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Next-hop is not suitable for inject-down
    virtual la_status set_inject_down_destination(const la_next_hop* next_hop) = 0;

    /// @brief Get the inject destination for this session's packets.
    ///
    /// @param[out]  out_next_hop       Inject-down next-hop
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_inject_down_destination(const la_next_hop*& out_next_hop) = 0;

    /// @brief Set the inject-up input port
    ///
    /// This a port on the desired VRF which will be used as the input port for
    /// outgoing packets.
    ///
    /// This api is only for inject-up cases:
    ///   MULTI_HOP
    ///   SINGLE_HOP over bundle or svi interfaces
    ///
    /// @param[in]  port                Input port for packet inject.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status set_inject_up_source_port(const la_l3_ac_port* port) = 0;

    /// @brief Get the inject-up input port.
    ///
    /// @param[out] out_l3_ac_port      Input port for packet inject.
    //
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_inject_up_source_port(const la_l3_ac_port*& out_l3_ac_port) = 0;

    /// @brief Set the packet transmit interval for this session.
    ///
    /// @param[in]  interval            Transmit interval.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE Number of unique intervals exceeded.
    virtual la_status set_transmit_interval(std::chrono::microseconds interval) = 0;

    /// @brief Get the packet transmit interval for this session.
    ///
    /// @param[out] out_interval        Transmit interval.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    virtual la_status get_transmit_interval(std::chrono::microseconds& out_interval) const = 0;

    /// @brief Set the IP tos for outgoing BFD packets.
    ///
    /// @param[in]  tos                 Outgoing TOS.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status set_ip_tos(la_ip_tos tos) = 0;

    /// @brief Get the IP tos for outgoing BFD packets.
    ///
    /// @param[out] out_tos             Outgoing TOS.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_ip_tos(la_ip_tos& out_tos) const = 0;

    /// @brief Set the local ipv4 address.
    ///
    /// @param[in]  local_addr          Local ipv4 address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an ipv4 session.
    virtual la_status set_local_address(la_ipv4_addr_t local_addr) = 0;

    /// @brief Get the local ipv4 address.
    ///
    /// @param[out] out_local_addr      Local ipv4 address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an ipv4 session.
    virtual la_status get_local_address(la_ipv4_addr_t& out_local_addr) const = 0;

    /// @brief Set the local ipv6 address.
    ///
    /// @param[in]  local_addr          Local ipv6 address
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ERESOURCE Out of unique ipv6 source addresses.
    /// @retval     LA_STATUS_EINVAL    Not an ipv6 session.
    virtual la_status set_local_address(la_ipv6_addr_t local_addr) = 0;

    /// @brief Get the local ipv6 address.
    ///
    /// @param[out] out_local_addr      Local ipv6 address
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an ipv6 session.
    virtual la_status get_local_address(la_ipv6_addr_t& out_local_addr) const = 0;

    /// @brief Set the remote ipv4 address.
    ///
    /// @param[in]  remote_addr         Remote ipv4 address.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status set_remote_address(la_ipv4_addr_t remote_addr) = 0;

    /// @brief Get the remote address for an ipv4 session.
    ///
    /// @param[out] out_remote_addr     Remote ipv4 address
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Not an ipv4 session.
    virtual la_status get_remote_address(la_ipv4_addr_t& out_remote_addr) const = 0;

    /// @brief Set the remote address for an ipv6 session.
    ///
    /// @param[in] remote_addr          Remote IPv6 address.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL     Not an IPv6 session.
    virtual la_status set_remote_address(la_ipv6_addr_t remote_addr) = 0;

    /// @brief Get the remote address for an ipv6 session.
    ///
    /// @param[out] remote_addr         Remote IPv6 address.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL     Not an IPv6 session.
    virtual la_status get_remote_address(la_ipv6_addr_t& remote_addr) const = 0;

    /// @brief Set the BFD session's counter.
    ///
    /// @param[in]  counter             Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid set size.
    /// @retval     LA_STATUS_EINVAL    Counter type is other than BFD.
    virtual la_status set_counter(la_counter_set* counter) = 0;

    /// @brief Get the BFD session's counter.
    ///
    /// @param[out] out_counter         Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_counter(la_counter_set*& out_counter) const = 0;

    /// @brief Set the detection time.
    ///
    /// @param[in]  detection_time      Detection time
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status set_detection_time(std::chrono::microseconds detection_time) = 0;

    /// @brief Get the detection time.
    ///
    /// @param[out] out_detection_time  Detection time.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_detection_time(std::chrono::microseconds& out_detection_time) const = 0;

    /// @brief Arm the detection timer.
    ///
    /// Arm the detection timer. To prevent excessive duplicate events, the
    /// detection timer is automatically disarmed when SDK receives an expiry event.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Detection time not configured.
    virtual la_status arm_detection_timer() = 0;

    /// @brief Disarm the detection timer.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status disarm_detection_timer() = 0;

    /// @brief Return internal id.
    ///
    /// @return Internal id for debugging purposes.
    virtual uint32_t get_internal_id() const = 0;

    /// @brief Return Echo mode enabled
    ///
    /// @return state of the echo mode enable.
    virtual bool get_echo_mode_enabled() const = 0;

    /// @brief Set Echo mode enabled.
    ///
    /// @param[in]  enabled      true if there is an Echo mode session associated with this Async session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Only set for IPv4 and Single hop sessions.
    virtual la_status set_echo_mode_enabled(bool enabled) = 0;

    /// @brief Get the traffic class for a session.
    ///
    /// @param[out] out_tc              Traffic class
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_traffic_class(la_traffic_class_t& out_tc) const = 0;

    /// @brief Set the traffic class for a session. Default is set to 7
    ///
    /// @param[in] tc                   Traffic class
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL     Traffic class not configured.
    virtual la_status set_traffic_class(la_traffic_class_t tc) = 0;

    /// @brief Get the encap MPLS label.
    ///
    /// @param[out] out_label           MPLS label.
    /// @param[out] out_ttl             MPLS TTL.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_ENOTINITIALIZED  Label has not been initialized.
    virtual la_status get_mpls_encap(la_mpls_label& out_label, la_uint8_t& out_ttl) const = 0;

    /// @brief Set the MPLS label for the outgoing BFD packet for a session.
    ///        Allows a BFD session to use inject up, with forwarding based on the label rather
    ///        than the IP destination address. When the device is configured in UNIFORM mode,
    ///        the TTL should be set to zero to allow it to wrap to 255, which will be copied to the
    ///        outgoing IP packet. The API is only supported for sessions using inject up.
    ///        ("if #silicon_one::la_bfd_session::set_inject_up_source_port is called")
    ///
    /// @param[in] label                MPLS label.
    /// @param[in] ttl                  MPLS TTL.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL     Session not configured using inject up.
    /// @retval    LA_STATUS_EINVAL     Label value in the special label range.
    virtual la_status set_mpls_encap(la_mpls_label label, la_uint8_t ttl) = 0;

    /// @brief Clear the MPLS label for the outgoing BFD packet for a session.
    ///
    /// @retval    LA_STATUS_SUCCESS    Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL     Programming error.
    virtual la_status clear_mpls_encap() = 0;

protected:
    ~la_bfd_session() override = default;
};

} // namespace silicon_one

/// @}

#endif // __LA_BFD_SESSION_H__
