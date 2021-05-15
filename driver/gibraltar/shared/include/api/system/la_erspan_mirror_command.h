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

#ifndef __LA_ERSPAN_MIRROR_COMMAND_H__
#define __LA_ERSPAN_MIRROR_COMMAND_H__

/// @file
/// @brief Leaba ERSPAN Mirror command API-s.
///
/// Defines API-s for managing and using ERSPAN Mirror command.
///

#include "api/system/la_mirror_command.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_tm_types.h"
#include "common/la_ip_addr.h"

/// @addtogroup PACKET
/// @{

namespace silicon_one
{

/// @brief ERSPAN Mirror command to configure snoop/mirror traffic.
///
class la_erspan_mirror_command : public la_mirror_command
{
public:
    /// @brief Encapsulation type of the ERSPAN session.
    enum class type_e {
        ERSPAN = 0,   ///< Remote SPAN session with GRE and an ERSPAN encapsulation.
        SFLOW_TUNNEL, ///< Remote SPAN session with UDP and custom metadata encapsulation.
    };

    /// @brief IPV4 transport header parameters.
    struct ipv4_transport_parameters {
        la_ipv4_addr_t tunnel_dest_addr;   ///< Destination IP Address for the ERSPAN session.
        la_ipv4_addr_t tunnel_source_addr; ///< Source IP Address for the ERSPAN session.
        la_uint_t ttl;                     ///< TTL for the ERSPAN session.
        la_ip_dscp dscp;                   ///< DSCP for the ERSPAN session.
    };

    /// @brief IPV6 transport header parameters.
    struct ipv6_transport_parameters {
        la_ipv6_addr_t tunnel_dest_addr;   ///< Destination IP Address for the ERSPAN session.
        la_ipv6_addr_t tunnel_source_addr; ///< Source IP Address for the ERSPAN session.
        la_uint_t ttl;                     ///< TTL for the ERSPAN session.
        la_ip_dscp dscp;                   ///< DSCP for the ERSPAN session.
    };

    /// @brief SFLOW Tunnel parameters.
    struct sflow_tunnel_parameters {
        la_uint16_t sport; ///< UDP source port
        la_uint16_t dport; ///< UDP destination port
    };

    /// @brief Session header parameters.
    union session_parameters {
        la_erspan_session_id_t session_id;
        sflow_tunnel_parameters sflow;
    };

    /// @brief Remote SPAN session encapsulation structure.
    struct ipv4_encapsulation {
        type_e type;                    ///< Remote SPAN Session type
        la_mac_addr_t mac_addr;         ///< Destination MAC for the Remote SPAN session
        la_mac_addr_t source_mac_addr;  ///< Source MAC for the Remote SPAN session
        la_vlan_tag_t vlan_tag;         ///< VLAN tag for the mirror command encapsulation.
        ipv4_transport_parameters ipv4; ///< Transport header definition
        session_parameters session;     ///< Session related parameters
    };

    /// @brief Remote SPAN session encapsulation structure.
    struct ipv6_encapsulation {
        type_e type;                    ///< Remote SPAN Session type
        la_mac_addr_t mac_addr;         ///< Destination MAC for the Remote SPAN session
        la_mac_addr_t source_mac_addr;  ///< Source MAC for the Remote SPAN session
        la_vlan_tag_t vlan_tag;         ///< VLAN tag for the mirror command encapsulation.
        ipv6_transport_parameters ipv6; ///< Transport header definition
        session_parameters session;     ///< Session related parameters
    };

    /// @brief Get ERSPAN session ID.
    ///
    /// @return ERSPAN session ID.
    virtual la_erspan_session_id_t get_session_id() const = 0;

    /// @brief Set the destination MAC associated with the session.
    ///
    /// @param[in]  mac_addr            Destination MAC associated with the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mac address updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_mac(la_mac_addr_t mac_addr) = 0;

    /// @brief Retrieve the destination MAC associated with the session.
    ///
    /// @param[out] out_mac_addr        Destination MAC associated with the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains destination's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Set the source MAC associated with the session.
    ///
    /// @param[in]  mac_addr            Source MAC associated with the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mac address updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_source_mac(la_mac_addr_t mac_addr) = 0;

    /// @brief Retrieve the source MAC associated with the session.
    ///
    /// @param[out] out_mac_addr        Source MAC associated with the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains destination's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_source_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Set the egress vlan tag associated with the session.
    ///
    /// @param[in]  vlan_tag            Egress vlan tag associated with the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Egress vlan tag updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_egress_vlan_tag(la_vlan_tag_t vlan_tag) = 0;

    /// @brief Retrieve the egress vlan tag associated with the session.
    ///
    /// @param[out] out_vlan_tag        Egress vlan tag associated with the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_vlan_tag contains the egress vlan tag.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_egress_vlan_tag(la_vlan_tag_t& out_vlan_tag) const = 0;

    /// @brief Set the Tunnel destination IP associated with the session.
    ///
    /// @param[in]  ip_addr      Destination IP for the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   IP address updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tunnel_destination(la_ip_addr ip_addr) = 0;

    /// @brief Retrieve the Tunnel destination IP associated with the session.
    ///
    /// @return Destination IP used for this ERSPAN session.
    ///
    virtual la_ip_addr get_tunnel_destination() const = 0;

    /// @brief Set the Tunnel source IP associated with the session.
    ///
    /// @param[in]  ip_addr    Source IP for the session.
    ///
    /// @retval     LA_STATUS_SUCCESS   IP address updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tunnel_source(la_ip_addr ip_addr) = 0;

    /// @brief Retrieve the Tunnel source IP associated with the session.
    ///
    /// @return Tunnel source IP used for this ERSPAN session.
    ///
    virtual la_ip_addr get_tunnel_source() const = 0;

    /// @brief Set the TTL for the ERSPAN session.
    ///
    /// @param[in]  ttl                 TTL to be used for the ERSPAN session
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    TTL is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ttl(la_uint_t ttl) = 0;

    /// @brief Return TTL used for this ERSPAN session.
    ///
    /// @return TTL used for this ERSPAN session.
    ///
    virtual la_uint_t get_ttl() const = 0;

    /// @brief Set the DSCP for the ERSPAN session.
    ///
    /// @param[in]  dscp                DSCP to be used for the ERSPAN session
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    dscp is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_dscp(la_ip_dscp dscp) = 0;

    /// @brief Return DSCP used for this ERSPAN session.
    ///
    /// @return DSCP used for this ERSPAN session.
    ///
    virtual la_ip_dscp get_dscp() const = 0;

    /// @brief Set the UDP source port for the ERSPAN session.
    ///
    /// @param[in]  sport               UDP source portto be used for the ERSPAN session
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status set_source_port(la_uint16_t sport) = 0;

    /// @brief Return UDP source port used for this ERSPAN session.
    ///
    /// @param[out] out_sport           UDP source port used for this ERSPAN session
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_sport contains the UDP source port.
    virtual la_status get_source_port(la_uint16_t& out_sport) const = 0;

    /// @brief Set the UDP destination port for the ERSPAN session.
    ///
    /// @param[in]  dport               UDP destination portto be used for the ERSPAN session
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status set_destination_port(la_uint16_t dport) = 0;

    /// @brief Return UDP destination port used for this ERSPAN session.
    ///
    /// @param[out] out_dport           UDP destination port used for this ERSPAN session
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_dport contains the UDP destination port.
    virtual la_status get_destination_port(la_uint16_t& out_dport) const = 0;

    /// @brief Set the ERSPAN session's counter.
    ///
    /// @param[in]  counter             Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid set size.
    virtual la_status set_counter(la_counter_set* counter) = 0;

    /// @brief Get the ERSPAN session's counter.
    ///
    /// @param[out] out_counter         Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_counter(la_counter_set*& out_counter) const = 0;

    /// @brief Set the destination port for the ERSPAN session.
    ///
    /// @param[in]  dsp                      Destination system port.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    One of the given ports is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_egress_port(const la_system_port* dsp) = 0;

    /// @brief Retrieve the system port used by this ERSPAN session.
    ///
    /// @return #silicon_one::la_system_port used by this session.
    virtual const la_system_port* get_system_port() const = 0;

    /// @brief Enable/disable mirror to truncate packet.
    ///
    /// Enabling this feature will limit the mirrored packet size up to 225B of the original packet.
    ///
    /// @param[in]      enabled                 True if truncation is enabled; false otherwise.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_truncate(bool enabled) = 0;

    /// @brief Get truncate state of the mirror.
    ///
    /// @retval         bool                    True if truncation is enabled; false otherwise.
    virtual bool get_truncate() const = 0;

protected:
    ~la_erspan_mirror_command() override = default;
};
}

/// @}

#endif // __LA_ERSPAN_MIRROR_COMMAND_H__
