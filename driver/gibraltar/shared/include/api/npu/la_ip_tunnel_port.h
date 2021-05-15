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

#ifndef __LA_IP_TUNNEL_PORT_H__
#define __LA_IP_TUNNEL_PORT_H__

#include "api/npu/la_l3_port.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_tm_types.h"

namespace silicon_one
{

/// @file
/// @brief Leaba IP Tunnel Port API-s.
///
/// Defines API-s for managing IP tunnel port object.

class la_ip_tunnel_port : public la_l3_port
{

public:
    /// @addtogroup L3PORT_IP_TUNNEL
    /// @{

    /// IP TUNNEL TTL inheritance mode.
    enum class la_ttl_inheritance_mode_e {
        PIPE,    ///< Pipe/Short-pipe model; do not inherit TTL from inner IP header.
        UNIFORM, ///< Uniform model; inherit TTL from inner IP header.
    };

    /// @brief Set the underlay VRF of the tunnel
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL           Invalid VRF specified.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_underlay_vrf(const la_vrf* underlay_vrf) = 0;

    /// @brief Return the underlay VRF of the tunnel
    ///
    /// @return    The underlay VRF associated with this la_gre_port.
    virtual const la_vrf* get_underlay_vrf() const = 0;

    /// @brief Return the local IP address of the tunnel
    ///
    /// @return    The local IP address associated with this la_gre_port.
    virtual la_ipv4_addr_t get_local_ip_addr() const = 0;

    /// @brief Set the local IP address of the tunnel
    ///
    /// @param[in]  local_ip_address          Local IP address of the tunnel.
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_local_ip_address(la_ipv4_addr_t local_ip_address) = 0;

    /// @brief Return the remote IP address of the tunnel
    ///
    /// @return    The remote IP address associated with this la_gre_port.
    virtual la_ipv4_addr_t get_remote_ip_addr() const = 0;

    /// @brief Set the remote IP address of the tunnel
    ///
    /// @param[in]  remote_ip_address         Remote IP address of the tunnel.
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_remote_ip_address(la_ipv4_addr_t remote_ip_address) = 0;

    /// @brief Return the overlay VRF object that this port is attached to.
    ///
    /// @return    The overlay VRF associated with this port.
    virtual const la_vrf* get_overlay_vrf() const = 0;

    /// @brief Set the overlay VRF that this port is attached to.
    ///
    /// @param[in]  overlay_vrf               Overlay VRF to attach this port to.
    ///
    /// @retval    LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval    LA_STATUS_EINVAL           Invalid VRF specified.
    /// @retval    LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_overlay_vrf(const la_vrf* overlay_vrf) = 0;

    /// @brief Get TTL inheritance mode for this port.
    ///
    /// @return  TTL inheritance mode.
    virtual la_ttl_inheritance_mode_e get_ttl_inheritance_mode() const = 0;

    /// @brief Set the TTL inheritance mode for this port.
    ///
    /// @param[in] mode                   TTL inheritance mode.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_ttl_inheritance_mode(la_ttl_inheritance_mode_e mode) = 0;

    /// @brief Get TTL value for this port.
    ///
    /// @return  TTL value in bytes.
    virtual la_uint8_t get_ttl() const = 0;

    /// @brief Set TTL for this port.
    ///
    /// @param[in]  ttl                   TTL value. Default is 255.
    ///                                   The TTL value is set the outer IP header when entering to the GRE tunnel.
    ///                                   Only applicable when the TTL inheritance mode is la_ttl_inheritance_mode_e::PIPE.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_ttl(la_uint8_t ttl) = 0;

    /// @brief Determine if the TTL is decremented for packets encapsulated in the tunnel.
    ///
    /// @return  True if the tunnel decrements the inner TTL, false otherwise.
    virtual bool get_decrement_inner_ttl() const = 0;

    /// @brief Configure whether the TTL is decremented for packets encapsulated in the tunnel.
    ///
    /// @param[in]  decrement_inner_ttl  true if the tunnel should decrement the inner TTL, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_decrement_inner_ttl(bool decrement_inner_ttl) = 0;

    /// @brief Get encap_tos for this tunnel.
    ///
    /// @param[out] out_encap_tos         The tunnel's encap_tos.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status get_encap_tos(la_ip_tos& out_encap_tos) const = 0;

    /// @brief Set encap_tos for this tunnel.
    ///
    /// @param[in]  encap_tos             encap_tos value. Default is flat 0.
    ///                                   This value is to set the outer IP header tos field of packets encapsulated in the tunnel.
    ///                                   Only applicable when the tunnel's encap_qos_mode is PIPE.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_encap_tos(la_ip_tos encap_tos) = 0;

    /// @brief Get the encapsulated packet outer IP QoS setting mode.
    ///
    /// @return     PIPE if the outer IP tos is taken from the tunnel's configured encap_tos.
    ///             UNIFORM then it is derived from the original packet.
    virtual la_tunnel_encap_qos_mode_e get_encap_qos_mode() const = 0;

    /// @brief Set the encapsulated packet outer IP QoS setting mode.
    ///
    /// @param[in]  mode                  PIPE then the outer IP tos is taken from the tunnel's configured encap_tos.
    ///                                   UNIFORM then it is derived from the original packet.
    ///                                   Default is UNIFORM.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_encap_qos_mode(la_tunnel_encap_qos_mode_e mode) = 0;

    /// @brief Get LP attribute inheritance mode for this port.
    ///
    /// @return  LP attribute inheritance mode.
    virtual la_lp_attribute_inheritance_mode_e get_lp_attribute_inheritance_mode() const = 0;

    /// @brief Set the LP attribute inheritance mode for this port.
    ///
    /// @param[in] mode                   LP attribute inheritance mode.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e mode) = 0;

protected:
    ~la_ip_tunnel_port() override = default;
    /// @}
};

} // namepace leaba

#endif // __LA_IP_TUNNEL_PORT_H__
