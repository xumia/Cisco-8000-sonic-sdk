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

#ifndef __LA_MPLS_TYPES_H__
#define __LA_MPLS_TYPES_H__

#include "api/types/la_common_types.h"
#include "api/types/la_ip_types.h"

/// @file
/// @brief Leaba MPLS definitions.
///
/// Defines MPLS related types and enumerations used by the Leaba API.

namespace silicon_one

{
class la_destination_pe;
class la_lsr;
class la_mpls_multicast_group;
class la_mpls_label_destination;
class la_mpls_vpn_decap;
class la_mpls_vpn_encap;
class la_mldp_vpn_decap;
class la_mpls_nhlfe;
class la_multicast_protection_group;
class la_multicast_protection_monitor;
class la_prefix_object;
class la_te_tunnel;
class la_mldp_vpn_decap;

/// @addtogroup MPLS
/// @{

/// @brief IANA special purpose MPLS label values.
enum {
    LA_MPLS_LABEL_EXPLICIT_NULL_IPV4 = 0x0,
    LA_MPLS_LABEL_ROUTER_ALERT = 0x1,
    LA_MPLS_LABEL_EXPLICIT_NULL_IPV6 = 0x2,
    LA_MPLS_LABEL_IMPLICIT_NULL = 0x3,
    LA_MPLS_LABEL_ENTROPY_INDICATOR = 0x7,
    LA_MPLS_LABEL_GAL = 0xD,
    LA_MPLS_LABEL_OAM_ALERT = 0xE,
    LA_MPLS_LABEL_EXTENSION = 0xF,
};

/// MPLS action to perform on incoming label.
enum class la_mpls_action_e {
    INVALID,
    POP,               ///< Pop the top label from the incoming MPLS label stack.
    SWAP,              ///< Swap the top label of the incoming MPLS label stack.
    TUNNEL_PROTECTION, ///< RSVP TE Midpoint Tunnel Protection.
    L2_ADJACENCY,      ///< L2 Adjacency.
};

/// MPLS QOS inheritance mode.
enum class la_mpls_qos_inheritance_mode_e {
    PIPE,    ///< Pipe/Short-pipe model; do not inherit QOS from inner protocol/label.
    UNIFORM, ///< Uniform model; inherit QOS from inner protocol/label.
};

/// MPLS TTL inheritance mode.
enum class la_mpls_ttl_inheritance_mode_e {
    PIPE,    ///< Pipe/Short-pipe model; do not inherit TTL from inner protocol/label.
    UNIFORM, ///< Uniform model; inherit TTL from inner protocol/label.
};

/// TTL settings.
struct la_mpls_ttl_settings {
    la_mpls_ttl_inheritance_mode_e mode; ///< Inheritance mode.
    la_uint8_t ttl;                      ///< Initial TTL value for the tunnel in case of pipe TTL mode.
};

/// Label field in a MPLS label.
struct la_mpls_label {
    la_uint32_t label : 20;
};

/// MPLS Label stack vector
typedef std::vector<la_mpls_label> la_mpls_label_vec_t;

/// LSR label-entry information.
struct la_mpls_route_info {
    const la_l3_destination* destination; ///< Destination.
    la_vrf_gid_t vrf_gid;                 ///< VRF GID.
    la_user_data_t user_data;             ///< User data associated with the entry.
};

/// MPLS tunnel type.
enum class la_mpls_tunnel_type_e {
    PLAIN,      ///< Tunnel without VPN.
    VRF_VPN,    ///< Per PE and VRF VPN tunnel.
    PER_CE_VPN, ///< Per CE VPN tunnel.
    PWE,        ///< PWE tunnel.
};

/// MPLS VPN ENCAP object global ID.
typedef la_uint_t la_mpls_vpn_encap_gid_t;

/// MPLS VPN properties
struct la_mpls_vpn_properties_t {
    const la_l3_destination* bgp_nh;
    la_mpls_label_vec_t label;
    la_ip_version_e ip_version;
};

/// VPN label info vector
using la_mpls_vpn_properties_vec_t = std::vector<la_mpls_vpn_properties_t>;

/// @}

} // namespace silicon_one

#endif // __LA_MPLS_TYPES_H__
