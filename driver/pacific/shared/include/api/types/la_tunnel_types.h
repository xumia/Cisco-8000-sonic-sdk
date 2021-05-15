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

#ifndef __LA_TUNNEL_TYPES_H__
#define __LA_TUNNEL_TYPES_H__

#include "api/types/la_common_types.h"

/// @file
/// @brief Leaba tunnel type definitions.
///
/// Defines tunnel related types and enumerations used by the Leaba API.

namespace silicon_one

{
/// @addtogroup TUNNEL
/// @{

struct la_tunnel_s;
/// A Tunnel. Contains up to one encap and one decap.
typedef struct la_tunnel_s* la_tunnel_t;

struct la_tunnel_decap_s;
/// Tunnel decapsulator base class.
typedef struct la_tunnel_decap_s* la_tunnel_decap_t;

struct la_tunnel_encap_s;
/// Tunnel encapsulator base class.
typedef struct la_tunnel_encap_s* la_tunnel_encap_t;

struct la_ipv4_tunnel_decap_s;
/// An IPv4 Tunnel decapsulator.
/// @ingroup TUNNEL_IP
typedef struct la_ipv4_tunnel_decap_s* la_ipv4_tunnel_decap_t;

struct la_ipv4_tunnel_encap_s;
/// An IPv4 Tunnel encapsulator.
/// @ingroup TUNNEL_IP
typedef struct la_ipv4_tunnel_encap_s* la_ipv4_tunnel_encap_t;

struct la_ipv6_tunnel_decap_s;
/// An IPv6 Tunnel decapsulator.
/// @ingroup TUNNEL_IP
typedef struct la_ipv6_tunnel_decap_s* la_ipv6_tunnel_decap_t;

struct la_ipv6_tunnel_encap_s;
/// An IPv6 Tunnel encapsulator.
/// @ingroup TUNNEL_IP
typedef struct la_ipv6_tunnel_encap_s* la_ipv6_tunnel_encap_t;

struct la_ipv4_gre_tunnel_decap_s;
/// An IPv4 GRE Tunnel decapsulator.
/// @ingroup TUNNEL_IP_GRE
typedef struct la_ipv4_gre_tunnel_decap_s* la_ipv4_gre_tunnel_decap_t;

struct la_ipv4_gre_tunnel_encap_s;
/// An IPv4 GRE Tunnel encapsulator.
/// @ingroup TUNNEL_IP_GRE
typedef struct la_ipv4_gre_tunnel_encap_s* la_ipv4_gre_tunnel_encap_t;

struct la_ipv6_gre_tunnel_decap_s;
/// An IPv6 GRE Tunnel decapsulator.
/// @ingroup TUNNEL_IP_GRE
typedef struct la_ipv6_gre_tunnel_decap_s* la_ipv6_gre_tunnel_decap_t;

struct la_ipv6_gre_tunnel_encap_s;
/// An IPv6 GRE Tunnel encapsulator.
/// @ingroup TUNNEL_IP_GRE
typedef struct la_ipv6_gre_tunnel_encap_s* la_ipv6_gre_tunnel_encap_t;

struct la_mpls_tunnel_decap_s;
/// An MPLS Tunnel decapsulator.
/// @ingroup TUNNEL_MPLS
typedef struct la_mpls_tunnel_decap_s* la_mpls_tunnel_decap_t;

struct la_mpls_tunnel_encap_s;
/// An MPLS Tunnel encapsulator.
/// @ingroup TUNNEL_MPLS
typedef struct la_mpls_tunnel_encap_s* la_mpls_tunnel_encap_t;

/// An invalid tunnel.
static const la_tunnel_t LA_TUNNEL_INVALID = NULL;

/// An invalid IPv4 tunnel decapsulator.
/// @ingroup TUNNEL_IP
static const la_ipv4_tunnel_decap_t LA_IPV4_TUNNEL_DECAP_INVALID = NULL;

/// An invalid IPv4 tunnel encapsulator.
/// @ingroup TUNNEL_IP
static const la_ipv4_tunnel_encap_t LA_IPV4_TUNNEL_ENCAP_INVALID = NULL;

/// An invalid IPv6 tunnel decapsulator.
/// @ingroup TUNNEL_IP
static const la_ipv6_tunnel_decap_t LA_IPV6_TUNNEL_DECAP_INVALID = NULL;

/// An invalid IPv6 tunnel encapsulator.
/// @ingroup TUNNEL_IP
static const la_ipv6_tunnel_encap_t LA_IPV6_TUNNEL_ENCAP_INVALID = NULL;

/// An invalid IPv4 GRE tunnel decapsulator.
/// @ingroup TUNNEL_IP_GRE
static const la_ipv4_gre_tunnel_decap_t LA_IPV4_GRE_TUNNEL_DECAP_INVALID = NULL;

/// An invalid IPv4 GRE tunnel encapsulator.
/// @ingroup TUNNEL_IP_GRE
static const la_ipv4_gre_tunnel_encap_t LA_IPV4_GRE_TUNNEL_ENCAP_INVALID = NULL;

/// An invalid IPv6 GRE tunnel decapsulator.
/// @ingroup TUNNEL_IP_GRE
static const la_ipv6_gre_tunnel_decap_t LA_IPV6_GRE_TUNNEL_DECAP_INVALID = NULL;

/// An invalid IPv6 GRE tunnel encapsulator.
/// @ingroup TUNNEL_IP_GRE
static const la_ipv6_gre_tunnel_encap_t LA_IPV6_GRE_TUNNEL_ENCAP_INVALID = NULL;

/// An invalid MPLS tunnel decapsulator.
/// @ingroup TUNNEL_MPLS
static const la_mpls_tunnel_decap_t LA_MPLS_TUNNEL_DECAP_INVALID = NULL;

/// An invalid MPLS tunnel encapsulator.
/// @ingroup TUNNEL_MPLS
static const la_mpls_tunnel_encap_t LA_MPLS_TUNNEL_ENCAP_INVALID = NULL;

/// GRE tunnel key.
/// @ingroup TUNNEL_IP_GRE
typedef la_uint32_t la_gre_key_t;

/// GRE tunnel sequence number.
/// @ingroup TUNNEL_IP_GRE
typedef la_uint32_t la_gre_seq_num_t;

/// IP TUNNEL LP attribute inheritance mode.
enum class la_lp_attribute_inheritance_mode_e {
    PORT,   ///< inherit port attributes from L3 logical port.
    TUNNEL, ///< inherit port attributes from Tunnel.
};

/// TUNNEL encapsulated outer IP QoS setting mode.
/// @ingroup TUNNEL_IP_GRE
enum class la_tunnel_encap_qos_mode_e {
    UNIFORM, ///< encap outer IP tos is determined by egress_qos_profile mapping.
    PIPE,    ///< encap outer IP tos is overidden with a tunnel configuration.
};

// IP TUNNEL MODE.
/// @ingroup TUNNEL_IP_GRE
enum class la_ip_tunnel_mode_e {
    ENCAP_DECAP, ///< tunnel that supports encapsulation and decapsulation
    ENCAP_ONLY,  ///< tunnel that supports only encapsulation
    DECAP_ONLY   ///< tunnel that supports only decapsulation
};

/// @brief IP Tunnel Types
enum class la_ip_tunnel_type_e {
    IP_IN_IP = 0x0, ///< IP in IP Tunnel
    GRE = 0x1,      ///< GRE Tunnel
    GUE = 0x2,      ///< GUE Tunnel
    VXLAN = 0x3,    ///< VxLAN Tunnel
    NVGRE = 0x4,    ///< NVGRE Tunnel
    LAST = NVGRE,
};

/// @}

} // namespace silicon_one

#endif // __LA_TUNNEL_TYPES_H__
