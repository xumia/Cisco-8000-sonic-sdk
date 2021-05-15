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

#ifndef __LA_IP_TYPES_H__
#define __LA_IP_TYPES_H__

#include "api/types/la_common_types.h"
#include <vector>

namespace silicon_one
{
class la_counter_set;
class la_ecmp_group;
class la_pbts_group;
class la_gre_port;
class la_gue_port;
class la_ip_multicast_group;
class la_l2_multicast_group;
class la_ip_tunnel_destination;
class la_l3_destination;
class la_l3_fec;
class la_l3_port;
class la_l3_ac_port;
class la_next_hop;
class la_vxlan_next_hop;
class la_svi_port;
class la_ip_over_ip_tunnel_port;
class la_vrf;

/// @file
/// @brief Leaba IP definitions.
///
/// Defines IP related types and enumerations used by the Leaba API.

/// @addtogroup L3PORT
/// @{

/// l3 destinations vector
typedef std::vector<const la_l3_destination*> la_l3_destination_vec_t;

/// An IPv4 address.
union la_ipv4_addr_t {
    la_uint8_t b_addr[4]; ///< IPv4 address in byte fragments
    la_uint32_t s_addr;   ///< IPv4 address, flat
};

/// An IPv4 network prefix.
struct la_ipv4_prefix_t {
    la_ipv4_addr_t addr; ///< IPv4 address
    la_uint_t length;    ///< Length of prefix, in bits

    bool operator==(const la_ipv4_prefix_t& pfx) const
    {
        return ((addr.s_addr == pfx.addr.s_addr) && (length == pfx.length));
    }
};

/// An IPv6 address.
union la_ipv6_addr_t {
    la_uint8_t b_addr[16]; ///< IPv6 address in byte fragments
    la_uint16_t w_addr[8]; ///< IPv6 address in word fragments
    la_uint32_t d_addr[4]; ///< IPv6 address in double-word fragments
    la_uint64_t q_addr[2]; ///< IPv6 address in quad-word fragments
    la_uint128_t s_addr;
};

/// An IPv6 network prefix.
struct la_ipv6_prefix_t {
    la_ipv6_addr_t addr; ///< IPv6 address
    la_uint_t length;    ///< Length of prefix, in bits

    bool operator==(const la_ipv6_prefix_t& pfx) const
    {
        return ((addr.s_addr == pfx.addr.s_addr) && (length == pfx.length));
    }
};

/// An IPv6 extension header code.
typedef la_uint8_t la_ipv6_extension_header_t;

/// A special IPv4 address which is illegal and used as ANY IPv4 address.
static const la_ipv4_addr_t LA_IPV4_ANY_IP = {.s_addr = 0xFFFFFFFF};

/// A special IPv6 address which is illegal and used as ANY IPv6 address.
static const la_ipv6_addr_t LA_IPV6_ANY_IP = {.d_addr = {0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF}};

/// A special IPv4 prefix covering the range used only for multicast addresses.
static const la_ipv4_prefix_t LA_IPV4_MC_PREFIX = {.addr = {.s_addr = 0xE0000000}, .length = 4};

/// A special IPv6 prefix covering the range used only for multicast addresses.
static const la_ipv6_prefix_t LA_IPV6_MC_PREFIX
    = {.addr = {.d_addr = {0x00000000, 0x00000000, 0x00000000, 0xFF000000}}, .length = 8};

/// Default VXLAN UDP port
static const la_uint_t LA_VXLAN_DEFAULT_UDP_PORT = 4789;

/// Global L3 destination ID.
typedef la_uint_t la_l3_destination_gid_t;
static const la_l3_destination_gid_t LA_L3_DESTINATION_GID_INVALID = (la_l3_destination_gid_t)(-1);

/// Global L3 port ID.
typedef la_uint_t la_l3_port_gid_t;
static const la_l3_port_gid_t LA_L3_PORT_GID_INVALID = (la_l3_port_gid_t)(-1);

/// FEC ID.
typedef la_uint_t la_fec_gid_t;

/// Global PCL ID.
typedef la_uint_t la_pcl_gid_t;

/// Global LPTS application ID.
typedef la_uint_t la_lpts_app_gid_t;

/// Global Next Hop ID.
typedef la_uint_t la_next_hop_gid_t;

/// Global TE Tunnel ID.
typedef la_uint_t la_te_tunnel_gid_t;

/// Global L3 protection group ID.
typedef la_uint_t la_l3_protection_group_gid_t;

/// The "default" VRF of the system. TODO: think if we need it
static const la_vrf_gid_t LA_VRF_GID_DEFAULT = 0;

/// @brief IPv6 extension header options.
enum {
    LA_IPV6_EXT_HDR_HOP_BY_HOP = 0x0,   ///< IPv6 extension header Hop-by-Hop option
    LA_IPV6_EXT_HDR_ROUTING = 0x2B,     ///< IPv6 extension header Routing option
    LA_IPV6_EXT_HDR_DESTINATION = 0x3C, ///< IPv6 extension header Destination option
    LA_IPV6_EXT_HDR_MOBILITY = 0x87,    ///< IPv6 extension header Mobility option
};

/// @brief Feature type PCL is attached too.
enum class pcl_feature_type_e {
    ACL = 0, ///< ACL attached PCL
    LPTS,    ///< LPTS attached PCL
    LAST,
};

/// Hold the return value of get_ip*_route functions
struct la_ip_route_info {
    bool is_host; ///< True iff the queried address belongs to a directly attached host, in which case the 'l3_dest' holds NULL
    la_class_id_t class_id;           ///< Class identifier passed by the user at add-route
    la_user_data_t user_data;         ///< Token that were passed by the user at add-route
    const la_l3_destination* l3_dest; ///< L3 destination in case there is one (queried address is not of a directly attached host)
    bool latency_sensitive;           ///< True if the queried address is latency sensitive
};

/// Hold the return value of get_ip*_multicast_route functions
struct la_ip_mc_route_info {
    const la_ip_multicast_group* mcg; ///< Multicast group object.
    const la_l3_port* rpf;            ///< Reverse path forwarding port.
    bool punt_on_rpf_fail;            ///< Punt on RPF fail.
    bool punt_and_forward;            ///< Punt and forward.
    const la_counter_set* counter;    ///< Counter.
    bool use_rpfid;
    la_uint_t rpfid;
    bool enable_rpf_check;
};

struct la_l2_mc_route_info {
    const la_l2_multicast_group* mcg;
};

struct la_ipv4_route_entry {
    la_ipv4_prefix_t prefix;
    la_ip_route_info route_info;
};

struct la_ipv6_route_entry {
    la_ipv6_prefix_t prefix;
    la_ip_route_info route_info;
};

using la_ipv4_route_entry_vec = std::vector<la_ipv4_route_entry>;
using la_ipv6_route_entry_vec = std::vector<la_ipv6_route_entry>;

/// l3 destinations vector
typedef std::vector<la_ipv4_prefix_t> la_ipv4_prefix_vec_t;

/// l3 destinations vector
typedef std::vector<la_ipv6_prefix_t> la_ipv6_prefix_vec_t;

/// TTL inheritance mode.
enum class la_ttl_inheritance_mode_e {
    PIPE,    ///< Pipe/Short-pipe model; do not inherit TTL from inner IP header.
    UNIFORM, ///< Uniform model; inherit TTL from inner IP header.
};

/// Prefix compression list bincode
typedef la_uint_t la_pcl_bincode_t;

/// @brief v4 prefix compression
struct la_pcl_v4 {
    la_ipv4_prefix_t prefix;
    la_uint_t bincode;
};

typedef std::vector<la_pcl_v4> la_pcl_v4_vec_t;

/// @brief v6 prefix compression
struct la_pcl_v6 {
    la_ipv6_prefix_t prefix;
    la_uint_t bincode;
};

typedef std::vector<la_pcl_v6> la_pcl_v6_vec_t;

/// l3 ip address vector
typedef std::vector<la_ipv4_addr_t> la_ipv4_addr_vec_t;
using la_ipv4_addr_vec = std::vector<la_ipv4_addr_t>;

typedef std::vector<la_ipv6_addr_t> la_ipv6_addr_vec_t;
using la_ipv6_addr_vec = std::vector<la_ipv6_addr_t>;

/// ip snooping vector
struct la_ip_snooping_entry_t {
    la_ip_version_e ip_version;
    la_vrf_gid_t vrf_gid;
    union prefix_ {
        la_ipv4_prefix_t ipv4;
        la_ipv6_prefix_t ipv6;
    } prefix;
    bool ip_inactivity_punt;
};

typedef std::vector<la_ip_snooping_entry_t> la_ip_snooping_entry_vec_t;

/// @}

} // namespace silicon_one

#endif // __LA_IP_TYPES_H__
