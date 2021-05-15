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

#ifndef __LA_COMMON_TYPES_H__
#define __LA_COMMON_TYPES_H__

#include "common/la_status.h"
#include <stddef.h>
#include <stdint.h>
#include <vector>

/// @file
/// @brief Leaba Common definitions.
///
/// Defines Common types and enumerations used by the Leaba API.

namespace silicon_one
{
class la_protection_monitor;
class la_multicast_protection_monitor;
}

/// @addtogroup SYSTEM
/// @{

#define LA_BITS_TO_BYTES(n) ((n + 7) / 8)

typedef unsigned char la_uint8_t;
typedef unsigned short la_uint16_t;
typedef unsigned int la_uint32_t;
typedef unsigned long long la_uint64_t;
#ifndef SWIG
typedef unsigned __int128 la_uint128_t;
#endif

typedef int la_int_t;
typedef unsigned int la_uint_t;
typedef float la_float_t;

static const la_uint64_t LA_MAX_UINT64 = 0xffffffffffffffffULL;

struct la_device_s;
/// @brief Leaba device handle.
///
/// All objects are associated with a device on creation.
typedef struct la_device_s* la_device_t;

/// An invalid device.
static const la_device_t LA_DEVICE_INVALID = nullptr;

/// @brief Device ID.
///
/// Identifies a specific device in a system.
typedef la_uint16_t la_device_id_t;
static const la_device_id_t LA_DEVICE_ID_INVALID = (la_device_id_t)(-1);

/// @brief Object ID.
///
/// Each la_object has an object ID (oid, not to be confused with GID) used to uniquely identify this object in an la_device.
typedef uint64_t la_object_id_t;
static const la_object_id_t LA_OBJECT_ID_INVALID = (la_object_id_t)(-1);

/// @brief Slice ID.
///
/// Identifies a specific slice inside a device.
typedef la_uint_t la_slice_id_t;
static const la_slice_id_t LA_SLICE_ID_INVALID = (la_slice_id_t)(-1);

/// @brief Slice-pair ID.
///
/// Identifies a specific slice-pair inside a device.
typedef la_uint_t la_slice_pair_id_t;
static const la_slice_pair_id_t LA_SLICE_PAIR_ID_INVALID = (la_slice_pair_id_t)(-1);

/// @brief Interface Group ID.
///
/// Identifies a specific IFG inside a slice.
typedef la_uint_t la_ifg_id_t;
static const la_ifg_id_t LA_IFG_ID_INVALID = (la_ifg_id_t)(-1);

static const la_uint_t LA_SERDES_INVALID = (la_uint_t)(-1);
static const la_uint_t LA_PIF_INVALID = (la_uint_t)(-1);

/// IFG details
struct la_slice_ifg {
    la_slice_id_t slice; ///< Slice index.
    la_ifg_id_t ifg;     ///< IFG index.
};

/// serdes details
struct la_slice_serdices {
    bool is_logical = true; ///< false if this serdes passed a mapping from physical to logical.
    la_slice_id_t slice;    ///< Slice index.
    la_ifg_id_t ifg;        ///< IFG index.
    la_uint_t first_serdes; ///< first serdes in range.
    la_uint_t last_serdes;  ///< last serdes in range.
};

/// serdes details
struct la_slice_pif {
    bool is_logical = true; ///< false if this serdes passed a mapping from physical to logical.
    la_slice_id_t slice;    ///< Slice index.
    la_ifg_id_t ifg;        ///< IFG index.
    la_uint_t first_pif;    ///< first serdes in range.
    la_uint_t last_pif;     ///< last serdes in range.
};
namespace silicon_one
{
/// @brief Vector of slices.
using la_slice_id_vec_t = std::vector<la_slice_id_t>;
/// @brief Vector of slices.
using la_slice_pair_id_vec_t = std::vector<la_slice_pair_id_t>;
}

namespace silicon_one
{
/// @brief Identifies specific Block inside a device.
typedef uint32_t la_block_id_t;

/// @brief Invalid block ID.
static const la_block_id_t LA_BLOCK_ID_INVALID = (la_block_id_t)(-1);

/// @brief Address of an entry (register, memory or TCAM) inside a block.
typedef uint32_t la_entry_addr_t;

/// @brief Width of an entry (register or memory)
typedef uint16_t la_entry_width_t;
}

/// @brief SerDes direction
enum class la_serdes_direction_e {
    RX, ///< Receive direction
    TX, ///< Transmit direction
};
struct la_lb_fields_s;
/// Fields to use for load balancing hashing.
typedef struct la_lb_fields_s* la_lb_fields_t;

/// @brief Layers.
enum class la_layer_e {
    L2,
    L3,
};

/// @brief L3 protocols.
enum class la_l3_protocol_e {
    IPV4_UC,                ///< IPv4 unicast protocol
    IPV6_UC,                ///< IPv6 unicast protocol
    MPLS,                   ///< MPLS protocol
    MC_TUNNEL_DECAP = MPLS, ///< Multicast Tunnel Decap
    IPV4_MC,                ///< IPv4 multicast protocol
    IPV6_MC,                ///< IPv6 multicast protocol
    LAST,
};

/// @brief L3 protocols to be used for accounting.
enum class la_l3_protocol_counter_e {
    IPV4_UC, ///< IPv4 unicast protocol
    IPV6_UC, ///< IPv6 unicast protocol
    MPLS,    ///< MPLS protocol
    IPV4_MC, ///< IPv4 multicast protocol
    IPV6_MC, ///< IPv6 multicast protocol
    MPLS_SR, ///< MPLS Segment Routing
    LAST,
};

/// @brief MPLS SR protocols to be used for accounting.
enum class la_mpls_sr_protocol_counter_e {
    IP_UC, ///< IPv4 or IPv6 unicast protocol
    MPLS,  ///< MPLS Segment Routing
    LAST,
};

/// @brief IP versions.
enum class la_ip_version_e {
    IPV4, ///< IPv4 protocol
    IPV6, ///< IPv6 protocol
};

/// @brief Rate Limiters packet types.
enum class la_rate_limiters_packet_type_e {
    BC,         ///< Broadcast Packets
    UNKNOWN_MC, ///< Unknown Multicast Packets
    UNKNOWN_UC, ///< Unknown Unicast Packets
    MC,         ///< Multicast Packets
    UC,         ///< Unicast Packets
    LAST,
};

/// @brief L4 protocols.
enum class la_l4_protocol_e {
    HOP_BY_HOP = 0,
    ICMP = 1,
    IGMP = 2,
    TCP = 6,
    UDP = 17,
    RSVP = 46,
    GRE = 47,
    IPV6_ICMP = 58,
    EIGRP = 88,
    OSPF = 89,
    PIM = 103,
    VRRP = 112,
    L2TP = 113,
    IPV6_FRAGMENT = 44,
    RESERVED = 255,
};

/// @brief Load balancing modes.
enum class la_lb_mode_e {
    CONSISTENT = 0, ///< Load balancing is consistent when groups change.
    DYNAMIC,        ///< Load balancing changes when groups change.
};

/// @brief Hash functions for generating a load-balancing key.
enum class la_lb_hash_e {
    A = 0, ///< Load-balancing hash function A.
    B,     ///< Load-balancing hash function B.
    C,     ///< Load-balancing hash function C.
    D      ///< Load-balancing hash function D.
};

/// @ingroup EVENTS
typedef la_uint_t la_trap_priority_t;

/// @ingroup EVENTS
typedef la_uint_t la_snoop_priority_t;

/// @brief Counter index.
typedef la_uint32_t la_counter_index_t;

/// @brief Global VRF ID.
typedef la_uint_t la_vrf_gid_t;
static const la_vrf_gid_t LA_VRF_GID_INVALID = (la_vrf_gid_t)(-1);

/// @brief QoS class identifier that can be associated by a user to an ip route
typedef la_uint8_t la_class_id_t;
static const la_class_id_t LA_CLASS_ID_DEFAULT = (la_class_id_t)(0);

/// @brief Opaque token that can be associated by a user with a data info
typedef la_uint64_t la_user_data_t;

/// @brief Device family.
enum class la_device_family_e {
    NONE = 0,  ///< None
    PACIFIC,   ///< Pacific
    GIBRALTAR, ///< Gibraltar
    ASIC4, ///< Asic4
    ASIC3,  ///< Asic3
    ASIC7,    ///< Asic7
    ASIC5,     ///< Asic5

    LAST = ASIC5,
};

/// @brief Device revision.
enum class la_device_revision_e {
    NONE = 0,     ///< None
    PACIFIC_A0,   ///< Pacific revision A0
    PACIFIC_B0,   ///< Pacific revision B0
    PACIFIC_B1,   ///< Pacific revision B1
    GIBRALTAR_A0, ///< Gibraltar revision A0
    GIBRALTAR_A1, ///< Gibraltar revision A1
    GIBRALTAR_A2, ///< Gibraltar revision A2
    ASIC4_A0, ///< Asic4 revision A0
    ASIC3_A0,  ///< Asic3 revision A0
    ASIC7_A0,    ///< Asic3 revision A0
    ASIC5_A0,     ///< Asic5 revision A0

    LAST = ASIC5_A0,
};

/// @brief Layers.
enum class la_component_type_e {
    SERDES,
};

/// @brief Counters for the number of calls to the slow and fast poll functions.
struct la_component_health_t {
    la_component_type_e type; ///< Type of component
    la_uint_t addr;           ///< Address of component
    bool status;              ///< True for a healthy component, False for a failing component.
};

using la_component_health_vec_t = std::vector<la_component_health_t>;

static inline bool
is_pacific(la_device_revision_e rev)
{
    return (rev >= la_device_revision_e::PACIFIC_A0 && rev <= la_device_revision_e::PACIFIC_B1);
}

static inline bool
is_gibraltar(la_device_revision_e rev)
{
    return (rev >= la_device_revision_e::GIBRALTAR_A0 && rev <= la_device_revision_e::GIBRALTAR_A2);
}

static inline bool
is_asic4(la_device_revision_e rev)
{
    return (rev == la_device_revision_e::ASIC4_A0);
}

static inline bool
is_asic3(la_device_revision_e rev)
{
    return (rev == la_device_revision_e::ASIC3_A0);
}

static inline bool
is_asic7(la_device_revision_e rev)
{
    return (rev == la_device_revision_e::ASIC7_A0);
}

static inline bool
is_asic5(la_device_revision_e rev)
{
    return (rev == la_device_revision_e::ASIC5_A0);
}

/// @}

#endif // __LA_COMMON_TYPES_H__
