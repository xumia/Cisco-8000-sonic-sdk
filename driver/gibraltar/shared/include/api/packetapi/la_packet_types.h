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

#ifndef __LA_PACKET_TYPES_H__
#define __LA_PACKET_TYPES_H__

/// @file
/// @brief Leaba Packet Punt/Inject type definitions.
///
/// @details Defines Packet Punt/Inject related types and enumerations.

#include <stdint.h>

#include "la_packet_headers.h"

namespace silicon_one
{

/// @addtogroup PACKET
/// @{

#ifndef SWIGPYTHON
namespace la_packet_types
{
#else
struct la_packet_types {
#endif

enum { LA_PROTOCOL_TYPE_VLAN_PREFIX = 8 };
enum { LA_PROTOCOL_TYPE_SYSTEM_PREFIX = 0x1E };
enum { LA_PROTOCOL_TYPE_L4_PREFIX = 0xE };

enum { LA_HEADER_TYPE_IPV4_HEADERS_PREFIX = 2 };
enum { LA_HEADER_TYPE_IPV6_HEADERS_PREFIX = 4 };
enum { LA_HEADER_TYPE_MPLS_HEADERS_PREFIX = 8 };
enum { LA_HEADER_TYPE_IP_ROUTE_SUFFIX = 0 };        // ip routed packet fwd (UC / MC none collapsed)
enum { LA_HEADER_TYPE_IP_COLLAPSED_MC_SUFFIX = 1 }; // Ip routed packet collapsed mc fwd

/// @brief Inject packet types.
///
/// @details Packet type signals the NPU how to process the injected packet.
enum la_packet_inject_type_e {
    LA_PACKET_INJECT_TYPE_DOWN,          ///< Encapsulated packet, ready to be sent on the wire. \n
                                         ///< No processing will be done for that packet.
    LA_PACKET_INJECT_TYPE_UP_ETH = 0x22, ///< Packet will be processed as Ethernet packet ingressing on specified system port.
    LA_PACKET_INJECT_TYPE_UP_STD_PROCESS = 0x26, ///< Packet will be processed as Ethernet packet coming from actual ingress port.
    LA_PACKET_INJECT_TYPE_UP_DESTINATION_OVERRIDE = 0x2e, ///< Packet will be processed as Ethernet packet coming from actual
                                                          /// ingress port. But the forwarding destination is replaced with
    /// destination provided in the inject header.
    LA_PACKET_INJECT_TYPE_UP_LEARN_RECORD = 0x2f, ///< MAC learning records generated by NPU Host
};

/// @brief Inject packet extension types.
///
/// @details Extension type signals the NPU what type of inject extension exists.
enum la_packet_inject_ext_type_e {
    LA_INJECT_HEADER_EXT_TYPE_NONE = 0, ///< No extension.
    LA_INJECT_HEADER_EXT_TYPE_TIME = 4, ///< Time extension (To be used for injecting PTP packets).
};

/// @brief Time stamp command opcode.
///
/// @details Time stamp command opcode used in packet inject time stamp.
enum la_packet_time_stamp_command_e {
    LA_PACKET_TIME_STAMP_COMMAND_OP_NOP = 0x0,
    LA_PACKET_TIME_STAMP_COMMAND_UPDATE_CF = 0x1,
    LA_PACKET_TIME_STAMP_COMMAND_UPDATE_CF_UPDATE_CS = 0x2,
    LA_PACKET_TIME_STAMP_COMMAND_UPDATE_CF_RESET_CS = 0x3,
    LA_PACKET_TIME_STAMP_COMMAND_STAMP_DEV_TIME = 0x5,
    LA_PACKET_TIME_STAMP_COMMAND_STAMP_DEV_TIME_UPDATE_CS = 0x6,
    LA_PACKET_TIME_STAMP_COMMAND_STAMP_DEV_TIME_RESET_CS = 0x7,
    LA_PACKET_TIME_STAMP_COMMAND_STAMP_IN_SYS_TIME = 0x8,
    LA_PACKET_TIME_STAMP_COMMAND_RECORD = 0x9,
};

/// @brief Inject packet down destination types.
///
/// @details Valid destination for inject down packets.
enum la_packet_inject_down_dest_e {
    LA_PACKET_INJECT_DOWN_DEST_DSP, ///< Down destination is Destination System Port.
    LA_PACKET_INJECT_DOWN_DEST_BVN, ///< Down destination is Base VOQ Number.
};

/// @brief Destination global ID prefix.
///
/// @details Inject down with global ID must use one of the prefixes.
enum la_packet_destination_gid_prefix_e {
    LA_PACKET_DESTINATION_GID_PREFIX_DSP = 0x58000, ///< Destination System Port global ID prefix.
    LA_PACKET_DESTINATION_GID_PREFIX_BVN = 0xF0000, ///< Base VOQ Number global ID prefix.
};

/// @brief Destination prefix.
///
/// @details Inject up with destination override must use one of the destination prefixes.
enum la_packet_destination_prefix_e {
    LA_PACKET_DESTINATION_PREFIX_MCID = 0xe0000, ///< MCID prefix.
};

/// @brief Destination prefix mask.
///
/// @details mask for destination prefix.
enum la_packet_destination_prefix_mask_e {
    LA_PACKET_DESTINATION_PREFIX_MASK_MCID = 0xf0000, ///< MCID prefix mask.
};

/// @brief Inject packet down encapsulation types.
///
/// @details Encapsulation for inject down packets.
enum la_packet_inject_down_encap_e {
    LA_PACKET_INJECT_DOWN_ENCAP_NONE = 0, ///< No encapsulation.
};

/// @brief Protocol type enumeration.
///
/// Protocol of a packet layer identified by the format identifier.
enum la_protocol_type_e {
    LA_PROTOCOL_TYPE_UNKNOWN = 0,                                 ///< Unknown protocol.
    LA_PROTOCOL_TYPE_ETHERNET = 1,                                ///< Ethernet.
    LA_PROTOCOL_TYPE_UDP = (LA_PROTOCOL_TYPE_L4_PREFIX | 1),      ///< UDP protocol.
    LA_PROTOCOL_TYPE_IPV4 = 4,                                    ///< IPv4 protocol.
    LA_PROTOCOL_TYPE_IPV6 = 6,                                    ///< IPv6 protocol.
    LA_PROTOCOL_TYPE_MPLS = 7,                                    ///< MPLS protocol.
    LA_PROTOCOL_TYPE_VLAN_0 = (LA_PROTOCOL_TYPE_VLAN_PREFIX | 0), ///< VLAN protocol with TPID 0x8100.
    LA_PROTOCOL_TYPE_VLAN_1 = (LA_PROTOCOL_TYPE_VLAN_PREFIX | 1), ///< VLAN protocol with TPID 0x9100.
    LA_PROTOCOL_TYPE_GRE = 16,                                    ///< GRE protocol.
    LA_PROTOCOL_TYPE_ARP = 25,                                    ///< ARP protocol.

    // system protocol layer types
    LA_PROTOCOL_TYPE_PUNT = (LA_PROTOCOL_TYPE_SYSTEM_PREFIX | 0),   ///< Punt protocol.
    LA_PROTOCOL_TYPE_INJECT = (LA_PROTOCOL_TYPE_SYSTEM_PREFIX | 1), ///< Inject protocol.
};

/// @brief Header type enumeration.
///
/// Packet header type as identified by the format identifier.
enum la_header_type_e {
    LA_HEADER_TYPE_ETHERNET = 0,                                                                 ///< Ethernet header.
    LA_HEADER_TYPE_IPV4 = (LA_HEADER_TYPE_IPV4_HEADERS_PREFIX | LA_HEADER_TYPE_IP_ROUTE_SUFFIX), ///< IPv4 header.
    LA_HEADER_TYPE_IPV4_COLLAPSED_MC
    = (LA_HEADER_TYPE_IPV4_HEADERS_PREFIX | LA_HEADER_TYPE_IP_COLLAPSED_MC_SUFFIX), ///< IPv4 collapsed multicast header.
    LA_HEADER_TYPE_IPV6 = (LA_HEADER_TYPE_IPV6_HEADERS_PREFIX | LA_HEADER_TYPE_IP_ROUTE_SUFFIX), ///< IPv6 header.
    LA_HEADER_TYPE_IPV6_COLLAPSED_MC
    = (LA_HEADER_TYPE_IPV6_HEADERS_PREFIX | LA_HEADER_TYPE_IP_COLLAPSED_MC_SUFFIX), ///< IPv6 collapsed multicast header.

    LA_HEADER_TYPE_MPLS_NO_BOS = (LA_HEADER_TYPE_MPLS_HEADERS_PREFIX | 0), ///< Non Bottom-Of-Stack MPLS header.
    LA_HEADER_TYPE_MPLS_BOS_IPV4
    = (LA_HEADER_TYPE_MPLS_HEADERS_PREFIX | 1), ///< Bottom-Of-Stack MPLS header followed with IPv4 header.
    LA_HEADER_TYPE_MPLS_BOS_IPV6
    = (LA_HEADER_TYPE_MPLS_HEADERS_PREFIX | 2), ///< Bottom-Of-Stack MPLS header followed with IPv6 header.
    LA_HEADER_TYPE_MPLS_BOS_ETHERNET
    = (LA_HEADER_TYPE_MPLS_HEADERS_PREFIX | 3), ///< Bottom-Of-Stack MPLS header followed with Ethernet header.

    LA_HEADER_TYPE_INJECT_DOWN = 0xC, ///< Inject down header.
    LA_HEADER_TYPE_REDIRECT = 0xF,    ///< Redirect header.
};

/// @brief Punt packet source.
///
/// @details Indicates the trigger/location for punting the packet.
enum la_packet_punt_source_e {
    LA_PACKET_PUNT_SOURCE_INBOUND_MIRROR = 0x0,     ///< Inbound mirror due to ingress security ACL mirroring decision.
    LA_PACKET_PUNT_SOURCE_SNOOP = 0x1,              ///< Snoop.
    LA_PACKET_PUNT_SOURCE_LPTS_FORWARDING = 0x2,    ///< Regular forwarding.
    LA_PACKET_PUNT_SOURCE_INGRESS_ACL = 0x3,        ///< Ingress ACL.
    LA_PACKET_PUNT_SOURCE_INGRESS_TRAP = 0x4,       ///< Ingress trap.
    LA_PACKET_PUNT_SOURCE_INGRESS_INCOMPLETE = 0x5, ///< LPM incomplete lookup result.
    LA_PACKET_PUNT_SOURCE_NPUH = 0x6,               ///< From the NPU host.

    LA_PACKET_PUNT_SOURCE_OUTBOUND_MIRROR = 0xA, ///< Outbound mirror.
    LA_PACKET_PUNT_SOURCE_EGRESS_ACL = 0xB,      ///< Egress ACL.
    LA_PACKET_PUNT_SOURCE_EGRESS_TRAP = 0xC,     ///< Egress trap.
};

enum {
    LA_SYSTEM_PORT_GID_INVALID = 0xFFFF,      ///< Invalid system port GID.
    LA_L2_LOGICAL_PORT_GID_INVALID = 0x3FFFF, ///< Invalid L2 logical port GID.
    LA_L3_LOGICAL_PORT_GID_INVALID = 0x7FFF,  ///< Invalid L3 logical port GID.
};

/// @brief MAC learning notification types.
///
enum la_learn_notification_type_e {
    LA_LEARN_NOTIFICATION_TYPE_NEW = 0,    ///< New MAC address to learn.
    LA_LEARN_NOTIFICATION_TYPE_UPDATE = 1, ///< MAC moved.
    LA_LEARN_NOTIFICATION_TYPE_REFRESH = 3 ///< MAC aging info updated.
};

}; // struct la_packet_types

/// @brief PHB value source for injected packets.
///
enum la_inject_up_hdr_phb_src_e {
    PHB_FROM_INJECTED_PACKET = 0,  ///< PHB value from inject header of injected packet
    PHB_FROM_PACKET_PROCESSING = 1 ///< PHB value from packet processing pipeline.
};

/// @brief Return encoded destination ID of the give GID.
///
/// @param[in]  dtype               Destination type.
/// @param[in]  gid                 Destination GID.
///
/// @retval Encoded destination ID.
uint32_t
la_get_destination_id_from_gid(la_packet_types::la_packet_inject_down_dest_e dtype, uint32_t gid)
{
    uint32_t typemask = (dtype == la_packet_types::LA_PACKET_INJECT_DOWN_DEST_DSP)
                            ? la_packet_types::LA_PACKET_DESTINATION_GID_PREFIX_DSP
                            : la_packet_types::LA_PACKET_DESTINATION_GID_PREFIX_BVN;
    return (typemask | gid);
}

/// @}

}; // namespace silicon_one

#endif // __LA_PACKET_TYPES_H__
