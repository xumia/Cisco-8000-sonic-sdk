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

#ifndef __LA_LPTS_TYPES_H__
#define __LA_LPTS_TYPES_H__

#include "api/types/la_acl_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_counter_or_meter_set.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"

/// @file
/// @brief Leaba LPTS type definitions.
///
/// @details Defines LPTS-related types and enumerations.

namespace silicon_one
{

/// @addtogroup LPTS
/// @{

class la_lpts;

#pragma pack(push, 1)
/// @brief LPTS key type.
enum class lpts_type_e {
    LPTS_TYPE_IPV4, ///< LPTS key composed of packet's IPv4 and L4 fields
    LPTS_TYPE_IPV6, ///< LPTS key composed of packet's IPv6 and L4 fields
    LAST,
};

/// @brief LPTS L4 port key struct.
struct la_lpts_key_l4_ports {
    la_uint16_t sport; ///< Source port
    la_uint16_t dport; ///< Destination port
};

/// @brief LPTS ACL IPv4 flags and fragment offset.
typedef la_acl_key_ipv4_fragment la_ipv4_fragment_info;

/// @brief LPTS IPv4 key structure.
struct la_lpts_key_ipv4 {
    la_lpts_app_gid_t app_id;            ///< LPTS Application ID
    silicon_one::la_ipv4_addr_t sip;     ///< Source IP address
    la_uint_t src_og_compression_code;   ///< Source PCL OG compression code
    la_uint_t dst_og_compression_code;   ///< Destination OG compression code
    la_l4_protocol_e protocol;           ///< L4 protocol
    la_lpts_key_l4_ports ports;          ///< L4 ports
    la_vrf_gid_t relay_id;               ///< VRF ID
    la_uint8_t fragment : 1;             ///< fragment of the IP datagram
    la_ipv4_fragment_info fragment_info; ///< IPv4 flags and fragment offset
    la_uint16_t ip_length;               ///< IP packet-length
    bool established;                    ///< Boolean flag for an established flow
    bool ttl_255;                        ///< Boolean flag to configure ttl == 255 check
    bool is_mc;                          ///< Boolean flag to indicate if the destination is multicast
};

/// @brief LPTS IPv6 key structure.
struct la_lpts_key_ipv6 {
    la_lpts_app_gid_t app_id;          ///< LPTS Application ID
    silicon_one::la_ipv6_addr_t sip;   ///< Source IP address
    la_uint_t src_og_compression_code; ///< Source PCL OG compression code
    la_uint_t dst_og_compression_code; ///< Destination OG compression code
    la_l4_protocol_e protocol;         ///< L4 protocol
    la_lpts_key_l4_ports ports;        ///< L4 ports
    la_vrf_gid_t relay_id;             ///< VRF ID
    la_uint16_t ip_length;             ///< IP packet-length
    bool established;                  ///< Boolean flag for an established flow
    bool ttl_255;                      ///< Boolean flag to configure ttl == 255 check
    bool is_mc;                        ///< Boolean flag to indicate if the destination is multicast
};

/// @brief LPTS key fields union.
union la_lpts_key_fields {
    la_lpts_key_ipv4 ipv4; ///< IPv4 fields
    la_lpts_key_ipv6 ipv6; ///< IPv6 fields
};

/// @brief LPTS key - value and mask
struct la_lpts_key {
    lpts_type_e type;        ///< key type
    la_lpts_key_fields val;  ///< Key value
    la_lpts_key_fields mask; ///< Key mask - which fields of the value are valid
};

/// @brief LPTS result.
struct la_lpts_result {
    la_uint8_t punt_code;                                         ///< LPTS punt code for this LPTS entry.
    la_uint8_t flow_type;                                         ///< LPTS flow type for this LPTS entry.
    la_traffic_class_t tc;                                        ///< Traffic class for this LPTS entry.
    const silicon_one::la_counter_or_meter_set* counter_or_meter; ///< Per-Entry Counter or Meter for counting on this LPTS entry.
    const silicon_one::la_meter_set* meter;                       ///< Meter for this LPTS entry.
    const silicon_one::la_l2_punt_destination* dest;              ///< L2 punt destination.
};

/// @brief LPTS application properties fields.
struct la_lpts_app_properties_key_fields {
    la_ip_version_e ip_version; ///< IP version
    la_l4_protocol_e protocol;  ///< L4 protocol
    la_lpts_key_l4_ports ports; ///< L4 ports
    bool fragment;              ///< fragment of the IP datagram
};

/// @brief LPTS application properties.
struct la_lpts_app_properties {
    la_lpts_app_properties_key_fields val;  ///< Key value
    la_lpts_app_properties_key_fields mask; ///< Key mask - which fields of the value are valid
};

/// @brief LPTS entry information.
struct lpts_entry_desc {
    la_lpts_key key_val;   ///< Entry key.
    la_lpts_result result; ///< Entry value.
};

} // namespace silicon_one

#pragma pack(pop)

/// @}

#endif // __LA_LPTS_TYPES_H__
