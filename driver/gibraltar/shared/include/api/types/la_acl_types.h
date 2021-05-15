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

#ifndef __LA_ACL_TYPES_H__
#define __LA_ACL_TYPES_H__

#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_qos_types.h"
#include "api/types/la_system_types.h"
#include "nplapi/npl_enums.h"
#include <vector>

/// @file
/// @brief Leaba ACL type definitions.
///
/// @details Defines ACL-related types and enumerations.

namespace silicon_one
{

/// @addtogroup ACL
/// @{

class la_acl;
class la_acl_scaled;
class la_counter_or_meter_set;

/// @brief ACL packet format type.
enum class la_acl_packet_format_e { ETHERNET = 0, IPV4, IPV6, LAST };

/// @brief ACL key type.
enum class la_acl_key_type_e {
    ETHERNET = 0, ///< ACL key composed of packet's Ethernet an VLAN fields.
    IPV4,         ///< ACL key composed of packet's IPv4, L4 and user defined fields.
    IPV6,         ///< ACL key composed of packet's IPv6, L4 and user defined fields.
    SGACL,        ///< ACL key composed of common for IPv4 and IPv6, L4 and user defined fields.
    LAST
};

/// @brief ACL direction.
enum class la_acl_direction_e {
    INGRESS, ///< Key profile ingress acl.
    EGRESS,  ///< Key profile egress acl.
    LAST
};

/// @brief ACL mirror action source
enum class la_acl_mirror_src_e { DO_MIRROR_FROM_LP = 0, DO_MIRROR_FROM_CMD };

/// @brief ACL counter type
enum class la_acl_counter_type_e { DO_QOS_COUNTING = 0, DO_METERING, OVERRIDE_METERING_PTR, NONE };

/// @brief ACL field names.
enum class la_acl_field_type_e {
    DA = 0,                          ///< Destination MAC
    SA,                              ///< Source MAC
    VLAN_OUTER,                      ///< VLAN1 Tag Protocol Identifier
    VLAN_INNER,                      ///< VLAN2 Tag Protocol Identifier
    ETHER_TYPE,                      ///< Ether Type
    TOS,                             ///< IP TOS, composed of ECN and DSCP
    IPV4_LENGTH,                     ///< IPv4 total length
    IPV6_LENGTH,                     ///< IPv4 payload length
    IPV4_FLAGS,                      ///< Field in IPv4 header
    IPV4_FRAG_OFFSET,                ///< IPv4 fragment offset
    IPV6_FRAGMENT,                   ///< IPv6 fragment header
    TTL,                             ///< TTL in IPv4 header
    HOP_LIMIT,                       ///< TTL in IPv6 header
    PROTOCOL,                        ///< Protocol field in IPv4 header
    LAST_NEXT_HEADER,                ///< Protocol field in IPv6 header
    IPV4_SIP,                        ///< IPv4 Source IP
    IPV4_DIP,                        ///< IPv4 Destination IP
    IPV6_SIP,                        ///< IPv6 Source IP
    IPV6_DIP,                        ///< IPv6 Destination IP
    SRC_PCL_BINCODE,                 ///< Source Prefix Compression List Bincode
    DST_PCL_BINCODE,                 ///< Destination Prefix Compression List Bincode
    CLASS_ID,                        ///< Class Identifier
    SPORT,                           ///< Source port if Protocol is TCP/UDP
    DPORT,                           ///< Destination port if Protocol is TCP/UDP
    MSG_CODE,                        ///< If Protocol or Next Header is ICMP/IGMP
    MSG_TYPE,                        ///< If Protocol or Next Header is ICMP/IGMP
    TCP_FLAGS,                       ///< If Protocol or Next Header is TCP
    VRF_GID,                         ///< VRF global ID
    SGACL_BINCODE,                   ///< SGACL BINCODE (ACL Sharing Bit Mask)
    IP_VERSION,                      ///< IP Version field for SGACL
    QOS_GROUP,                       ///< QOS group ID
    UDF = 128,                       ///< User defined field
    WELL_KNOWN_FIELD_START = DA,     ///< First well known field
    WELL_KNOWN_FIELD_END = TCP_FLAGS ///< Last well known field
};

/// @brief UDF profile type.
enum class la_udf_profile_type_e {
    UDF_NONE = 0,
    UDF_160,
    UDF_320,
};

/// @brief ACL UDF description structure.
struct la_acl_udf_desc {
    la_uint8_t index;        ///< Index used to identify an UDF
    la_int_t protocol_layer; ///< Protocol layer inside the packet
    la_int_t header;         ///< Header inside the protocol_layer
    la_int_t offset;         ///< Offset inside the header, in bytes
    la_uint8_t width;        ///< Width of the field, in bytes
    bool is_relative;        ///< If true, fields will be taken from the protocol_layer relative to the current
                             ///< protocol-layer that is being used to forward the packet. If false, fields will
                             ///< be taken from the absolute protocol_layer from the start of the packet.
};

struct la_acl_field_def {
    la_acl_field_type_e type; ///< Field type
    la_acl_udf_desc udf_desc; ///< UDF description, contents are valid only if name is UDF
};

/// @brief ACL key definition.
typedef std::vector<la_acl_field_def> la_acl_key_def_vec_t;

// clang-format off

static const std::vector<la_acl_field_type_e> LA_ACL_KEY_ETHERNET_FIELDS = {
    la_acl_field_type_e::UDF,
    la_acl_field_type_e::DA,
    la_acl_field_type_e::SA,
    la_acl_field_type_e::VLAN_OUTER,
    la_acl_field_type_e::VLAN_INNER,
    la_acl_field_type_e::ETHER_TYPE,
    la_acl_field_type_e::CLASS_ID,
    la_acl_field_type_e::QOS_GROUP,
};

static const std::vector<la_acl_field_type_e> LA_ACL_KEY_IPV4_AND_ETH_FIELDS = {
    la_acl_field_type_e::UDF,
    la_acl_field_type_e::DA,
    la_acl_field_type_e::SA,
    la_acl_field_type_e::VLAN_OUTER,
    la_acl_field_type_e::VLAN_INNER,
    la_acl_field_type_e::ETHER_TYPE,
    la_acl_field_type_e::IPV4_SIP,
    la_acl_field_type_e::IPV4_DIP,
    la_acl_field_type_e::IPV4_LENGTH,
    la_acl_field_type_e::IPV4_FRAG_OFFSET,
    la_acl_field_type_e::TOS,
    la_acl_field_type_e::PROTOCOL,
    la_acl_field_type_e::IPV4_FLAGS,
    la_acl_field_type_e::TTL,
    la_acl_field_type_e::SPORT,
    la_acl_field_type_e::DPORT,
    la_acl_field_type_e::TCP_FLAGS,
    la_acl_field_type_e::MSG_CODE,
    la_acl_field_type_e::MSG_TYPE,
    la_acl_field_type_e::VRF_GID,
    la_acl_field_type_e::CLASS_ID,
    la_acl_field_type_e::SRC_PCL_BINCODE,
    la_acl_field_type_e::DST_PCL_BINCODE,
    la_acl_field_type_e::QOS_GROUP,
};

static const std::vector<la_acl_field_type_e> LA_ACL_KEY_IPV6_AND_ETH_FIELDS = {
    la_acl_field_type_e::UDF,
    la_acl_field_type_e::DA,
    la_acl_field_type_e::SA,
    la_acl_field_type_e::VLAN_OUTER,
    la_acl_field_type_e::VLAN_INNER,
    la_acl_field_type_e::ETHER_TYPE,
    la_acl_field_type_e::IPV6_SIP,
    la_acl_field_type_e::IPV6_DIP,
    la_acl_field_type_e::IPV6_LENGTH,
    la_acl_field_type_e::TOS,
    la_acl_field_type_e::LAST_NEXT_HEADER,
    la_acl_field_type_e::IPV6_FRAGMENT,
    la_acl_field_type_e::HOP_LIMIT,
    la_acl_field_type_e::SPORT,
    la_acl_field_type_e::DPORT,
    la_acl_field_type_e::TCP_FLAGS,
    la_acl_field_type_e::MSG_CODE,
    la_acl_field_type_e::MSG_TYPE,
    la_acl_field_type_e::VRF_GID,
    la_acl_field_type_e::CLASS_ID,
    la_acl_field_type_e::SRC_PCL_BINCODE,
    la_acl_field_type_e::DST_PCL_BINCODE,
    la_acl_field_type_e::QOS_GROUP,
};

/// @brief Default ethernet key.
static const la_acl_key_def_vec_t LA_ACL_KEY_ETHERNET = {
    {.type = la_acl_field_type_e::DA, {}},
    {.type = la_acl_field_type_e::SA, {}},
    {.type = la_acl_field_type_e::VLAN_OUTER, {}}
};

/// @brief Default IPv4 & L4 key.
static const la_acl_key_def_vec_t LA_ACL_KEY_IPV4 = {
    {.type = la_acl_field_type_e::IPV4_SIP, {}},
    {.type = la_acl_field_type_e::IPV4_DIP, {}},
    {.type = la_acl_field_type_e::TOS, {}},
    {.type = la_acl_field_type_e::PROTOCOL, {}},
    {.type = la_acl_field_type_e::IPV4_FLAGS, {}},
    {.type = la_acl_field_type_e::TTL, {}},
    {.type = la_acl_field_type_e::SPORT, {}},
    {.type = la_acl_field_type_e::DPORT, {}},
    {.type = la_acl_field_type_e::TCP_FLAGS, {}},
    {.type = la_acl_field_type_e::MSG_CODE, {}},
    {.type = la_acl_field_type_e::MSG_TYPE, {}}
};

/// @brief Default IPv6 & L4 key.
static const la_acl_key_def_vec_t LA_ACL_KEY_IPV6 = {
    {.type = la_acl_field_type_e::IPV6_SIP, {}},
    {.type = la_acl_field_type_e::IPV6_DIP, {}},
    {.type = la_acl_field_type_e::TOS, {}},
    {.type = la_acl_field_type_e::LAST_NEXT_HEADER, {}},
    {.type = la_acl_field_type_e::IPV6_FRAGMENT, {}},
    {.type = la_acl_field_type_e::SPORT, {}},
    {.type = la_acl_field_type_e::DPORT, {}},
    {.type = la_acl_field_type_e::TCP_FLAGS, {}},
    {.type = la_acl_field_type_e::MSG_CODE, {}},
    {.type = la_acl_field_type_e::MSG_TYPE, {}}
};

/// @brief Default ETHERNET key.
static const la_acl_key_def_vec_t LA_ACL_KEY_MAC = {
    {.type = la_acl_field_type_e::DA, {}},
    {.type = la_acl_field_type_e::SA, {}},
    {.type = la_acl_field_type_e::VLAN_OUTER, {}},
    {.type = la_acl_field_type_e::VLAN_INNER, {}},
    {.type = la_acl_field_type_e::ETHER_TYPE, {}}
};

/// @brief Default PBR IPv4 & L4 key.
static const la_acl_key_def_vec_t LA_ACL_KEY_PBR_IPV4 = {
    {.type = la_acl_field_type_e::IPV4_SIP, {}},
    {.type = la_acl_field_type_e::IPV4_DIP, {}},
    {.type = la_acl_field_type_e::TOS, {}},
    {.type = la_acl_field_type_e::PROTOCOL, {}},
    {.type = la_acl_field_type_e::IPV4_FLAGS, {}},
    {.type = la_acl_field_type_e::IPV4_LENGTH, {}},
    {.type = la_acl_field_type_e::SPORT, {}},
    {.type = la_acl_field_type_e::DPORT, {}},
    {.type = la_acl_field_type_e::VRF_GID, {}},
};

/// @brief Default PBR IPv6 & L4 key.
static const la_acl_key_def_vec_t LA_ACL_KEY_PBR_IPV6 = {
    {.type = la_acl_field_type_e::IPV6_SIP, {}},
    {.type = la_acl_field_type_e::IPV6_DIP, {}},
    {.type = la_acl_field_type_e::TOS, {}},
    {.type = la_acl_field_type_e::LAST_NEXT_HEADER, {}},
    {.type = la_acl_field_type_e::IPV6_FRAGMENT, {}},
    {.type = la_acl_field_type_e::SPORT, {}},
    {.type = la_acl_field_type_e::DPORT, {}},
    {.type = la_acl_field_type_e::TCP_FLAGS, {}},
    {.type = la_acl_field_type_e::MSG_CODE, {}},
    {.type = la_acl_field_type_e::MSG_TYPE, {}},
};

/// @brief Default Security Group ACL (SGACL) & L4 key.
static const la_acl_key_def_vec_t LA_ACL_KEY_SECURITY_GROUP = {
    {.type = la_acl_field_type_e::SPORT, {}},
    {.type = la_acl_field_type_e::DPORT, {}},
    {.type = la_acl_field_type_e::TOS, {}},
    {.type = la_acl_field_type_e::PROTOCOL, {}},
    {.type = la_acl_field_type_e::TTL, {}},
    {.type = la_acl_field_type_e::TCP_FLAGS, {}},
    {.type = la_acl_field_type_e::SGACL_BINCODE, {}},
    {.type = la_acl_field_type_e::IP_VERSION, {}},
    {.type = la_acl_field_type_e::IPV4_FLAGS, {}},
    {.type = la_acl_field_type_e::IPV6_FRAGMENT, {}},
    {.type = la_acl_field_type_e::MSG_CODE, {}},
    {.type = la_acl_field_type_e::MSG_TYPE, {}}
};

// clang-format on

/// @brief Types ACL commands.
enum class la_acl_cmd_type_e {
    NOP,             ///< NOP command.
    INGRESS_UNIFIED, ///< Ingress unified (security and qos) command.
    INGRESS_QOS,     ///< Ingress QoS command.
    EGRESS_UNIFIED,  ///< Egress unified (security and qos) command.
    EGRESS_QOS,      ///< Egress QoS command.
    PBR,             ///< PBR command.
    SGACL,           ///< Security Group ACL command.
};

/// @brief Scaled ACL field value - compressed value of a specific field (used in the scaled search).
typedef la_uint8_t la_acl_scale_field_val;

/// @brief ACL TCAM pool id.
typedef la_uint8_t la_acl_tcam_pool_id_t;

#pragma pack(push, 1)
/// @brief ACL TCP flags.
union la_acl_key_tcp_flags {
    struct tcp_flags_fields {
        la_uint8_t fin : 1;
        la_uint8_t syn : 1;
        la_uint8_t rst : 1;
        la_uint8_t psh : 1;
        la_uint8_t ack : 1;
        la_uint8_t urg : 1;
        la_uint8_t padding : 2; ///< Unmatched
    } fields;

    la_uint8_t flat;
};

/// @brief ACL IPv4 flags.
struct la_acl_key_ipv4_flags {
    la_uint8_t fragment : 1; ///< Not the first fragment of the IP datagram
    la_uint8_t df : 1;       ///< Don't Fragment flag
    la_uint8_t mf : 1;       ///< More Fragments flag
};

/// @brief ACL IPv4 flags and fragment offset.
union la_acl_key_ipv4_fragment {
    struct ipv4_fragment_fields {
        la_uint16_t frag_offset : 13; ///< Fragment offset in unit of 8B blocks
        la_uint8_t mf : 1;            ///< More Fragments flag
        la_uint8_t df : 1;            ///< Don't Fragment flag
        la_uint8_t evil : 1;          ///< Evil flag (RFC3514)
    } fields;

    la_uint16_t flat;
};

/// @brief ACL IPv6 fragment.
struct la_acl_key_ipv6_fragment_extension {
    la_uint8_t fragment : 1; ///< Not the first fragment of the IP datagram
    la_uint8_t mf : 1;       ///< More Fragments flag
};

/// @brief ACL UDF data.
union la_acl_udf_data {
    la_uint8_t b_data[16]; ///< UDF data in byte fragments
    la_uint16_t w_data[8]; ///< UDF data in word fragments
    la_uint32_t d_data[4]; ///< UDF data in double-word fragments
    la_uint64_t q_data[2]; ///< UDF data in quad-word fragments
    la_uint128_t s_data;
};

/// @brief ACL field data.
union la_acl_field_data {
    la_mac_addr_t da;                                 ///< MAC destination address
    la_mac_addr_t sa;                                 ///< MAC source address
    la_vlan_tag_t vlan1;                              ///< VLAN1 (outermost VLAN)
    la_vlan_tag_t vlan2;                              ///< VLAN2 (inner VLAN)
    la_uint16_t ethtype;                              ///< Ethernet type
    la_uint16_t ipv4_length;                          ///< IPv4 total length
    la_uint16_t ipv6_length;                          ///< IPv6 payload length
    la_ip_tos tos;                                    ///< IP TOS
    la_acl_key_ipv4_flags ipv4_flags;                 ///< IPv4 flags
    la_acl_key_ipv4_fragment ipv4_fragment;           ///< IPv4 flags and fragment offset
    la_acl_key_ipv6_fragment_extension ipv6_fragment; ///< IPv6 fragment extension
    la_uint8_t ttl;                                   ///< IPv4 TTL
    la_uint8_t protocol;                              ///< Protocol field in IPv4 header
    la_uint8_t last_next_header;                      ///< Next-header field in IPv6 header
    silicon_one::la_ipv4_addr_t ipv4_sip;             ///< Source IP address
    silicon_one::la_ipv4_addr_t ipv4_dip;             ///< Destination IP address
    silicon_one::la_ipv6_addr_t ipv6_sip;             ///< Source IP address
    silicon_one::la_ipv6_addr_t ipv6_dip;             ///< Destination IP address
    silicon_one::la_pcl_bincode_t src_pcl_bincode;    ///< Source prefix compression bincode
    silicon_one::la_pcl_bincode_t dst_pcl_bincode;    ///< Destination prefix compression bincode
    la_class_id_t class_id;                           ///< Class Identifier
    la_uint16_t sport;                                ///< Source port
    la_uint16_t dport;                                ///< Destination port
    la_acl_key_tcp_flags tcp_flags;                   ///< TCP flags
    la_uint8_t mcode;                                 ///< Message code
    la_uint8_t mtype;                                 ///< Message type
    la_uint32_t sgacl_bincode;                        ///< Security Group ACL Bincode
    la_ip_version_e ip_version;                       ///< SGACL IPv4/IPv6 version
    la_acl_udf_data udf;                              ///< User defined field
    la_vrf_gid_t vrf_gid;                             ///< VRF gid
    la_qos_group_t qos_group;                         ///< QOS group ID
};

#pragma pack(pop)

/// @brief ACL field value and mask structure.
struct la_acl_field {
    la_acl_field_type_e type; ///< Field type
    la_uint8_t udf_index;     ///< Valid only if type is UDF
    la_acl_field_data val;    ///< Field value
    la_acl_field_data mask;   ///< Field mask
};

/// @brief ACL key value and mask vector.
typedef std::vector<la_acl_field> la_acl_key;

/// @brief ACL scaled result key structure.
struct la_acl_key_scaled_result {
    la_acl_scale_field_val compress_sip; ///< Compressed source IP address.
    la_acl_scale_field_val compress_dip; ///< Compressed destination IP address.
};
/// @brief ACL key fields union.
struct la_acl_key_fields {
    la_acl_key_scaled_result scaled_res; ///< Scaled ACL result fields
};

/// @brief ACL key - value and mask
struct la_acl_key_vm {
    la_acl_key_fields val;  ///< Key value
    la_acl_key_fields mask; ///< Key mask - which fields of the value are valid
};

/// @brief ACL action type.
enum class la_acl_action_type_e {
    // QoS actions
    TRAFFIC_CLASS,
    COLOR,
    QOS_OR_METER_COUNTER_OFFSET,
    ENCAP_EXP,
    REMARK_FWD,
    REMARK_GROUP,
    // Security actions
    DROP,
    PUNT,
    DO_MIRROR,  // Mirror Command from LP
    MIRROR_CMD, // Mirror Command from ACE
    COUNTER_TYPE,
    COUNTER,
    L2_DESTINATION,
    L3_DESTINATION,
    METER
};

/// @brief ACL action definition.
struct la_acl_action_def {
    la_acl_action_type_e type;
};

/// @brief ACL action definitions vector.
typedef std::vector<la_acl_action_def> la_acl_command_def_vec_t;

/// @brief Default command.
static const la_acl_command_def_vec_t LA_ACL_COMMAND = {{.type = la_acl_action_type_e::TRAFFIC_CLASS},
                                                        {.type = la_acl_action_type_e::COLOR},
                                                        {.type = la_acl_action_type_e::QOS_OR_METER_COUNTER_OFFSET},
                                                        {.type = la_acl_action_type_e::ENCAP_EXP},
                                                        {.type = la_acl_action_type_e::REMARK_FWD},
                                                        {.type = la_acl_action_type_e::REMARK_GROUP},
                                                        {.type = la_acl_action_type_e::DROP},
                                                        {.type = la_acl_action_type_e::PUNT},
                                                        {.type = la_acl_action_type_e::DO_MIRROR},
                                                        {.type = la_acl_action_type_e::MIRROR_CMD},
                                                        {.type = la_acl_action_type_e::COUNTER_TYPE},
                                                        {.type = la_acl_action_type_e::COUNTER},
                                                        {.type = la_acl_action_type_e::L2_DESTINATION},
                                                        {.type = la_acl_action_type_e::L3_DESTINATION},
                                                        {.type = la_acl_action_type_e::METER}};

static const la_acl_command_def_vec_t LA_SGACL_COMMAND = {{.type = la_acl_action_type_e::DROP}};

/// @brief ACL Action payload
union la_acl_action_payload {
    // QoS actions
    la_traffic_class_t traffic_class;
    la_qos_color_e color;
    la_uint32_t qos_offset;
    la_uint32_t meter_offset;
    la_acl_counter_type_e counter_type;
    la_uint32_t encap_exp;
    la_uint32_t remark_fwd;
    la_uint32_t remark_group;

    // Sec actions
    bool drop;
    bool punt;
    la_counter_set* counter;                 ///< If set, counter is incremented.
    la_acl_mirror_src_e do_mirror;           ///< Set port conditional mirror type
    la_mirror_gid_t mirror_cmd;              ///< Set port conditional mirror command
    silicon_one::la_l2_destination* l2_dest; ///< L2 destination.
    silicon_one::la_l3_destination* l3_dest; ///< L3 destination.
    la_meter_set* meter;                     ///< Meter.
};

/// @brief ACL command.
struct la_acl_command_action {
    la_acl_action_type_e type;  ///< Action type.
    la_acl_action_payload data; ///< Action data.
};

/// @brief  The actual command passed to an ACL
typedef std::vector<la_acl_command_action> la_acl_command_actions;

// Scaled ACL

/// @brief Scaled ACL - scale field type.
enum class la_acl_scale_field_type_e {
    UNDEF = 0, ///< Undefined scale field.
    IPV4,      ///< IPv4 scale field.
    IPV6,      ///< IPv6 scale field.
    LAST,
};

/// @brief Scaled ACL - scale field key fields union.
union la_acl_scale_key_fields {
    silicon_one::la_ipv4_addr_t ipv4;
    silicon_one::la_ipv6_addr_t ipv6;
};

/// @brief Scaled ACL - scale field key.
struct la_acl_scale_field_key {
    la_acl_scale_field_type_e type; ///< Key type.
    la_acl_scale_key_fields val;    ///< Key value.
    la_acl_scale_key_fields mask;   ///< Key mask - which bits of the value are valid.
};

/// @brief ACL entry information.
struct acl_entry_desc {
    la_acl_key key_val; ///< Entry key.
    la_acl_command_actions cmd_actions;
};

/// @brief ACL packet processing stages
enum class la_acl_packet_processing_stage_e {
    // Ingress packet processing stages
    PRE_FORWARDING,
    POST_FORWARDING,
    RX_DONE,

    // Egress packet processing stages
    EGRESS,
    LAST,
};

typedef std::vector<silicon_one::la_acl*> la_acl_vec_t;

} // namespace silicon_one

/// @}

#endif // __LA_ACL_TYPES_H__
