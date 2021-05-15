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

#ifndef __LA_ETHERNET_TYPES_H__
#define __LA_ETHERNET_TYPES_H__

#include "api/types/la_common_types.h"

#include <vector>

/// @file
/// @brief Leaba Ethernet definitions.
///
/// Defines Ethernet related types and enumerations used by the Leaba API.

namespace silicon_one
{

class la_meter_profile;
class la_meter_action_profile;
class la_ac_profile;
class la_ethernet_port;
class la_filter_group;
class la_l2_destination;
class la_l2_port;
class la_l2_protection_group;
class la_l2_service_port;
class la_switch;
class la_l2_multicast_group;
class la_system_port;

/// L2 destinations vector
typedef std::vector<const la_l2_destination*> la_l2_destination_vec_t;

/// System ports vector
typedef std::vector<la_system_port*> system_port_vec_t;
}

/// @addtogroup L2TYPES
/// @{

/// LA_VLAN_MAX_ID
enum { LA_VLAN_MAX_ID = 4095 };

/// LA_VXVLAN_MAX_VNI
enum { LA_VXVLAN_MAX_VNI = (1 << 24) };

/// Tag Protocol Identifier.
typedef la_uint16_t la_tpid_t;

using la_tpid_vec = std::vector<la_tpid_t>;

/// VLAN ID.
typedef la_uint16_t la_vlan_id_t;

/// L2 destination Global ID.
typedef la_uint_t la_l2_destination_gid_t;
static const la_l2_destination_gid_t LA_L2_DESTINATION_GID_INVALID = (la_l2_destination_gid_t)(-1);

/// L2 LAG group Global ID.
typedef la_uint_t la_l2_lag_group_gid_t;

/// Multicast group Global ID.
typedef la_uint_t la_multicast_group_gid_t;

/// VXLAN Network Identifier.
typedef la_uint_t la_vni_t;

/// PWE Global ID.
typedef la_uint_t la_pwe_gid_t;

/// Key value to select extended port above System Port or System Port Aggregate.
typedef la_uint_t la_channel_key_t;

/// Ethernet type.
typedef la_uint16_t la_ethertype_t;

using la_ethertype_vec = std::vector<la_ethertype_t>;

/// MTU type.
typedef la_uint16_t la_mtu_t;

/// MAC aging time.
typedef la_uint64_t la_mac_aging_time_t;

/// L2PORT_VLAN_SET
typedef la_uint_t la_vlan_set_t[LA_BITS_TO_BYTES(LA_VLAN_MAX_ID)];

/// vid vector
typedef std::vector<la_vlan_id_t> la_vid_vec_t;

/// @brief Port security mode.
///
/// Port security mode for L2 ethernet ports.
enum class la_port_security_mode_e {
    NONE = 0,             ///< Port performs no security checks for ingress/egress packets.
    LOOSE_SA,             ///< Port verifies packet's Source Address is authorized. Unauthorized packets are dropped.
    LOOSE_ANTI_SPOOFING,  ///< Port verifies packet's (Source Address, Source IP) are authorized. Unauthorized
                          ///< packets are dropped.
    STRICT_SA,            ///< Port verifies packet's Source Address is authorized for the current port. Unauthorized
                          ///< packets are dropped.
    STRICT_ANTI_SPOOFING, ///< Port verifies packet's (Source Address, Source IP) are authorized for the
                          ///< current port. Unauthorized packets are dropped.
};

/// Struct for single VLAN Tag control information header
struct la_vlan_tag_tci_fields_t {
    la_uint16_t pcp : 3;  ///< Priority Code Point
    la_uint16_t dei : 1;  ///< Drop Eligible Indicator
    la_uint16_t vid : 12; ///< VLAN IDentifier
};

union la_vlan_tag_tci_t {
    la_vlan_tag_tci_fields_t fields;
    la_uint16_t raw;
};

/// Struct for single VLAN header
struct la_vlan_tag_t {
    la_uint16_t tpid;      ///< Tag Protocol Identifier
    la_vlan_tag_tci_t tci; ///< Tag Control Information
};

/// Untagged VLAN meta-tag.
/// Using this tag means 'untagged'.
constexpr la_vlan_tag_t LA_VLAN_TAG_UNTAGGED = {.tpid = 0, .tci = {.raw = 0}};

/// VLAN format of packet.
/// tpid1 denotes the outermost VLAN header, tpid2 the inner VLAN header.
struct la_packet_vlan_format_t {
    bool outer_vlan_is_priority;
    la_tpid_t tpid1;
    la_tpid_t tpid2;
};

/// ERSPAN Session ID.
typedef la_uint16_t la_erspan_session_id_t;

/// @}

/// @addtogroup L2PORT
/// @{
/// L2 port Global ID.
typedef la_uint_t la_l2_port_gid_t;
static const la_l2_port_gid_t LA_L2_PORT_GID_INVALID = (la_l2_port_gid_t)(-1);

/// @}

/// @addtogroup PWE_ID
/// @{
/// PWE Global ID.
static const la_pwe_gid_t LA_PWE_GID_INVALID = (la_pwe_gid_t)(-1);

/// @}

/// @addtogroup PACKET
/// @{
/// L2 Punt destination Global ID.
typedef la_uint_t la_l2_punt_destination_gid_t;
static const la_l2_punt_destination_gid_t LA_L2_PUNT_DESTINATION_GID_INVALID = (la_l2_punt_destination_gid_t)(-1);

/// @}

/// @addtogroup L2SWITCH
/// @{

/// Switch Global ID.
typedef la_uint_t la_switch_gid_t;

enum class la_lp_mac_learning_mode_e {
    NONE = 0,   ///< Service port does not learn MAC addresses.
    STANDALONE, ///< Service port learns MAC addresses automatically.
    CPU,        ///< Service port directs MAC learning information to CPU, but does not learn given MAC automatically.
};

/// @}

/// @addtogroup L2SWITCH_STP
/// @{
enum class la_port_stp_state_e {
    BLOCKING = 0, ///< Port in blocking mode. BPDU data is received.
    LISTENING,    ///< Port in listening mode. BPDU data is received and processed.
    LEARNING,     ///< Port in learning mode. Source addresses are learned from incoming packets, but packets are not forwarded.
    FORWARDING    ///< Port receives and sends packets, and performs learning operations.
};

/// @}

/// @addtogroup L2SWITCH_VLAN_EDT
/// @{

/// @brief VLAN edit command.
///
/// The first #la_vlan_edit_command::num_tags_to_pop tags are popped,
/// then #la_vlan_edit_command::num_tags_to_push are pushed. If no tags are popped nor pushed, then pcpdei_rewrite_only
/// controls whether to rewrite the outer tag's PCP, DEI fields.
///
/// @see #silicon_one::la_l2_service_port::set_egress_vlan_edit_command,
/// #silicon_one::la_l2_service_port::set_ingress_vlan_edit_command
struct la_vlan_edit_command {
    constexpr la_vlan_edit_command()
        : num_tags_to_pop(0),
          num_tags_to_push(0),
          tag0(LA_VLAN_TAG_UNTAGGED),
          tag1(LA_VLAN_TAG_UNTAGGED),
          pcpdei_rewrite_only(false)
    {
    }

    explicit la_vlan_edit_command(la_uint_t _num_tags_to_pop)
        : num_tags_to_pop(_num_tags_to_pop),
          num_tags_to_push(0),
          tag0(LA_VLAN_TAG_UNTAGGED),
          tag1(LA_VLAN_TAG_UNTAGGED),
          pcpdei_rewrite_only(false)
    {
    }

    la_vlan_edit_command(la_uint_t _num_tags_to_pop, la_vlan_tag_t _tag0)
        : num_tags_to_pop(_num_tags_to_pop),
          num_tags_to_push(1),
          tag0(_tag0),
          tag1(LA_VLAN_TAG_UNTAGGED),
          pcpdei_rewrite_only(false)
    {
    }

    la_vlan_edit_command(la_uint_t _num_tags_to_pop, la_vlan_tag_t _tag0, la_vlan_tag_t _tag1)
        : num_tags_to_pop(_num_tags_to_pop), num_tags_to_push(2), tag0(_tag0), tag1(_tag1), pcpdei_rewrite_only(false)
    {
    }

    enum {
        MAX_POP_OPERATIONS = 2, ///< Maximum number of supported pop operations per edit command
        MAX_PUSH_OPERATIONS = 2 ///< Maximum number of supported push operations per edit commands
    };

    /// Number of tags to pop.
    la_uint_t num_tags_to_pop;

    /// Number of tags to push.
    la_uint_t num_tags_to_push;

    /// Outer tag to push.
    la_vlan_tag_t tag0;

    /// Inner tag to push.
    la_vlan_tag_t tag1;

    /// Whether to rewrite the PCP, DEI fields if no headers are popped or pushed.
    bool pcpdei_rewrite_only;
};

/// @brief NOP VLAN edit commmand.
constexpr la_vlan_edit_command LA_VLAN_EDIT_COMMAND_NOP = la_vlan_edit_command();

/// @}

/// @addtogroup TUNNEL_VXLAN
/// @{
struct la_vtep_s;

/// @brief      A VXLAN Virtual Tunnel Endpoint.
///
/// @details    A VTEP (Virtual Tunnel Endpoint) defines the tunnel termination IP, UDP port,
///             and Switch <-> VNI (VXLAN Network Identifier) mapping.
///             #la_vxlan_tunnel_t-s are created using the VTEP and associated with it for learning purposes.
typedef struct la_vtep_s* la_vtep_t;

/// An invalid VXLAN Virtual Tunnel Endpoint.
static const la_vtep_t LA_VXLAN_VTEP_INVALID = NULL;

struct la_vxlan_tunnel_s;

/// @brief      A VXLAN Tunnel.
//
/// @details    VXLAN tunnels are connected locally to a #la_vtep_t, and created with a destination IP.
///             Their Switch <-> VNI mapping is inherited from the VTEP associated with the tunnel.
///             The tunnel serves as the learning destination for packets received from its destination IP.
///
/// @note       If no tunnel is associated with an incoming packet, the #silicon_one::la_switch will not learn its Source Address.
///             Traffic going to this destination will be flooded.
typedef struct la_vxlan_tunnel_s* la_vxlan_tunnel_t;

/// Invalid VXLAN tunnel.
static const la_vxlan_tunnel_t LA_VXLAN_TUNNEL_INVALID = NULL;

/// @}

/// @addtogroup L2SWITCH_MAC_ITER
/// @{
struct la_mac_table_iter_s;
/// @brief      A MAC table iterator.
///
/// @details    Iterates over select entries in MAC table and returns MAC address, Switch and Destination.
typedef struct la_mac_table_iter_s* la_mac_table_iter_t;

/// Invalid MAC table iterator.
static const la_mac_table_iter_t LA_MAC_TABLE_ITER_INVALID = NULL;

/// @}

/// @addtogroup L2DEST_LAG
/// @{
struct la_l2_lag_group_s;

/// @brief      L2 Link Aggregation Group.
///
/// @details    An LAG group enables aggregating multiple L2 ports as one, enhancing load-balancing and redundancy.
///             Different packets can be transmitted through different group members, depending on the group's hash settings.
typedef struct la_l2_lag_group_s* la_l2_lag_group_t;

/// Invalid L2 LAG group.
static const la_l2_lag_group_t LA_L2_LAG_GROUP_INVALID = NULL;

/// @}

/// @addtogroup L2TYPES
/// @{

/// Type constants for general API types.
static const la_tpid_t LA_TPID_INVALID = 0; ///< Marker for invalid TPID entry
static const la_tpid_t LA_TPID_ANY = 1;     ///< Marker for don't-care TPID entry

constexpr la_packet_vlan_format_t LA_PACKET_VLAN_FORMAT_UNTAGGED
    = {.outer_vlan_is_priority = false, .tpid1 = LA_TPID_INVALID, .tpid2 = LA_TPID_INVALID};
constexpr la_packet_vlan_format_t LA_PACKET_VLAN_FORMAT_802Q
    = {.outer_vlan_is_priority = false, .tpid1 = 0x8100, .tpid2 = LA_TPID_INVALID};
constexpr la_packet_vlan_format_t LA_PACKET_VLAN_FORMAT_802QinQ
    = {.outer_vlan_is_priority = false, .tpid1 = 0x88a8, .tpid2 = 0x8100};

/// Ethernet Address
union la_mac_addr_t {
    la_uint16_t word[3];
    la_uint8_t bytes[6];
    la_uint64_t flat : 48;
};

using la_mac_addr_vec = std::vector<la_mac_addr_t>;

struct la_mac_entry_t {
    la_mac_addr_t addr;
    la_switch_gid_t relay_gid;
    la_l2_destination_gid_t slp_gid;
};

using la_mac_entry_vec = std::vector<la_mac_entry_t>;

struct la_mac_age_info_t {
    la_mac_aging_time_t age_value;     // elapsed time
    la_mac_aging_time_t age_remaining; // time before getting aged
    bool owner;
};

/// Invalid VLAN ID.
static const la_vlan_id_t LA_VLAN_ID_INVALID = 0;

/// VLAN ID value when it is detached from L3 AC PORT
static const la_vlan_id_t LA_VLAN_ID_DETACHED = (la_vlan_id_t)-1;

/// MAC aging time constant interpreted as 'never expire'.
static const la_mac_aging_time_t LA_MAC_AGING_TIME_NEVER = 0xffffffffffffffffULL;
/// MAC aging timer ticks every 100ms
#define LA_MAC_AGING_TIMER_TICKS_PER_SECOND 10

/// @brief CFM Mep direction
///
enum class la_mep_direction_e {
    DOWN = 0, ///< Down MEP
    UP        ///< Up MEP
};

/// Max CFM Mep level
static const uint8_t LA_MAX_MEP_LVL = 7;

/// @}

#endif // __LA_ETHERNET_TYPES_H__
