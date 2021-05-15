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

#ifndef __LA_QOS_TYPES_H__
#define __LA_QOS_TYPES_H__

#include "api/types/la_common_types.h"

/// @file
/// @brief Leaba Quality-of-Serivce type definitions.
///
/// Defines QoS related types and enumerations used by the Leaba API.

namespace silicon_one
{

/// @addtogroup QOS_TYPES
/// @{

class la_ingress_qos_profile;
class la_egress_qos_profile;

/// @name Egress remarking canonization
/// @{

/// @brief Defines the number of GIDs and IDs used in QoS marking.
enum {
    LA_MAX_INGRESS_ENCAP_QOS_TAG = (1 << 7),      ///< Maximum value of Ingress encap QoS tag.
    LA_MAX_EGRESS_ENCAP_QOS_TAG = ((1 << 5) * 3), ///< Maximum value of Egress encap QoS tag.
    LA_MAX_QOS_GROUP = (1 << 7),                  ///< Maximum number of QoS groups.
    LA_MAX_QOS_COUNTER_OFFSET = (1 << 3) - 1,     ///< Maximum counter offset for ingress/egress profile.
    LA_MAX_DSCP = (1 << 6),                       ///< Maximum DSCP Value.
    LA_MAX_EXP = (1 << 3),                        ///< Maximum EXP value.
    LA_MAX_QOS_GROUP_OR_EXP_PCPDEI = (1 << 5),    ///< Maximum QOS group ID.
    LA_MAX_PCPDEI = (1 << 4),                     ///< Maximum PCPDEI value.
    LA_NUM_METER_MARKDOWN_PROFILES = 15,          ///< Number of meter markdown profiles, user configurable.
    LA_NUM_L2_INGRESS_TRAFFIC_CLASSES = 8,        ///< Number of ingress traffic classes supported on L2 AC.
    LA_NUM_L3_INGRESS_TRAFFIC_CLASSES = 32,       ///< Number of ingress traffic classes supported on L3 AC and SVI.
    LA_NUM_EGRESS_TRAFFIC_CLASSES = 8,            ///< Number of egress traffic classes.
};

/// @brief Packet ingress encapsulation QoS tag.
///
/// Defines the packet's ingress encapsulation QoS tag; this value is system-global and is used to derive the packet's egress
/// encapsulation fields QoS tag #silicon_one::la_egress_encap_qos_tag_t.
typedef la_uint_t la_ingress_encap_qos_tag_t;

/// @brief Packet egress encapsulation QoS tag.
///
/// Defines the packet's egress encapsulation QoS tag; this value is used to derive the packet's transmit encapsulation fields'
/// QoS values.
typedef la_uint_t la_egress_encap_qos_tag_t;
static const la_egress_encap_qos_tag_t LA_EGRESS_ENCAP_QOS_TAG_INVALID = LA_MAX_EGRESS_ENCAP_QOS_TAG;

/// @brief Packet QoS group.
///
/// Defines the packet's associated QoS group ingress encapsulation QoS level; this value is system-global and is used to derive
/// the packet's transmit QoS fields' values.
typedef la_uint_t la_qos_group_t;

/// @}

/// @brief Port egress QoS marking mode.
///
/// Defines the mode an egress port derives the transmit QoS fields' values.
enum class la_egress_qos_marking_source_e {
    QOS_GROUP = 0, ///< Use the packet's QoS group association #silicon_one::la_qos_group_t.
    QOS_TAG,       ///< Use the packet's egress QoS tag.
    LAST = QOS_TAG
};

/// @brief Forwarding header types.
enum class la_forwarding_header_e {
    ETHERNET = 0, ///< An Ethernet-forwarded packet will access Ethernet QoS mapping table.
    IP,           ///< An IP-forwarded packet will access IP QoS mapping table.
    MPLS,         ///< An MPLS-forwarded packet will access MPLS QoS mapping table.
    LAST = MPLS
};

/// @brief Traffic class.
typedef la_uint8_t la_traffic_class_t;

/// Global meter markdown profile table ID.
typedef la_uint8_t la_meter_markdown_gid_t;

/// @brief Packet's QoS color.
enum class la_qos_color_e {
    GREEN = 0,  ///< Packet conformity color green (conform).
    YELLOW = 1, ///< Packet conformity color yellow (exceed).
    RED = 2,    ///< Packet conformity color red (violate).
    NONE = 4,   ///< An indication to pass all color.
    LAST = NONE
};

/// @name QOS field types
/// @{

/// @brief VLAN tag PCP and DEI fields.
union la_vlan_pcpdei {
    explicit la_vlan_pcpdei() : flat(0)
    {
    }

    explicit la_vlan_pcpdei(la_uint8_t _flat) : flat(_flat)
    {
    }

    explicit la_vlan_pcpdei(la_uint8_t pcp, la_uint8_t dei)
    {
        fields.pcp = pcp;
        fields.dei = dei;
    }

    struct vlan_pcpdei_s {
        la_uint8_t dei : 1; ///< Drop Eligibiligy Indicator.
        la_uint8_t pcp : 3; ///< Priority Code Point.
    } fields;
    la_uint8_t flat : 4;
};

/// @brief IP Differentiated Services Code Point.
struct la_ip_dscp {
    la_uint8_t value : 6;
};

/// @brief IP Type Of Service.
union la_ip_tos {
    struct ip_tos_s {
        la_uint8_t ecn : 2;  ///< Explicit Congestion Notification
        la_uint8_t dscp : 6; ///< Differentiated Services Code Point
    } fields;

    la_uint8_t flat;
};

/// @brief MPLS Traffic Class.
struct la_mpls_tc {
    la_uint8_t value : 3;
};

/// @brief Forward Class ID.
struct la_fwd_class_id {
    la_uint8_t value : 3;
};

/// @}

/// @}

/// @addtogroup METER
/// @{

class la_meter_set;
class la_meter_profile;
class la_meter_action_profile;
class la_meter_markdown_profile;

/// @}
}

#endif // __LA_QOS_TYPES_H__
