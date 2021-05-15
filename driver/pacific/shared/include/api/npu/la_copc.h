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

#ifndef __LA_COPC_H__
#define __LA_COPC_H__

#include "api/types/la_common_types.h"
#include "api/types/la_event_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief silicon_one COPC API-s.
///
/// Defines API-s for configuring COPC (Control Plane Classifier).

/// @addtogroup COPC
/// @{

namespace silicon_one
{

/// @brief Local Packet Transport System API-s.
///
/// @details COPC is an ordered list of Entries.\n
///          Each entry defines a match rule, a destination to send the packet to if that rule is matched
///          and a metering action associated with the matched flow.

class la_control_plane_classifier : public la_object
{
public:
    /// @brief COPC table types
    enum class type_e {
        IPV4, ///< COPC key composed of packet's IPv4 and L4 fields
        IPV6, ///< COPC key composed of packet's IPv6 and L4 fields
        MAC,  ///< COPC key composed of packet's MAC fields
        LAST,
    };

    /// @brief logical port types
    enum class logical_port_type_e {
        L2, ///< L2 logical port
        L3, ///< L3 logical port
    };

    /// @brief switch profile id type.
    typedef la_uint8_t switch_profile_id_t;

    /// @brief ethernet profile id type.
    typedef la_uint8_t ethernet_profile_id_t;

    // @brief L2 service port profile id type.
    typedef la_uint8_t l2_service_port_profile_id_t;

    /// @brief COPC ipv4 field names.
    enum class ipv4_field_type_e {
        SWITCH_PROFILE_ID,          ///< Switch profile id
        ETHERNET_PROFILE_ID,        ///< Ethernet port profile id
        L2_SERVICE_PORT_PROFILE_ID, ///< L2 service port profile id
        LP_TYPE,                    ///< logical port Type
        IPV4_DIP,                   ///< IPv4 Destination IP
        TTL,                        ///< TTL in IPv4 header
        PROTOCOL,                   ///< Protocol field in IPv4 header
        SPORT,                      ///< Source port if Protocol is TCP/UDP
        DPORT,                      ///< Destination port if Protocol is TCP/UDP
        MY_MAC,                     ///< My MAC
        IS_SVI,                     ///< Is SVI
        HAS_VLAN_TAG,               ///< Has vlan tag
    };

    /// @brief COPC ipv4 field data.
    union ipv4_field_data {
        la_control_plane_classifier::switch_profile_id_t switch_profile_id;                   ///< Switch profile id
        la_control_plane_classifier::ethernet_profile_id_t ethernet_profile_id;               ///< Ethernet port profile id
        la_control_plane_classifier::l2_service_port_profile_id_t l2_service_port_profile_id; ///< L2 service port profile id
        la_control_plane_classifier::logical_port_type_e lp_type;                             ///< Logical port type
        silicon_one::la_ipv4_addr_t ipv4_dip;                                                 ///< Destination IPv4 address
        la_uint8_t ttl;                                                                       ///< IPv4 TTL
        la_uint8_t protocol;                                                                  ///< Protocol field in IPv4 header
        la_uint16_t sport;                                                                    ///< Source port
        la_uint16_t dport;                                                                    ///< Destination port
        bool my_mac;                                                                          ///< My mac
        bool is_svi;                                                                          ///< Is SVI
        bool has_vlan_tag;                                                                    ///< Has vlan tag
    };

    /// @brief COPC ipv6 field names.
    enum class ipv6_field_type_e {
        SWITCH_PROFILE_ID,          ///< Switch profile id
        ETHERNET_PROFILE_ID,        ///< Ethernet port profile id
        L2_SERVICE_PORT_PROFILE_ID, ///< L2 service port profile id
        LP_TYPE,                    ///< logical port Type
        IPV6_DIP,                   ///< IPv6 Destination IP
        HOP_LIMIT,                  ///< TTL in IPv6 header
        NEXT_HEADER,                ///< Protocol field in IPv6 header
        SPORT,                      ///< Source port if Protocol is TCP/UDP
        DPORT,                      ///< Destination port if Protocol is TCP/UDP
        MY_MAC,                     ///< My MAC
        IS_SVI,                     ///< Is SVI
        HAS_VLAN_TAG,               ///< Has vlan tag
    };

    /// @brief COPC ipv6 field data.
    union ipv6_field_data {
        la_control_plane_classifier::switch_profile_id_t switch_profile_id;                   ///< Switch profile id
        la_control_plane_classifier::ethernet_profile_id_t ethernet_profile_id;               ///< Ethernet port profile id
        la_control_plane_classifier::l2_service_port_profile_id_t l2_service_port_profile_id; ///< L2 service port profile id
        la_control_plane_classifier::logical_port_type_e lp_type;                             ///< Logical port tpye
        silicon_one::la_ipv6_addr_t ipv6_dip;                                                 ///< Destination IPv6 address
        la_uint8_t hop_limit;                                                                 ///< IPv6 hop limit
        la_uint8_t next_header;                                                               ///< Next-header field in v6 header
        la_uint16_t sport;                                                                    ///< Source port
        la_uint16_t dport;                                                                    ///< Destination port
        bool my_mac;                                                                          ///< My mac
        bool is_svi;                                                                          ///< Is SVI
        bool has_vlan_tag;                                                                    ///< Has vlan tag
    };

    /// @brief COPC mac field names.
    enum class mac_field_type_e {
        SWITCH_PROFILE_ID,          ///< Switch profile id
        ETHERNET_PROFILE_ID,        ///< Ethernet port profile id
        L2_SERVICE_PORT_PROFILE_ID, ///< L2 service port profile id
        DA,                         ///< Destination MAC
        ETHERTYPE,                  ///< Ether Type
        LP_TYPE,                    ///< logical port type
        MY_MAC,                     ///< My MAC
        IS_SVI,                     ///< Is SVI
        HAS_VLAN_TAG,               ///< Has vlan tag
    };

    /// @brief COPC mac field data.
    union mac_field_data {
        la_control_plane_classifier::switch_profile_id_t switch_profile_id;                   ///< Switch profile id
        la_control_plane_classifier::ethernet_profile_id_t ethernet_profile_id;               ///< Ethernet port profile id
        la_control_plane_classifier::l2_service_port_profile_id_t l2_service_port_profile_id; ///< L2 service port profile id
        la_mac_addr_t da;                                                                     ///< MAC destination address
        la_uint16_t ethertype;                                                                ///< Ether type
        la_control_plane_classifier::logical_port_type_e lp_type;                             ///< Logical port type
        bool my_mac;                                                                          ///< My mac
        bool is_svi;                                                                          ///< Is SVI
        bool has_vlan_tag;                                                                    ///< Has vlan tag
    };

    /// @brief COPC field type
    union field_type {
        la_control_plane_classifier::ipv4_field_type_e ipv4; ///< Ipv4 field type
        la_control_plane_classifier::ipv6_field_type_e ipv6; ///< Ipv6 field type
        la_control_plane_classifier::mac_field_type_e mac;   ///< Mac field type
    };

    /// @brief COPC field data
    union field_data {
        la_control_plane_classifier::ipv4_field_data ipv4; ///< Ipv4 field data
        la_control_plane_classifier::ipv6_field_data ipv6; ///< Ipv6 field data
        la_control_plane_classifier::mac_field_data mac;   ///< Mac field data
    };

    /// @brief COPC field
    struct field {
        la_control_plane_classifier::field_type type; ///< Field type
        la_control_plane_classifier::field_data val;  ///< Field value
        la_control_plane_classifier::field_data mask; ///< Field mask
    };

    /// @brief COPC key value and mask vector.
    typedef std::vector<la_control_plane_classifier::field> key;

    /// @brief COPC result.
    struct result {
        la_event_e event; ///< COPC result event to raise.
    };

    /// @brief COPC entry information.
    struct entry_desc {
        la_control_plane_classifier::key key_val;   ///< Entry key.
        la_control_plane_classifier::result result; ///< Entry value.
    };

    /// @brief COPC Protocol table data information.
    struct protocol_table_data {
        la_ip_version_e l3_protocol;  ///< L3 Protocol.
        la_l4_protocol_e l4_protocol; ///< L4 Protocol.
        la_uint16_t dst_port;         ///< Destination L4 Port value.
    };

    using protocol_table_data_vec = std::vector<la_control_plane_classifier::protocol_table_data>;

    /// @brief Get COPC type.
    ///
    /// @param[out] out_type            Type of this COPC instance.
    ///
    /// @retval     LA_STATUS_SUCCESS   Type retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_copc_type(la_control_plane_classifier::type_e& out_type) const = 0;

    /// @brief Get a count of the number of entries in the COPC instance.
    ///
    /// @param[out] out_count           Entry count.
    ///
    /// @retval     LA_STATUS_SUCCESS   Key retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_count(size_t& out_count) const = 0;

    /// @brief Create and add an COPC entry to the end of the set of COPC entries.
    ///
    /// @param[in]  key                 COPC key value to set.
    /// @param[in]  result              COPC result to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   COPC entry modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or result is invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for appending an COPC entry.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status append(const la_control_plane_classifier::key& key, const la_control_plane_classifier::result& result) = 0;

    /// @brief Add an COPC entry at a specified position and also move following
    ////       entries down to create a hole for the new entry.
    ///
    /// @param[in]  position    Index in the COPC table. If it's greater than COPC size, then it will be appended.
    /// @param[in]  key         COPC key value to set.
    /// @param[in]  result      COPC result to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   COPC entry added successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or result is invalid.
    /// @retval     LA_STATUS_ERESOURCE No resources for pushing an COPC entry.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status push(size_t position,
                           const la_control_plane_classifier::key& key,
                           const la_control_plane_classifier::result& result)
        = 0;

    /// @brief Update an COPC entry at a specified position.
    ///
    /// @param[in]  position    Index in the COPC table. If it's greater than COPC size, then it will be appended.
    /// @param[in]  key         COPC key value to set.
    /// @param[in]  result      COPC result to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   COPC entry modified successfully.
    /// @retval     LA_STATUS_EINVAL    Either key or result is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No COPC entry at a given position.
    /// @retval     LA_STATUS_ERESOURCE No resources for inserting an COPC entry.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set(size_t position,
                          const la_control_plane_classifier::key& key,
                          const la_control_plane_classifier::result& result)
        = 0;

    /// @brief Remove an COPC entry at a specific location and also move all the following entries
    ///        up to fill the hole.
    ///
    /// @param[in]  position            The position of the COPC entry.
    ///
    /// @retval     LA_STATUS_SUCCESS   COPC entry successfully removed.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No COPC entry at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status pop(size_t position) = 0;

    /// @brief Retrieve an COPC entry from a specific position.
    ///
    /// @param[in]  position                The position of the COPC entry.
    /// @param[out] out_copc_entry_desc  COPC entry descriptor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   COPC entry found successfully.
    /// @retval     LA_STATUS_EINVAL    Position is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No COPC entry at a given position.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get(size_t position, la_control_plane_classifier::entry_desc& out_copc_entry_desc) const = 0;

    /// @brief Delete all entries from the COPC instance.
    ///
    /// @retval     LA_STATUS_SUCCESS   All entries successfully removed.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear() = 0;

protected:
    ~la_control_plane_classifier() override = default;
};

} // namespace silicon_one

/// @}
#endif // __LA_COPC_H__
