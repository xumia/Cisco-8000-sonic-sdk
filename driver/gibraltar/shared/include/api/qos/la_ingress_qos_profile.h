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

#ifndef __LA_INGRESS_QOS_PROFILE_H__
#define __LA_INGRESS_QOS_PROFILE_H__

#include "api/npu/la_acl.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"

/// @file
/// @brief Leaba Ingress Quality of Service profile API-s.
///
/// Defines API-s for managing an ingress QoS profile.

namespace silicon_one
{

/// @addtogroup INGRESS_QOS_PROFILE
/// @{

/// @brief      Ingress Quality of Service profile.
///
/// @details    Ingress QoS profile defines the mapping between QoS field values of incoming packets to:
///                1. The traffic class of the packet, which is (usually) used to derive the VOQ of the packet. Read
///                   #silicon_one::la_tc_profile for more information.
///
///                2. The color of the packet, which is used for metering and packet buffering in a VOQ. Read
///                   #silicon_one::la_voq_cgm_profile for more information.
///
///                3. Meter/Counter offset, which is used together with the ingress logical port's meter/counter set object to
///                   derive a specific meter/counter.
///
///                4. Whether to apply metering.
///
///                5. The marking indication to the egress profile of how to mark the packet. Read
///                #silicon_one::la_egress_qos_profile
///                   for more information.
///
///             There are three QoS mapping tables, one for each forwarding header type: Ethernet, IP and MPLS. The accessed table
///             is decided based on the forwarding header. The key with which the table is accessed depends on the QoS
///             inheritance mode of the last termination stage. Read #silicon_one::la_mpls_qos_inheritance_mode_e for more
///             information.
///
///             For example, assume a MAC-->MPLS(label)-->IPv4 packet should undergo a VPN decapsulation, and the VPN
///             decapsulation is configured to be be in UNIFORM QoS inheritance mode. The UNIFORM QoS inheritance mode dictates
///             that the MPLS header's QoS field (the MPLS_TC) will be used as the key. The forwarding header is IPv4, hence, the
///             IP QoS mapping table will be accessed.

class la_ingress_qos_profile : public la_object
{
public:
    /// @brief Enable/Disable ingress header remarking for all flows.
    ///
    /// @param[in]  enabled             true if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occured.
    virtual la_status set_qos_tag_mapping_enabled(bool enabled) = 0;

    /// @brief Get whether ingress header remarking is enabled/disabled.
    ///
    /// @param[out] out_enabled         true if enabled, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_qos_tag_mapping_enabled(bool& out_enabled) const = 0;

    /// @name Traffic class mapping.
    /// @{

    /// @brief Set (PCP, DEI)->Traffic Class mapping.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[in]  tc                  Traffic Class.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid Traffic Class value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t tc) = 0;

    /// @brief Get (PCP, DEI)->Traffic Class mapping.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[out] out_tc              Traffic Class to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND TC mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_traffic_class_mapping(la_vlan_pcpdei pcpdei, la_traffic_class_t& out_tc) const = 0;

    /// @brief Set DSCP->Traffic Class mapping.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[in]  tc                  Traffic Class.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t tc) = 0;

    /// @brief Get DSCP->Traffic Class mapping.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[out] out_tc              Traffic Class to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND TC mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_traffic_class_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_traffic_class_t& out_tc) const = 0;

    /// @brief Set MPLS-TC->Traffic Class mapping.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[in]  tc                  Traffic Class.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t tc) = 0;

    /// @brief Get MPLS-TC->Traffic Class mapping.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[out] out_tc              Traffic Class to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND TC mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_traffic_class_mapping(la_mpls_tc mpls_tc, la_traffic_class_t& out_tc) const = 0;

    /// @}
    /// @name Color mapping.
    /// @{

    /// @brief Set (PCP, DEI)->Color mapping.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[in]  color               Packet Color.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e color) = 0;

    /// @brief Get (PCP, DEI)->Color mapping.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[out] out_color           Packet Color to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Color mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_color_mapping(la_vlan_pcpdei pcpdei, la_qos_color_e& out_color) const = 0;

    /// @brief Set DSCP->Color mapping.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[in]  color               Packet Color.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e color) = 0;

    /// @brief Get DSCP->Color mapping.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[out] out_color           Packet Color to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Color mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_color_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_color_e& out_color) const = 0;

    /// @brief Set MPLS-TC->Color mapping.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[in]  color               Packet Color.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e color) = 0;

    /// @brief Get MPLS-TC->Color mapping.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[out] out_color           Packet Color to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Color mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_color_mapping(la_mpls_tc mpls_tc, la_qos_color_e& out_color) const = 0;

    /// @}
    /// @name Meter/Counter offset mapping.
    /// @{

    /// @brief Set (PCP, DEI)->meter/counter offset mapping.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[in]  offset              Meter/Counter offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid meter/counter offset value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_meter_or_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t offset) = 0;

    /// @brief Get (PCP, DEI)->meter/counter offset mapping.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[out] out_offset          Meter/Counter offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Meter/Counter mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_meter_or_counter_offset_mapping(la_vlan_pcpdei pcpdei, la_uint8_t& out_offset) const = 0;

    /// @brief Set DSCP->meter/counter offset mapping.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[in]  offset              Meter/Counter offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid meter/counter offset value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_meter_or_counter_offset_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_uint8_t offset) = 0;

    /// @brief Get DSCP->meter/counter offset mapping.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[out] out_offset          Meter/Counter offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Meter/Counter mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_meter_or_counter_offset_mapping(la_ip_version_e ip_version,
                                                          la_ip_dscp dscp,
                                                          la_uint8_t& out_offset) const = 0;

    /// @brief Set MPLS-TC->meter/counter offset mapping.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[in]  offset              Meter/Counter offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid meter/counter offset value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_meter_or_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t offset) = 0;

    /// @brief Get MPLS-TC->meter/counter offset mapping.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[out] out_offset          Meter/Counter offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Meter/Counter mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_meter_or_counter_offset_mapping(la_mpls_tc mpls_tc, la_uint8_t& out_offset) const = 0;

    /// @}
    /// @name Meter or counter selection mapping.
    /// @{

    /// @brief Set (PCP, DEI)->meter or counter selection mapping.
    ///
    /// Selects whether to apply a meter or a counter on packets entering a logical port which uses this ingress QoS profile. The
    /// actual meter/counter sets are configured on the logical port.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[in]  enabled             true if a meter should be enabled; false if a counter should be applied.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool enabled) = 0;

    /// @brief Get (PCP, DEI)->meter or counter selection mapping.
    ///
    /// @param[in]  pcpdei              (PCP, DEI) field.
    /// @param[out] out_enabled         true if a meter is enabled.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Meter enabling in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_metering_enabled_mapping(la_vlan_pcpdei pcpdei, bool& out_enabled) const = 0;

    /// @brief Set DSCP->meter or counter selection mapping.
    ///
    /// Selects whether to apply a meter or a counter on packets entering a logical port which uses this ingress QoS profile. The
    /// actual meter/counter sets are configured on the logical port.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[in]  enabled             true if a meter should be enabled; false if a counter should be applied.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool enabled) = 0;

    /// @brief Get DSCP->meter or counter selection mapping.
    ///
    /// @param[in]  ip_version          IPv4 or IPv6 mapping.
    /// @param[in]  dscp                DSCP field.
    /// @param[out] out_enabled         true if a meter is enabled.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Meter enabling in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_metering_enabled_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, bool& out_enabled) const = 0;

    /// @brief Set MPLS-TC->meter or counter selection mapping.
    ///
    /// Selects whether to apply a meter or a counter on packets entering a logical port which uses this ingress QoS profile. The
    /// actual meter/counter sets are configured on the logical port.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[in]  enabled             true if a meter should be enabled; false if a counter should be applied.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_metering_enabled_mapping(la_mpls_tc mpls_tc, bool enabled) = 0;

    /// @brief Get MPLS-TC->meter or counter selection mapping.
    ///
    /// @param[in]  mpls_tc             MPLS-TC field.
    /// @param[out] out_enabled         true if a meter is enabled.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Meter enabling in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_metering_enabled_mapping(la_mpls_tc mpls_tc, bool& out_enabled) const = 0;

    /// @}
    /// @name Ingress QoS tag mapping.
    /// @{

    /// @brief Set (PCP, DEI)->(PCP, DEI) ingress QoS tag mapping.
    ///
    /// @param[in]  ingress_pcpdei              Ingress (PCP, DEI) field.
    /// @param[in]  mapped_pcpdei_tag           Mapped (PCP, DEI) tag.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_qos_tag_mapping_pcpdei(la_vlan_pcpdei ingress_pcpdei, la_vlan_pcpdei mapped_pcpdei_tag) = 0;

    /// @brief Get (PCP, DEI)->(PCP, DEI) ingress QoS tag mapping.
    ///
    /// @param[in]  ingress_pcpdei              Ingress (PCP, DEI) field.
    /// @param[out] out_mapped_pcpdei_tag       Mapped (PCP, DEI) tag to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         QOS tag mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_qos_tag_mapping_pcpdei(la_vlan_pcpdei ingress_pcpdei, la_vlan_pcpdei& out_mapped_pcpdei_tag) const = 0;

    /// @brief Set DSCP->DSCP ingress QoS tag mapping for IPv4 and IPv6
    ///
    /// @param[in]  ingress_dscp                Ingress DSCP field.
    /// @param[in]  mapped_dscp_tag             Mapped DSCP tag.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_qos_tag_mapping_dscp(la_ip_dscp ingress_dscp, la_ip_dscp mapped_dscp_tag) = 0;

    /// @brief Set DSCP->DSCP ingress QoS tag mapping.
    ///
    /// @param[in]  ip_version                  IPv4 or IPv6 mapping.
    /// @param[in]  ingress_dscp                Ingress DSCP field.
    /// @param[in]  mapped_dscp_tag             Mapped DSCP tag.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_qos_tag_mapping_dscp(la_ip_version_e ip_version, la_ip_dscp ingress_dscp, la_ip_dscp mapped_dscp_tag) = 0;

    /// @brief Get DSCP->DSCP ingress QoS tag mapping.
    ///
    /// @param[in]  ip_version                  IPv4 or IPv6 mapping.
    /// @param[in]  ingress_dscp                Ingress DSCP field.
    /// @param[out] out_mapped_dscp_tag         Mapped DSCP tag to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         QOS tag mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_qos_tag_mapping_dscp(la_ip_version_e ip_version,
                                               la_ip_dscp ingress_dscp,
                                               la_ip_dscp& out_mapped_dscp_tag) const = 0;

    /// @brief Set MPLS-TC->MPLS-TC ingress QoS tag mapping.
    ///
    /// @param[in]  ingress_mpls_tc             Ingress MPLS-TC field.
    /// @param[in]  mapped_mpls_tc_tag          Mapped MPLS-TC tag.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_qos_tag_mapping_mpls_tc(la_mpls_tc ingress_mpls_tc, la_mpls_tc mapped_mpls_tc_tag) = 0;

    /// @brief Get MPLS-TC->MPLS-TC ingress QoS tag mapping.
    ///
    /// @param[in]  ingress_mpls_tc             Ingress MPLS-TC field.
    /// @param[out] out_mapped_mpls_tc_tag      Mapped MPLS-TC tag to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         QOS tag mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_qos_tag_mapping_mpls_tc(la_mpls_tc ingress_mpls_tc, la_mpls_tc& out_mapped_mpls_tc_tag) const = 0;

    /// @}
    /// @name Qos mapping for mpls imposition
    /// @{

    /// @brief Set (PCP, DEI)->encap MPLS-TC.
    ///
    /// @param[in]  pcpdei                      (PCP, DEI) field.
    /// @param[in]  encap_mpls_tc               MPLS traffic-class for imposed labels
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            Invalid ingress encapsulating headers QoS tag.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc encap_mpls_tc) = 0;

    /// @brief Get (PCP, DEI)->encap MPLS-TC.
    ///
    /// @param[in]  pcpdei                      (PCP, DEI) field.
    /// @param[out] out_encap_mpls_tc           Encap MPLS traffic-class to populate
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         QOS tag mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_encap_qos_tag_mapping(la_vlan_pcpdei pcpdei, la_mpls_tc& out_encap_mpls_tc) const = 0;

    /// @brief Set DSCP->encap MPLS-TC.
    ///
    /// @param[in]  ip_version                  IPv4 or IPv6 mapping.
    /// @param[in]  dscp                        DSCP field.
    /// @param[in]  encap_mpls_tc               MPLS traffic-class for imposed labels
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_encap_qos_tag_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_mpls_tc encap_mpls_tc) = 0;

    /// @brief Get DSCP->encap MPLS-TC.
    ///
    /// @param[in]  ip_version                  IPv4 or IPv6 mapping.
    /// @param[in]  dscp                        DSCP field.
    /// @param[out] out_encap_mpls_tc           Encap MPLS traffic-class to populate
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         QOS tag mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_encap_qos_tag_mapping(la_ip_version_e ip_version,
                                                la_ip_dscp dscp,
                                                la_mpls_tc& out_encap_mpls_tc) const = 0;

    /// @brief Set MPLS-TC->encap MPLS-TC.
    ///
    /// @param[in]  mpls_tc                     MPLS-TC field.
    /// @param[in]  encap_mpls_tc               MPLS traffic-class for imposed labels
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status set_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc encap_mpls_tc) = 0;

    /// @brief Get MPLS-TC->encap MPLS-TC.
    ///
    /// @param[in]  mpls_tc                     MPLS-TC field.
    /// @param[out] out_encap_mpls_tc           Encap MPLS traffic-class to populate
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         QOS tag mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    virtual la_status get_encap_qos_tag_mapping(la_mpls_tc mpls_tc, la_mpls_tc& out_encap_mpls_tc) const = 0;

    /// @}
    /// @name QoS Group mapping.
    /// @{

    /// @brief Set (PCP, DEI)->QoS Group mapping.
    ///
    /// @param[in]  pcpdei                  (PCP, DEI) field.
    /// @param[in]  qos_group               QoS Group.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid QoS group.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t qos_group) = 0;

    /// @brief Get (PCP, DEI)->QoS Group mapping.
    ///
    /// @param[in]  pcpdei                  (PCP, DEI) field.
    /// @param[out] out_qos_group           QoS Group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     QOS group mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_group_mapping(la_vlan_pcpdei pcpdei, la_qos_group_t& out_qos_group) const = 0;

    /// @brief Set DSCP->QoS Group mapping.
    ///
    /// @param[in]  ip_version              IPv4 or IPv6 mapping.
    /// @param[in]  dscp                    DSCP field.
    /// @param[in]  qos_group               QoS Group.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid QoS group.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t qos_group) = 0;

    /// @brief Get DSCP->QoS Group mapping.
    ///
    /// @param[in]  ip_version              IPv4 or IPv6 mapping.
    /// @param[in]  dscp                    DSCP field.
    /// @param[out] out_qos_group           QoS Group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     QOS group mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_group_mapping(la_ip_version_e ip_version, la_ip_dscp dscp, la_qos_group_t& out_qos_group) const = 0;

    /// @brief Set MPLS-TC->QoS Group mapping.
    ///
    /// @param[in]  mpls_tc                 MPLS-TC field.
    /// @param[in]  qos_group               QoS Group.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Invalid QoS group.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t qos_group) = 0;

    /// @brief Get MPLS-TC->QoS Group mapping.
    ///
    /// @param[in]  mpls_tc                 MPLS-TC field.
    /// @param[out] out_qos_group           QoS Group to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     QOS group mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_group_mapping(la_mpls_tc mpls_tc, la_qos_group_t& out_qos_group) const = 0;

    /// @brief Set meter markdown profile.
    ///
    /// @param[in]  meter_markdown_profile     Meter markdown profile object.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL           Invalid meter markdown profile object.
    virtual la_status set_meter_markdown_profile(const la_meter_markdown_profile* meter_markdown_profile) = 0;

    /// @brief Get meter markdown profile.
    ///
    /// @param[out] out_meter_markdown_profile  Meter markdown profile object.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND         Meter markdown profile object not found.
    virtual la_status get_meter_markdown_profile(const la_meter_markdown_profile*& out_meter_markdown_profile) const = 0;

    /// @brief Clear meter markdown profile.
    ///
    /// @retval     LA_STATUS_SUCCESS          Meter markdown profile object detached successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status clear_meter_markdown_profile() = 0;

    /// @}

protected:
    ~la_ingress_qos_profile() override = default;
}; // class la_ingress_qos_profile

/// @}

} // namespace silicon_one

#endif // __LA_INGRESS_QOS_PROFILE_H__
