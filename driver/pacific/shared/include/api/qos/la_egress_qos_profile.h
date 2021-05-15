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

#ifndef __LA_EGRESS_QOS_PROFILE_H__
#define __LA_EGRESS_QOS_PROFILE_H__

#include "api/npu/la_acl.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"

/// @file
/// @brief Leaba Egress Quality of Service profile API-s.
///
/// Defines API-s for managing an egress QoS profile.

namespace silicon_one
{

/// @addtogroup EGRESS_QOS_PROFILE
/// @{

/// @brief      Egress Quality of Service profile.
///
/// @details    Egress QoS profile controls the QoS fields' marking in transmitted packets, by defining a mapping between:
///                1. Egress-indicated forwarding header tag, or
///                2. Egress QOS group
///             and the QoS field values in a transmitted packet.
///
///             The mapping from 1. Egress-indicated forwarding header QoS tag and 2. QoS Group, control both the remarking value
///             of the QoS field in the forwarding header, and marking value in the encapsulating headers. The mapping of 3.
///             Encapsulating headers canonical QoS tag controls only the marking value in the encapsulating headers.
///
///             There are three QoS mapping tables, one for each forwarding header type: Ethernet, IP and MPLS. The accessed table
///             is decided based on the egress-forwarding header.
///
///             For example, assume a MAC-->MPLS(label)-->IPv4 packet should undergo a MPLS-PHP (penultimate hop popping). On
///             ingress, the MPLS header is the forwarding header. On egress, the IPv4 is the forwarding header. Hence, it will
///             be mapped using the IP-DSCP.

class la_egress_qos_profile : public la_object
{
public:
    /// @brief Encapsulating headers QoS fields' values.
    struct encapsulating_headers_qos_values {
        la_vlan_pcpdei pcpdei;     ///< Priority Code Point, Drop Eligibility Indicator field in VLAN header.
        la_ip_tos tos;             ///< Type of Service field in IP header.
        la_mpls_tc tc;             ///< MPLS Traffic Class field.
        bool use_for_inner_labels; ///< If true, use this Traffic Class for inner imposed MPLS labels.
    };

    /// @name Ethernet forwarding QoS re/marking mapping
    /// @{

    /// @brief Get profile's QoS source mode.
    ///
    /// @param[out] out_marking_source              Egress QoS marking source to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS               Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN              An unknown error occurred.
    virtual la_status get_marking_source(la_egress_qos_marking_source_e& out_marking_source) const = 0;

    /// @brief Set the forwarding and encapsulating headers QoS fields' values based on Egress-indicated (PCP, DEI) tag.
    ///
    /// When doing Ethernet forwarding, defines the mapping between the Egress-indicated (PCP, DEI) tag and
    ///    - (PCP, DEI) to set in the forwarding header.
    ///    - QoS fields' values in the encapsulating headers.
    ///    .
    /// This mapping is used when the profile is in #silicon_one::la_egress_qos_marking_source_e::QOS_TAG mode.
    ///
    /// @param[in]  egress_pcpdei_tag   Egress-indicated (PCP, DEI) tag.
    /// @param[in]  remark_pcpdei       Remarking (PCP, DEI) value.
    /// @param[in]  encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_tag_mapping_pcpdei(la_vlan_pcpdei egress_pcpdei_tag,
                                                 la_vlan_pcpdei remark_pcpdei,
                                                 encapsulating_headers_qos_values encap_qos_values)
        = 0;

    /// @brief Get the forwarding and encapsulating headers QoS fields' values based on Egress-indicated (PCP, DEI) tag.
    ///
    /// @param[in]  egress_pcpdei_tag       Egress-indicated (PCP, DEI) tag.
    ///
    /// @param[out] out_remark_pcpdei       Remarking (PCP, DEI) value.
    /// @param[out] out_encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND     QOS tag mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_tag_mapping_pcpdei(la_vlan_pcpdei egress_pcpdei_tag,
                                                 la_vlan_pcpdei& out_remark_pcpdei,
                                                 encapsulating_headers_qos_values& out_encap_qos_values) const = 0;

    /// @brief Set the forwarding and encapsulating headers QoS fields' values based on QoS Group.
    ///
    /// When doing Ethernet forwarding, defines the mapping between the QoS Group and
    ///    - (PCP, DEI) to set in the forwarding header.
    ///    - QoS fields' values in the encapsulating headers.
    ///    .
    /// This mapping is used when the profile is in
    /// #silicon_one::la_egress_qos_marking_source_e::QOS_GROUP mode.
    ///
    /// @param[in]  qos_group           QoS Group.
    /// @param[in]  pcpdei              Remarking (PCP, DEI) value.
    /// @param[in]  encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid QoS Group value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_group_mapping_pcpdei(la_qos_group_t qos_group,
                                                   la_vlan_pcpdei pcpdei,
                                                   encapsulating_headers_qos_values encap_qos_values)
        = 0;

    /// @brief Get the forwarding and encapsulating headers QoS fields' values based on QoS Group.
    ///
    /// @param[in]      qos_group               QoS Group.
    ///
    /// @param[out]     out_pcpdei              Remarking (PCP, DEI) value.
    /// @param[out]     out_encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL        Invalid QoS Group value.
    /// @retval         LA_STATUS_ENOTFOUND     QOS tag mapping in the given position was not defined.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_group_mapping_pcpdei(la_qos_group_t qos_group,
                                                   la_vlan_pcpdei& out_pcpdei,
                                                   encapsulating_headers_qos_values& out_encap_qos_values) const = 0;

    /// @}
    /// @name IP forwarding QoS re/marking mapping
    /// @{

    /// @brief Set the forwarding and encapsulating headers QoS fields' values based on Egress-indicated DSCP tag.
    ///
    /// When doing IP forwarding, defines the mapping between the Egress-indicated DSCP tag and
    ///    - DSCP to set in the forwarding header.
    ///    - QoS fields' values in the encapsulating headers.
    ///    .
    /// This mapping is used when the profile is in
    /// #silicon_one::la_egress_qos_marking_source_e::QOS_TAG mode.
    ///
    /// @param[in]  egress_dscp_tag     Egress-indicated DSCP tag.
    /// @param[in]  remark_dscp         Remarking DSCP value.
    /// @param[in]  encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_tag_mapping_dscp(la_ip_dscp egress_dscp_tag,
                                               la_ip_dscp remark_dscp,
                                               encapsulating_headers_qos_values encap_qos_values)
        = 0;

    /// @brief Get the forwarding and encapsulating headers QoS fields' values based on Egress-indicated DSCP tag.
    ///
    /// @param[in]      egress_dscp_tag         Egress-indicated DSCP tag.
    ///
    /// @param[out]     out_remark_dscp         Remarking DSCP value.
    /// @param[out]     out_encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_ENOTFOUND     QOS tag mapping in the given position was not defined.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_tag_mapping_dscp(la_ip_dscp egress_dscp_tag,
                                               la_ip_dscp& out_remark_dscp,
                                               encapsulating_headers_qos_values& out_encap_qos_values) const = 0;

    /// @brief Set the forwarding and encapsulating headers QoS fields' values based on QoS Group.
    ///
    /// When doing IP forwarding, defines the mapping between the QoS Group and
    ///    - DSCP to set in the forwarding header.
    ///    - QoS fields' values in the encapsulating headers.
    ///    .
    /// This mapping is used when the profile is in
    /// #silicon_one::la_egress_qos_marking_source_e::QOS_GROUP mode.
    ///
    /// @param[in]  qos_group           QoS Group.
    /// @param[in]  dscp                Remarking DSCP value.
    /// @param[in]  encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid QoS Group value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_group_mapping_dscp(la_qos_group_t qos_group,
                                                 la_ip_dscp dscp,
                                                 encapsulating_headers_qos_values encap_qos_values)
        = 0;

    /// @brief Get the forwarding and encapsulating headers QoS fields' values based on QoS Group.
    ///
    /// @param[in]      qos_group               QoS Group.
    ///
    /// @param[out]     out_dscp                Remarking DSCP value.
    /// @param[out]     out_encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL        Invalid QoS Group value.
    /// @retval         LA_STATUS_ENOTFOUND     QOS group mapping in the given position was not defined.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_group_mapping_dscp(la_qos_group_t qos_group,
                                                 la_ip_dscp& out_dscp,
                                                 encapsulating_headers_qos_values& out_encap_qos_values) const = 0;

    /// @}
    /// @name MPLS forwarding QoS re/marking mapping
    /// @{

    /// Configure the forwarding label Traffic Class and encapsulating headers QoS fields' to set when doing MPLS forwarding
    /// flows. The forwarding label is defined by per flow:
    ///    - Label swap flow - forwarding label = the swapped label.
    ///    - Label swap + push flow - forwarding label = the swapped label.
    ///    - PHP flow - forwarding label = the exposed label.

    /// @brief Set the forwarding label and encapsulating headers QoS fields' values based on Egress-indicated MPLS-TC tag.
    ///
    /// When doing MPLS forwarding, defines the mapping between the on Egress-indicated MPLS-TC tag and
    ///    - MPLS-TC to set in the forwarding label.
    ///    - QoS fields' values in the encapsulating headers.
    ///    .
    /// This mapping is used when the profile is in
    /// #silicon_one::la_egress_qos_marking_source_e::QOS_TAG mode.
    ///
    /// @param[in]  egress_mpls_tc_tag  Egress-indicated MPLS-TC tag.
    /// @param[in]  remark_mpls_tc      Remarking MPLS-TC value.
    /// @param[in]  encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_tag_mapping_mpls_tc(la_mpls_tc egress_mpls_tc_tag,
                                                  la_mpls_tc remark_mpls_tc,
                                                  encapsulating_headers_qos_values encap_qos_values)
        = 0;

    /// @brief Get the forwarding label and encapsulating headers QoS fields' values based on Egress-indicated MPLS-TC tag.
    ///
    /// @param[in]      egress_mpls_tc_tag      Egress-indicated MPLS-TC tag.
    ///
    /// @param[out]     out_remark_mpls_tc      Remarking MPLS-TC value.
    /// @param[out]     out_encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_ENOTFOUND     QOS tag mapping in the given position was not defined.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_tag_mapping_mpls_tc(la_mpls_tc egress_mpls_tc_tag,
                                                  la_mpls_tc& out_remark_mpls_tc,
                                                  encapsulating_headers_qos_values& out_encap_qos_values) const = 0;

    /// @brief Set the forwarding label and encapsulating headers QoS fields' values based on QoS Group.
    ///
    /// When doing MPLS forwarding, defines the mapping between the QoS Group and
    ///    - MPLS-TC to set in the forwarding label.
    ///    - QoS fields' values in the encapsulating headers.
    ///    .
    /// This mapping is used when the profile is in
    /// #silicon_one::la_egress_qos_marking_source_e::QOS_GROUP mode.
    ///
    /// @param[in]  qos_group           QoS Group.
    /// @param[in]  mpls_tc             Remarking MPLS-TC value.
    /// @param[in]  encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid QoS Group value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_qos_group_mapping_mpls_tc(la_qos_group_t qos_group,
                                                    la_mpls_tc mpls_tc,
                                                    encapsulating_headers_qos_values encap_qos_values)
        = 0;

    /// @brief Get the forwarding label and encapsulating headers QoS fields' values based on QoS Group.
    ///
    /// @param[in]      qos_group               QoS Group.
    ///
    /// @param[out]     out_mpls_tc             Remarking MPLS-TC value.
    /// @param[out]     out_encap_qos_values    QoS fields' values of the encapsulating headers.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EINVAL        Invalid QoS Group value.
    /// @retval         LA_STATUS_ENOTFOUND     QOS group mapping in the given position was not defined.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_qos_group_mapping_mpls_tc(la_qos_group_t qos_group,
                                                    la_mpls_tc& out_mpls_tc,
                                                    encapsulating_headers_qos_values& out_encap_qos_values) const = 0;

    /// @}
    /// @name Counter offset mapping.
    /// @{

    /// @brief Set (QOS_GROUP)->counter offset mapping.
    ///
    /// @param[in]  qos_group           Egress-indicated (QOS_GROUP) tag.
    /// @param[in]  offset              Counter offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid counter offset value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_counter_offset_mapping(la_qos_group_t qos_group, la_uint8_t offset) = 0;

    /// @brief Get (QOS_GROUP)->counter offset mapping.
    ///
    /// @param[in]  qos_group           Egress-indicated (QOS_GROUP) tag.
    /// @param[out] out_offset          Counter offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Counter offset mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_counter_offset_mapping(la_qos_group_t qos_group, la_uint8_t& out_offset) const = 0;

    /// @brief Set (PCP, DEI)->counter offset mapping.
    ///
    /// @param[in]  egress_pcpdei_tag   Egress-indicated (PCP, DEI) tag.
    /// @param[in]  offset              Counter offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid counter offset value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_counter_offset_mapping(la_vlan_pcpdei egress_pcpdei_tag, la_uint8_t offset) = 0;

    /// @brief Get (PCP, DEI)->counter offset mapping.
    ///
    /// @param[in]  egress_pcpdei_tag   Egress-indicated (PCP, DEI) tag.
    /// @param[out] out_offset          Counter offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Counter offset mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_counter_offset_mapping(la_vlan_pcpdei egress_pcpdei_tag, la_uint8_t& out_offset) const = 0;

    /// @brief Set DSCP->counter offset mapping.
    ///
    /// @param[in]  egress_dscp_tag     Egress-indicated DSCP tag.
    /// @param[in]  offset              Counter offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid counter offset value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_counter_offset_mapping(la_ip_dscp egress_dscp_tag, la_uint8_t offset) = 0;

    /// @brief Get DSCP->counter offset mapping.
    ///
    /// @param[in]  egress_dscp_tag     Egress-indicated DSCP tag.
    /// @param[out] out_offset          Counter offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Counter offset mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_counter_offset_mapping(la_ip_dscp egress_dscp_tag, la_uint8_t& out_offset) const = 0;

    /// @brief Set MPLS-TC->counter offset mapping.
    ///
    /// @param[in]  egress_mpls_tc_tag  Egress-indicated MPLS-TC tag.
    /// @param[in]  offset              Counter offset.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid counter offset value.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_counter_offset_mapping(la_mpls_tc egress_mpls_tc_tag, la_uint8_t offset) = 0;

    /// @brief Get MPLS-TC->counter offset mapping.
    ///
    /// @param[in]  egress_mpls_tc_tag  Egress-indicated MPLS-TC tag.
    /// @param[out] out_offset          Counter offset to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND Counter offset mapping in the given position was not defined.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_counter_offset_mapping(la_mpls_tc egress_mpls_tc_tag, la_uint8_t& out_offset) const = 0;

protected:
    ~la_egress_qos_profile() override = default;
}; // class la_egress_qos_profile

} // namespace silicon_one

#endif // __LA_EGRESS_QOS_PROFILE_H__
