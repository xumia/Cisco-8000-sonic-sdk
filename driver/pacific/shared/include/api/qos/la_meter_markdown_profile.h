// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_METER_MARKDOWN_PROFILE_H__
#define __LA_METER_MARKDOWN_PROFILE_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"

/// @file
/// @brief Meter markdown profile API-s.
///
/// Defines API-s for managing meter markdown profile.

namespace silicon_one
{

/// @addtogroup METER_MARKDOWN_PROFILE
/// @{

/// @brief      Meter markdown profile.
///
/// @details    Defines API-s for managing meter markdown profile.
///             Ingress QoS (#silicon_one::la_ingress_qos_profile) defines the mapping between QoS field
///             values of the incoming packet to internal qos tag and color. The meter block
///             (#silicon_one::la_meter_action_profile) updates the color of the packet (coming from ingress qos)
///             to new outgoing color. The outgoing color is based on user configured meter action.
///             The internal qos tag and outgoing color are used by meter markdown profile to construct
///             the key. Meter markdown profile provides updated internal qos tag. This tag is used by
///             egress QoS for further processing(#silicon_one::la_egress_qos_profile).
///
///             Meter markdown profile has two tables -
///             1. Forward meter markdown - This table generates updated internal qos tag for forward header
///                                         rewrite by egress QoS.
///             2. Encap meter markdown   - This table generates updated mpls_exp. This field is used by
///                                         egress QoS for MPLS EXP rewrite (inner labels).

class la_meter_markdown_profile : public la_object
{
public:
    /// @brief Get global unique ID of meter markdown profile.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_meter_markdown_gid_t get_gid() const = 0;

    /// @brief Set forward meter markdown profile table for (PCP, DEI).
    ///
    /// @param[in]  color         Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_pcp      Remapped (PCP, DEI) value from ingress QoS.
    /// @param[in]  markdown_pcp  Markdown (PCP, DEI) value. Used as key for egress QoS processing.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_meter_markdown_mapping_pcpdei(la_qos_color_e color, la_vlan_pcpdei from_pcp, la_vlan_pcpdei markdown_pcp)
        = 0;

    /// @brief Set forward meter markdown profile table for DSCP.
    ///
    /// @param[in]  color          Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_dscp      Remapped DSCP value from ingress QoS.
    /// @param[in]  markdown_dscp  Markdown DSCP value. Used as key for egress QoS processing.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_meter_markdown_mapping_dscp(la_qos_color_e color, la_ip_dscp from_dscp, la_ip_dscp markdown_dscp) = 0;

    /// @brief Set forward meter markdown profile table for MPLS-TC.
    ///
    /// @param[in]  color             Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_mpls_tc      Remapped MPLS-TC value from ingress QoS.
    /// @param[in]  markdown_mpls_tc  Markdown MPLS-TC value. Used as key for egress QoS processing.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_meter_markdown_mapping_mpls_tc(la_qos_color_e color, la_mpls_tc from_mpls_tc, la_mpls_tc markdown_mpls_tc)
        = 0;

    /// @brief Get the forward meter markdown value for (PCP, DEI).
    ///
    /// @param[in]  color             Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_pcp          Remapped (PCP, DEI) value from ingress QoS.
    /// @param[out] out_markdown_pcp  Markdown (PCP, DEI) value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_meter_markdown_mapping_pcpdei(la_qos_color_e color,
                                                        la_vlan_pcpdei from_pcp,
                                                        la_vlan_pcpdei& out_markdown_pcp) const = 0;

    /// @brief Get the forward meter markdown value for DSCP.
    ///
    /// @param[in]  color              Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_dscp          Remapped DSCP value from ingress QoS.
    /// @param[out] out_markdown_dscp  Markdown DSCP value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_meter_markdown_mapping_dscp(la_qos_color_e color,
                                                      la_ip_dscp from_dscp,
                                                      la_ip_dscp& out_markdown_dscp) const = 0;

    /// @brief Get the forward meter markdown value for MPLS-TC.
    ///
    /// @param[in]  color                 Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_mpls_tc          Remapped MPLS-TC value from ingress QoS.
    /// @param[out] out_markdown_mpls_tc  Markdown MPLS-TC value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_meter_markdown_mapping_mpls_tc(la_qos_color_e color,
                                                         la_mpls_tc from_mpls_tc,
                                                         la_mpls_tc& out_markdown_mpls_tc) const = 0;

    /// @brief Set encap meter markdown profile table for MPLS-TC.
    ///
    /// @param[in]  color               Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_encap_mpls_tc  Remapped MPLS-TC value from ingress QoS.
    /// @param[in]  markdown_mpls_tc    Markdown MPLS-TC value. Used as key for egress QoS processing.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_meter_markdown_mapping_mpls_tc_encap(la_qos_color_e color,
                                                               la_mpls_tc from_encap_mpls_tc,
                                                               la_mpls_tc markdown_mpls_tc)
        = 0;

    /// @brief Get the encap meter markdown value for MPLS-TC.
    ///
    /// @param[in]  color                 Color of the packet set by ingress QoS or meter.
    /// @param[in]  from_encap_mpls_tc    Remapped MPLS-TC value from ingress QoS.
    /// @param[out] out_markdown_mpls_tc  Markdown MPLS-TC value to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_meter_markdown_mapping_mpls_tc_encap(la_qos_color_e color,
                                                               la_mpls_tc from_encap_mpls_tc,
                                                               la_mpls_tc& out_markdown_mpls_tc) const = 0;

protected:
    ~la_meter_markdown_profile() override = default;
}; // class la_meter_markdown_profile

/// @}

} // namespace silicon_one

#endif // __LA_METER_MARKDOWN_PROFILE_H__
