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

#ifndef __LA_MPLS_VPN_ENCAP_H__
#define __LA_MPLS_VPN_ENCAP_H__

#include "api/npu/la_l3_destination.h"
#include "api/npu/la_prefix_object.h"
#include "api/types/la_mpls_types.h"

/// @file
/// @brief Leaba MPLS VPN Encapsulator API-s.
///
/// Defines API-s for managing MPLS VPN encapsulators.

namespace silicon_one
{

class la_mpls_vpn_encap : public la_l3_destination
{
public:
    /// @brief Get MPLS VPN encap object's global ID.
    ///
    /// @return MPLS VPN encap object's global ID.
    virtual la_mpls_vpn_encap_gid_t get_gid() const = 0;

    /// @brief Get L3 destination for this MPLS VPN encap object.
    ///
    /// @retval The associated L3 destination for this MPLS VPN encap object.
    virtual const la_l3_destination* get_destination() const = 0;

    /// @brief Update the destination for this MPLS VPN encap object.
    ///
    /// @param[in]  destination         L3 destination the MPLS VPN encap object points to.
    ///
    /// @retval     LA_STATUS_SUCCESS   MPLS VPN encap object destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(const la_l3_destination* destination) = 0;

    /// @brief Update the VPN label stack corresponding to the next hop.
    ///
    /// @param[in]  nh         VPN next hop. Can be either a #silicon_one::la_prefix_object or #silicon_one::la_destination_pe.
    /// @param[in]  ip_version ip_version for which labels are to be updated.
    /// @param[in]  labels     The VPN labels associated with the VPN next hop.
    ///
    /// @retval     LA_STATUS_SUCCESS         Label stack for this next hop updated successfully.
    /// @retval     LA_STATUS_EINVAL          NH is invalid.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Number of MPLS labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_nh_vpn_properties(const la_l3_destination* nh,
                                            la_ip_version_e ip_version,
                                            const la_mpls_label_vec_t& labels)
        = 0;

    /// @brief Get the label stack for the VPN next hop
    ///
    /// @param[in]   nh           The VPN next hop. Can be either a #silicon_one::la_prefix_object or
    ///                           #silicon_one::la_destination_pe.
    /// @param[in]   ip_version   ip_version for which labels are to be retrieved.
    /// @param[out]  out_labels   The VPN labels configured for this next hop.
    ///
    /// @retval     LA_STATUS_SUCCESS      Label stack retrieved successfully.
    /// @retval     LA_STATUS_EINVAL       NH is invalid.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this next hop.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_nh_vpn_properties(const la_l3_destination* nh,
                                            la_ip_version_e ip_version,
                                            la_mpls_label_vec_t& out_labels) const = 0;

    /// @brief Get all VPN properties of this object.
    ///
    /// @param[out] out_nh_vpn_properties The VPN properties
    ///
    /// @retval     LA_STATUS_SUCCESS      VPN properties retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_all_nh_vpn_properties(la_mpls_vpn_properties_vec_t& out_nh_vpn_properties) const = 0;

    /// @brief Delete VPN label stack corresponding to the next hop
    ///
    /// @param[in]  nh                  VPN next hop. Can be either a #silicon_one::la_prefix_object or
    ///                                 #silicon_one::la_destination_pe.
    /// @param[in]  ip_version          ip_version for which labels are to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   VPN label stack removed successfully.
    /// @retval     LA_STATUS_EINVAL    NH is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No relevant information found for this next hop.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_nh_vpn_properties(const la_l3_destination* nh, la_ip_version_e ip_version) = 0;

protected:
    ~la_mpls_vpn_encap() override = default;
};

} // namespace silicon_one

#endif // __LA_MPLS_VPN_ENCAP_H__
