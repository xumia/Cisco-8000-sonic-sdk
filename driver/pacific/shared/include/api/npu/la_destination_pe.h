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

#ifndef __LA_DESTINATION_PE_H__
#define __LA_DESTINATION_PE_H__

#include "api/npu/la_l3_destination.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba Destination PE (in a Remote AS) API-s.
///
/// Defines API-s to manage an object that represents a Destination PE in the remote AS in an Inter-AS (Autonomous system)
/// configuration.
///
/// Inter-AS configurations are used to create/enable forwarding paths to send Labeled BGP traffic across inter-domain boundaries. A
/// Destination PE represents a node in the remote AS in an Inter-AS configuration to which traffic is destined.
///

/// @addtogroup DESTINATION_PE
/// @{

namespace silicon_one
{

class la_destination_pe : public la_l3_destination
{
public:
    /// @brief Get destination PE's global ID.
    ///
    /// @return destination PE's global ID.
    virtual la_l3_destination_gid_t get_gid() const = 0;

    /// @brief Get L3 destination for this DPE.
    ///
    /// @retval The associated L3 destination for this DPE.
    virtual const la_l3_destination* get_destination() const = 0;

    /// @brief Update the destination for this DPE.
    ///
    /// @param[in]  destination         L3 destination the DPE points to.
    ///
    /// @retval     LA_STATUS_SUCCESS   DPE destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(const la_l3_destination* destination) = 0;

    /// @brief Update the VPN label for this destination_PE-VRF pair.
    ///
    /// @param[in]  vrf      VRF to be updated.
    /// @param[in]  ip_version ip_version for which the labels are to be updated.
    /// @param[in]  labels   The labels to be updated for this destination_PE-VRF pair.
    ///
    /// @retval     LA_STATUS_SUCCESS         Labels for this destination_PE-VRF pair updated successfully.
    /// @retval     LA_STATUS_EINVAL          VRF is invalid.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The number of labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, const la_mpls_label_vec_t& labels) = 0;

    /// @brief Get the VPN label for this destination_PE-VRF pair.
    ///
    /// @param[in]   vrf          The VRF.
    /// @param[in]   ip_version     ip_version for which the labels are to be retrieved.
    /// @param[out]  out_labels   The labels configured for this destination_PE-VRF pair.
    ///
    /// @retval     LA_STATUS_SUCCESS      Labels retrieved for this destination_PE-VRF pair successfully.
    /// @retval     LA_STATUS_EINVAL       VRF is invalid.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this destination_PE-VRF pair.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, la_mpls_label_vec_t& out_labels) const = 0;

    /// @brief Delete the destination_PE-VRF pair entry.
    ///
    /// @param[in]  vrf      VRF to be removed.
    /// @param[in]  ip_version ip_version for which the labels are to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   destination_PE-VRF entry removed successfully.
    /// @retval     LA_STATUS_EINVAL    VRF is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No relevant information found for this destination_PE-VRF pair.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version) = 0;

    /// @brief Update the label stack for this destination_PE-ASBR pair.
    ///
    /// @param[in]  asbr     ASBR to be updated.
    /// @param[in]  labels   The MPLS labels to be updated for this destination_PE-ASBR pair.
    ///
    /// @retval     LA_STATUS_SUCCESS         Label stack this destination_PE-ASBR pair updated successfully.
    /// @retval     LA_STATUS_EINVAL          ASBR is invalid.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Number of MPLS labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_asbr_properties(const la_prefix_object* asbr, const la_mpls_label_vec_t& labels) = 0;

    /// @brief Get the label stack for this destination_PE-ASBR pair.
    ///
    /// @param[in]   asbr         ASBR info to be retrieved.
    /// @param[out]  out_labels   The MPLS labels configured for this destination_PE-ASBR pair.
    ///
    /// @retval     LA_STATUS_SUCCESS      Label stack retrieved for this destination_PE-ASBR pair successfully.
    /// @retval     LA_STATUS_EINVAL       ASBR is invalid.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this destination_PE-ASBR pair.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_asbr_properties(const la_prefix_object* asbr, la_mpls_label_vec_t& out_labels) const = 0;

    /// @brief Delete the destination_PE-ASBR pair entry.
    ///
    /// @param[in]  asbr                ASBR to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   destination_PE-ASBR entry removed successfully.
    /// @retval     LA_STATUS_EINVAL    ASBR is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No relevant information found for this destination_PE-ASBR pair.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_asbr_properties(const la_prefix_object* asbr) = 0;

protected:
    ~la_destination_pe() override = default;
};
}
/// @}
#endif // __LA_DESTINATION_PE_H__
