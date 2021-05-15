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

#ifndef __LA_PREFIX_OBJECT_H_
#define __LA_PREFIX_OBJECT_H_

/// @file
/// @brief Leaba Prefix Object API.
///
/// Defines API-s for managing a Prefix destination objects. Such objects can
/// be used for provisioning MPLS tunnels. E.g. - they can be used for
/// implmenting LDP and TE tunnels.

#include "api/npu/la_counter_set.h"
#include "api/npu/la_l3_destination.h"
#include "api/types/la_common_types.h"
#include "api/types/la_mpls_types.h"

namespace silicon_one
{

class la_prefix_object : public la_l3_destination
{
public:
    /// @brief MPLS prefix type.
    enum class prefix_type_e {
        NORMAL = 0, ///< LSP prefixes created with a unique label for every Next hop.
        GLOBAL,     ///< LSP prefixes created with a global label for the prefix (for use with Segment Routing).
    };

    enum class lsp_counter_mode_e {
        LABEL,          ///< LSP LABEL counter mode.
        PER_PROTOCOL,   ///< LSP per protocol label counter mode.
        TRAFFIC_MATRIX, ///< LSP traffic matrix label counter mode.
    };

    /// @brief Get prefix object's global ID.
    ///
    /// @return prefix object's global ID.
    virtual la_l3_destination_gid_t get_gid() const = 0;

    /// @brief Get L3 destination for this prefix object.
    ///
    /// @retval The associated L3 destination for this prefix object.
    virtual const la_l3_destination* get_destination() const = 0;

    /// @brief Update the destination for this prefix object.
    ///
    /// @param[in]  destination         L3 destination the prefix points to.
    ///
    /// @retval     LA_STATUS_SUCCESS   Prefix destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(const la_l3_destination* destination) = 0;

    /// @brief Update the label stack and counter for this global prefix.  This can be used in cases when the outgoing MPLS label is
    /// the same across all the NH's.
    ///
    /// @param[in]  labels        The MPLS labels to be updated for this prefix.
    /// @param[in]  counter       Counter to be updated for this prefix.
    /// @param[in]  counter_mode  Counter mode of the counter to be updated for this prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS         Label stack and counter for this prefix updated successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Number of MPLS labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_global_lsp_properties(const la_mpls_label_vec_t& labels,
                                                la_counter_set* counter,
                                                lsp_counter_mode_e counter_mode)
        = 0;

    /// @brief Get the label stack and counter for this prefix.
    ///
    /// @param[out]  out_labels        The MPLS labels configured for this prefix.
    /// @param[out]  out_counter       Counter configured for this prefix.
    /// @param[out]  out_counter_mode  Counter mode of the counter for this prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS      Label stack and counter retrieved for this prefix successfully.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this prefix.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_global_lsp_properties(la_mpls_label_vec_t& out_labels,
                                                const la_counter_set*& out_counter,
                                                lsp_counter_mode_e& out_counter_mode) const = 0;

    /// @brief Delete the entry representing the global LSP prefix.
    ///
    /// @retval     LA_STATUS_SUCCESS   Global LSP entry removed successfully.
    /// @retval     LA_STATUS_ENOTFOUND No relevant global information found for this prefix.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_global_lsp_properties() = 0;

    /// @brief Retrieve the type associated with the prefix object.
    ///
    /// @param[out] out_type        Reference to #prefix_type_e to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_prefix_type(prefix_type_e& out_type) const = 0;

    /// @brief Update the label stack and counter for this prefix-NH pair.
    ///
    ///
    /// @param[in]  nh            NH to be updated.
    /// @param[in]  labels        The MPLS labels to be updated for this prefix-NH pair.
    /// @param[in]  counter       Counter to be updated for this prefix-NH pair.
    /// @param[in]  counter_mode  Counter mode of the counter to be updated for this prefix-NH pair.
    ///
    /// @retval     LA_STATUS_SUCCESS         Label stack and counter for this prefix-NH pair updated successfully.
    /// @retval     LA_STATUS_EINVAL          NH is invalid.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Number of MPLS labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_nh_lsp_properties(const la_next_hop* nh,
                                            const la_mpls_label_vec_t& labels,
                                            la_counter_set* counter,
                                            lsp_counter_mode_e counter_mode)
        = 0;

    /// @brief Get the label stack and counter for this prefix-NH pair.
    ///
    /// @param[in]   nh                The Nexthop.
    /// @param[out]  out_labels        The MPLS labels configured for this prefix-NH pair.
    /// @param[out]  out_counter       Counter configured for this prefix-NH pair.
    /// @param[out]  out_counter_mode  Counter mode of the counter for this prefix-NH pair.
    ///
    /// @retval     LA_STATUS_SUCCESS      Label stack and counter retrieved for this prefix-NH pair successfully.
    /// @retval     LA_STATUS_EINVAL       NH is invalid.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this prefix-NH pair.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_nh_lsp_properties(const la_next_hop* nh,
                                            la_mpls_label_vec_t& out_labels,
                                            const la_counter_set*& out_counter,
                                            lsp_counter_mode_e& out_counter_mode) const = 0;

    /// @brief Delete the prefix-NH pair entry.
    ///
    /// @param[in]  nh       NH to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Prefix-NH entry removed successfully.
    /// @retval     LA_STATUS_EINVAL    NH is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No relevant information found for this prefix-NH pair.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_nh_lsp_properties(const la_next_hop* nh) = 0;

    /// @brief Update the VPN label for this prefix-VRF pair.
    ///
    /// @param[in]  vrf      VRF to be updated.
    /// @param[in]  ip_version ip_version for which the labels are to be updated.
    /// @param[in]  labels   The labels to be updated for this prefix-VRF pair.
    ///
    /// @retval     LA_STATUS_SUCCESS         Labels for this prefix-VRF pair updated successfully.
    /// @retval     LA_STATUS_EINVAL          VRF is invalid.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED The number of labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, const la_mpls_label_vec_t& labels) = 0;

    /// @brief Get the VPN label for this prefix-VRF pair.
    ///
    /// @param[in]   vrf          The VRF.
    /// @param[in]   ip_version     ip_version for which the labels are to be retrieved.
    /// @param[out]  out_labels   The labels configured for this prefix-VRF pair.
    ///
    /// @retval     LA_STATUS_SUCCESS      Labels retrieved for this prefix-VRF pair successfully.
    /// @retval     LA_STATUS_EINVAL       VRF is invalid.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this prefix-VRF pair.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version, la_mpls_label_vec_t& out_labels) const = 0;

    /// @brief Delete the prefix-VRF pair entry.
    ///
    /// @param[in]  vrf      VRF to be removed.
    /// @param[in]  ip_version ip_version for which the labels are to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Prefix-VRF entry removed successfully.
    /// @retval     LA_STATUS_EINVAL    VRF is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTFOUND No relevant information found for this prefix-VRF pair.
    virtual la_status clear_vrf_properties(const la_vrf* vrf, la_ip_version_e ip_version) = 0;

    /// @brief Update the label stack and counter for this prefix-TE_tunnel pair.
    ///
    /// @param[in]  te_tunnel  TE_tunnel to be updated.
    /// @param[in]  labels     The MPLS labels to be updated for this prefix-TE_tunnel pair.
    /// @param[in]  counter    Counter to be updated for this prefix-TE_tunnel pair.
    ///
    /// @retval     LA_STATUS_SUCCESS         Label stack and counter for this prefix-TE_tunnel pair updated successfully.
    /// @retval     LA_STATUS_EINVAL          TE_tunnel is invalid.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Number of MPLS labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel,
                                                   const la_mpls_label_vec_t& labels,
                                                   la_counter_set* counter)
        = 0;

    /// @brief Get the label stack and counter for this prefix-TE_tunnel pair.
    ///
    /// @param[in]   te_tunnel    TE_tunnel to be updated.
    /// @param[out]  out_labels   The MPLS labels configured for this prefix-TE_tunnel pair.
    /// @param[out]  out_counter  Counter configured for this prefix-TE_tunnel pair.
    ///
    /// @retval     LA_STATUS_SUCCESS      Label stack and counter retrieved for this prefix-TE_tunnel pair successfully.
    /// @retval     LA_STATUS_EINVAL       TE_tunnel is invalid.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this prefix-TE_tunnel pair.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel,
                                                   la_mpls_label_vec_t& out_labels,
                                                   const la_counter_set*& out_counter) const = 0;

    /// @brief Delete the prefix-TE_tunnel pair entry.
    ///
    /// @param[in]  te_tunnel           TE_tunnel to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Prefix-TE_tunnel entry removed successfully.
    /// @retval     LA_STATUS_EINVAL    TE_tunnel is invalid.
    /// @retval     LA_STATUS_ENOTFOUND No relevant information found for this prefix-TE_tunnel pair.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_te_tunnel_lsp_properties(const la_te_tunnel* te_tunnel) = 0;

    /// @brief Query IPv6 Explicit Null Label imposition mode.
    ///
    /// @param[out] out_enabled         True if IPv6 Explicit NULL is enabled; false otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_explicit_null_enabled(bool& out_enabled) const = 0;

    /// @brief Enable/Disable IPv6 Explicit Null Label to be imposed on packets going through the LSP.
    ///
    /// @param[in]  enabled            True if IPv6 Explicit NULL should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipv6_explicit_null_enabled(bool enabled) = 0;

protected:
    ~la_prefix_object() override = default;
};

} // namespace silicon_one

#endif // __LA_PREFIX_OBJECT_H_
