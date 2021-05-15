// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_TE_TUNNEL_H__
#define __LA_TE_TUNNEL_H__

/// @file
/// @brief Leaba TE Tunnel API.
///
/// Defines API-s for managing a TE Tunnel.  These API-s can be used
/// for implmenting TE tunnels.

#include "api/npu/la_l3_destination.h"
#include "api/types/la_mpls_types.h"

namespace silicon_one
{

class la_te_tunnel : public la_l3_destination
{
public:
    /// @brief TE_tunnel type.
    enum class tunnel_type_e {
        NORMAL = 0,  ///< Supports IP traffic over a TE_tunnel.
        LDP_ENABLED, ///< Supports IP and MPLS LDP traffic over a TE_tunnel.
    };

    /// @brief Get TE tunnel's global ID.
    ///
    /// @return TE tunnel's global ID.
    virtual la_te_tunnel_gid_t get_gid() const = 0;

    /// @brief Get L3 destination for this TE tunnel.
    ///
    /// @retval The associated L3 destination for this TE tunnel.
    virtual const la_l3_destination* get_destination() const = 0;

    /// @brief Update the destination for this TE tunnel.
    ///
    /// @param[in]  destination         L3 destination the TE tunnel points to.
    ///
    /// @retval     LA_STATUS_SUCCESS   TE tunnel destination updated successfully.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_destination(const la_l3_destination* destination) = 0;

    /// @brief Update the label stack and counter for this TE_tunnel/NH pair.
    /// @brief Nexthop's are used to update the TE-tunnel labels.
    ///
    /// @param[in]  nh          NH to be updated.
    /// @param[in]  labels      Labels to be updated for this TE_tunnel-NH pair.
    /// @param[in]  counter     Counter to be updated for this TE_tunnel-NH pair.
    ///
    /// @retval     LA_STATUS_SUCCESS         Label stack and counter updated successfully.
    /// @retval     LA_STATUS_EINVAL          NH is invalid.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Number of MPLS labels to be updated is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        An unknown error occurred.
    virtual la_status set_nh_lsp_properties(const la_next_hop* nh, const la_mpls_label_vec_t& labels, la_counter_set* counter) = 0;

    /// @brief Get the label stack and counter for this TE_tunnel/NH pair.
    ///
    /// @param[in]   nh           NH to be updated.
    /// @param[out]  out_labels   The MPLS labels configured for this TE_tunnel-NH pair.
    /// @param[out]  out_counter  Counter configured for this TE_tunnel-NH pair.
    ///
    /// @retval     LA_STATUS_SUCCESS      Label stack and counter retrieved for this TE_tunnel-NH pair successfully.
    /// @retval     LA_STATUS_EINVAL       NH is invalid.
    /// @retval     LA_STATUS_ENOTFOUND    No relevant information found for this TE_tunnel-NH pair.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_nh_lsp_properties(const la_next_hop* nh,
                                            la_mpls_label_vec_t& out_labels,
                                            const la_counter_set*& out_counter) const = 0;

    /// @brief Clear the label stack and counters for TE-tunnel/NH pair.
    ///
    /// @param[in]  nh                  NH to be removed.
    ///
    /// @retval     LA_STATUS_SUCCESS   TE_tunnel-NH removed successfully.
    /// @retval     LA_STATUS_EINVAL    NH is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_nh_lsp_properties(const la_next_hop* nh) = 0;

    /// @brief Retrieve the type associated with the TE tunnel.
    ///
    /// @param[out] out_type        Reference to #tunnel_type_e to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_tunnel_type(tunnel_type_e& out_type) const = 0;

    /// @brief Set the type of the TE tunnel.
    ///
    /// @param[in]  type            Tunnel type to be set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EBUSY     Operation cannot be completed because the tunnel is in use.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_tunnel_type(tunnel_type_e type) = 0;

    /// @brief Query IPv6 Explicit Null Label imposition mode.
    ///
    /// @param[out] out_enabled         True if IPv6 Explicit NULL is enabled; false otherwise
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_ipv6_explicit_null_enabled(bool& out_enabled) const = 0;

    /// @brief Enable/Disable IPv6 Explicit Null Label to be imposed on packets going through the TE tunnel.
    ///
    /// @param[in]  enabled            True if IPv6 Explicit NULL should be enabled; false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_ipv6_explicit_null_enabled(bool enabled) = 0;

protected:
    ~la_te_tunnel() override = default;
};

} // namespace silicon_one

#endif // __LA_TE_TUNNEL_H__
