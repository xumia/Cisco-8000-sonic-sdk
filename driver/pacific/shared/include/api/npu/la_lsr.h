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

#ifndef __LA_LSR_H__
#define __LA_LSR_H__

/// @file
/// @brief Leaba MPLS LSR API-s.
///
/// Defines API-s for managing a Label Switching Router.

#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"

namespace silicon_one
{

/// @addtogroup MPLS_LSR
/// @{

class la_lsr : public la_object
{

public:
    /// @brief Add a route to the LSR.
    ///
    /// @param[in]  label                   MPLS label to route.
    /// @param[in]  destination             Destination.
    /// @param[in]  user_data               Opaque data associated with the route. Returned by the get-route function.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EEXIST        A route for the given label already exists.
    /// @retval     LA_STATUS_EINVAL        Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status add_route(la_mpls_label label, const la_l3_destination* destination, la_user_data_t user_data) = 0;

    /// @brief Add a route to the LSR with vrf.
    ///
    /// @param[in]  label                   MPLS label to route.
    /// @param[in]  vrf                     VRF for this MPLS label route.
    /// @param[in]  destination             Destination.
    /// @param[in]  user_data               Opaque data associated with the route. Returned by the get-route function.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EEXIST        A route for the given label already exists.
    /// @retval     LA_STATUS_EINVAL        Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status add_route(la_mpls_label label,
                                const la_vrf* vrf,
                                const la_l3_destination* destination,
                                la_user_data_t user_data)
        = 0;

    /// @brief Retrieve label entry from the LSR.
    ///
    /// @param[in]  label                  Label to retrieve.
    /// @param[out] out_mpls_route_info    Routing information.
    ///
    /// @retval     LA_STATUS_SUCCESS      Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND    No route exists for given label.
    /// @retval     LA_STATUS_EUNKNOWN     An unknown error occurred.
    virtual la_status get_route(la_mpls_label label, la_mpls_route_info& out_mpls_route_info) const = 0;

    /// @brief Modify label entry in the LSR.
    ///
    /// @param[in]  label               MPLS label to route.
    /// @param[in]  destination         Destination.
    ///
    /// @retval     LA_STATUS_SUCCESS   Route modified successfully.
    /// @retval     LA_STATUS_ENOTFOUND LSR does not have a route for the given label.
    /// @retval     LA_STATUS_EINVAL    Destination is invalid.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status modify_route(la_mpls_label label, const la_l3_destination* destination) = 0;

    /// @brief Delete a route from the LSR.
    ///
    /// @param[in]  label                 Label of the route to be deleted.
    ///
    /// @retval     LA_STATUS_SUCCESS     Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND   LSR does not have a route the given label.
    /// @retval     LA_STATUS_EUNKNOWN    An unknown error occurred.
    virtual la_status delete_route(la_mpls_label label) = 0;

    /// @brief Delete all routes from the LSR.
    ///
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status clear_all_routes() = 0;

    /// @brief Create a MPLS VPN decapsulator.
    ///
    /// The decapsulator is used for termination of a VPN MPLS tunnel.
    ///
    /// @param[in]     label                VPN label.
    /// @param[in]     vrf                  Associated VRF.
    /// @param[out]    out_mpls_vpn_decap   Return the newly created decapsulator object.
    ///
    /// @retval     LA_STATUS_SUCCESS       Decapsulator created successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status add_vpn_decap(la_mpls_label label, const la_vrf* vrf, la_mpls_vpn_decap*& out_mpls_vpn_decap) = 0;

    /// @brief Modify a MPLS VPN decapsulator.
    ///
    /// The decapsulator is used for termination of a VPN MPLS tunnel.
    ///
    /// @param[in]     label                VPN label.
    /// @param[in]     vrf                  Associated VRF.
    /// @param[in]     mpls_vpn_decap       Decapsulator object.
    ///
    /// @retval     LA_STATUS_SUCCESS       Decapsulator Modified successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status modify_vpn_decap(la_mpls_label label, const la_vrf* vrf, la_mpls_vpn_decap* mpls_vpn_decap) = 0;

    /// @brief Create a MPLS VPN decapsulator.
    ///
    /// The decapsulator is used for termination of a VPN MPLS tunnel.
    ///
    /// @param[in]     label                VPN label.
    /// @param[in]     vrf                  Associated VRF.
    /// @param[in]     rpfid                Associated RPF id
    /// @param[in]     bud_node             True indicates MLDP bud node, False indicates Tail node
    /// @param[out]    out_mldp_vpn_decap   Return the newly created decapsulator object.
    ///
    /// @retval     LA_STATUS_SUCCESS       Decapsulator created successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status add_vpn_decap(la_mpls_label label,
                                    const la_vrf* vrf,
                                    la_uint_t rpfid,
                                    bool bud_node,
                                    la_mldp_vpn_decap*& out_mldp_vpn_decap)
        = 0;

    /// @brief Modify a MPLS VPN decapsulator.
    ///
    /// The decapsulator is used for termination of a VPN MPLS tunnel.
    ///
    /// @param[in]     label                VPN label.
    /// @param[in]     vrf                  Associated VRF.
    /// @param[in]     rpfid                Associated RPF id
    /// @param[in]     bud_node             True indicates MLDP bud node, False indicates Tail node
    /// @param[in]     mldp_vpn_decap       The decapsulator object.
    ///
    /// @retval     LA_STATUS_SUCCESS       Decapsulator modified successfully.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status modify_vpn_decap(la_mpls_label label,
                                       const la_vrf* vrf,
                                       la_uint_t rpfid,
                                       bool bud_node,
                                       la_mldp_vpn_decap* mldp_vpn_decap)
        = 0;

    /// @brief Destroy a MPLS VPN decapsulator.
    ///
    /// @param[in]     mpls_vpn_decap   Decapsulator to be destroyed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Decapsulator destroyed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_vpn_decap(la_mpls_vpn_decap* mpls_vpn_decap) = 0;

    /// @brief Destroy a MLDP VPN decapsulator.
    ///
    /// @param[in]     mldp_vpn_decap   Decapsulator to be destroyed.
    ///
    /// @retval     LA_STATUS_SUCCESS   Decapsulator destroyed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status delete_vpn_decap(la_mldp_vpn_decap* mldp_vpn_decap) = 0;

protected:
    ~la_lsr() override = default;
};

/// @}

} // namespace silicon_one

#endif // __LA_LSR_H__
