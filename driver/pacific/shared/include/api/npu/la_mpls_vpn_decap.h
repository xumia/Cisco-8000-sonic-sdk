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

#ifndef __LA_MPLS_VPN_DECAP_H__
#define __LA_MPLS_VPN_DECAP_H__

#include "api/types/la_ip_types.h"
#include "api/types/la_mpls_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba MPLS Tunnel Decapsulator API-s.
///
/// Defines API-s for managing MPLS tunnel decapsulators.

namespace silicon_one
{

class la_mpls_vpn_decap : public la_object
{
public:
    /// @brief counter offsets.
    enum class counter_offset_e {
        IPV4 = 0, /// Offset for L3 protocol type IPv4.
        IPV6,     /// Offset for L3 protocol type IPv6.
    };

    /// @brief  Return the VRF associated with the VPN decapsulator.
    ///
    /// @retval The VRF associated with the VPN decapsulator.
    virtual const la_vrf* get_vrf() const = 0;

    /// @brief  Return the label associated with the VPN decapsulator.
    ///
    /// @retval The label associated with the VPN decapsulator.
    virtual la_mpls_label get_label() const = 0;

    /// @brief Set the MPLS decap counter.
    ///
    /// Supported set size is 2 (count traffic per L3 protocol value defined in #counter_offset_e).
    /// Passing NULL counter removes an existing counter if there's one, and has no effect if there's none.
    /// If there's a counter already associated with this port then it is replaced by this function.
    ///
    /// @param[in]  counter                     Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL            Invalid set size.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS   counter is on a different device.
    virtual la_status set_counter(la_counter_set* counter) = 0;

    /// @brief Get the MPLS decap counter.
    ///
    /// @param[out] out_counter         Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_counter(la_counter_set*& out_counter) const = 0;

protected:
    ~la_mpls_vpn_decap() override = default;
};

} // namespace silicon_one

#endif // __LA_MPLS_VPN_DECAP_H__
