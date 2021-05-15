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

#ifndef __LA_L3_VXLAN_NEXT_HOP_H__
#define __LA_L3_VXLAN_NEXT_HOP_H__

#include "api/npu/la_l3_destination.h"
#include "api/types/la_ethernet_types.h"
#include "api/types/la_ip_types.h"
#include "common/la_status.h"

/// @file
/// @brief Leaba VXLAN Next Hop API-s.
///
/// Defines API-s for managing a Next Hop [#silicon_one::la_vxlan_next_hop] object.
/// Next hop is composed of an L3 port, and a destination MAC.

namespace silicon_one
{

/// @addtogroup L3DEST_VXLAN_NEXT_HOP
/// @{

class la_vxlan_next_hop : public la_l3_destination
{

public:
    /// @brief Retrieve the MAC associated with the VXLAN next hop object.
    ///
    /// @param[out] out_mac_addr        Reference to #la_mac_addr_t to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains next hop's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Retrieve the port associated with the VXLAN next hop object.
    ///
    /// @param[out] out_port            Reference to #silicon_one::la_l3_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_port contains next hop's port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_router_port(la_l3_port*& out_port) const = 0;

    /// @brief Retrieve the vxlan port associated with the VXLAN next hop object.
    ///
    /// @param[out] out_vxlan_port      Reference to #silicon_one::la_l2_port to be populated.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_port contains next hop's vxlan port.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vxlan_port(la_l2_port*& out_vxlan_port) const = 0;

protected:
    ~la_vxlan_next_hop() override = default;
    /// @}
};
}

#endif // __LA_L3_VXLAN_NEXT_HOP_H__
