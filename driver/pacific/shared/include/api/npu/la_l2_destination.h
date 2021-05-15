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

#ifndef __LA_L2_DESTINATION_H__
#define __LA_L2_DESTINATION_H__

#include "api/types/la_ethernet_types.h"
#include "api/types/la_object.h"

/// @file
/// @brief Leaba Layer 2 Destination API-s.
///
/// Layer 2 destinations are an abstract target to forward L2 traffic to.
/// They include L2 ports, Tunnels, LAG/Protection groups, and multicast groups.

namespace silicon_one
{

/// @addtogroup L2DEST
/// @{

/// @brief      Layer 2 destination base class.
///
/// @details    A layer 2 destination serves as a base class for L2 ports (#silicon_one::la_l2_port).\n
///             Layer 2 packets are forwarded through Switch/P2P connections to L2 destinations.\n
///             Specific destination types include #silicon_one::la_ethernet_port, #silicon_one::la_l2_service_port,
///             #la_vxlan_tunnel_t,
///             #la_l2_lag_group_t, #silicon_one::la_l2_protection_group and #silicon_one::la_l2_multicast_group.
class la_l2_destination : public la_object
{
protected:
    ~la_l2_destination() override = default;
};

/// @}
}

#endif
