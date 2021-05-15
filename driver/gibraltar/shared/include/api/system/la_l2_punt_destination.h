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

#ifndef __LA_L2_PUNT_DESTINATION_H__
#define __LA_L2_PUNT_DESTINATION_H__

/// @file
/// @brief Leaba Layer 2 Punt destination API-s.
///
/// Defines API-s for managing and using Layer 2 Punt destination.
///

#include "api/system/la_punt_destination.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"

/// @addtogroup PACKET
/// @{

namespace silicon_one
{

/// @brief Layer 2 Punt destination to configure punt traffic.
///
class la_l2_punt_destination : public la_punt_destination
{
public:
    /// @brief Get punt destination's global ID.
    ///
    /// @return L2 Punt destination's global ID.
    virtual la_l2_punt_destination_gid_t get_gid() const = 0;

    /// @brief Retrieve the MAC associated with the destination.
    ///
    /// @param[out] out_mac_addr        MAC associated with destination.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains destination's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Get destination's VLAN.
    ///
    /// VLAN contains PCP/DEI and VLAN ID.
    ///
    /// @param[out] out_vlan_tag        A #la_vlan_tag_tci_t to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_vid contains destination's VLAN.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vlan_tag(la_vlan_tag_tci_t& out_vlan_tag) const = 0;

protected:
    ~la_l2_punt_destination() override = default;
};
}

/// @}

#endif // __LA_L2_PUNT_DESTINATION_H__
