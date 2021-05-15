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

#ifndef __LA_L2_MIRROR_COMMAND_H__
#define __LA_L2_MIRROR_COMMAND_H__

/// @file
/// @brief Leaba Layer 2 Mirror command API-s.
///
/// Defines API-s for managing and using Layer 2 Mirror command.
///

#include "api/system/la_mirror_command.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ethernet_types.h"

/// @addtogroup PACKET
/// @{

namespace silicon_one
{

/// @brief Layer 2 Mirror command to configure snoop/mirror traffic.
///
class la_l2_mirror_command : public la_mirror_command
{
public:
    /// @brief Retrieve the MAC associated with the command.
    ///
    /// @param[out] out_mac_addr        MAC associated with destination.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_mac_addr contains destination's MAC address.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_mac(la_mac_addr_t& out_mac_addr) const = 0;

    /// @brief Get mirror command VLAN.
    ///
    /// VLAN contains PCP/DEI and VLAN ID.
    ///
    /// @param[out] out_vlan_tag        A #la_vlan_tag_tci_t to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vlan_tag(la_vlan_tag_tci_t& out_vlan_tag) const = 0;

    /// @brief Get punt/inject port associated with this Punt destination.
    ///
    /// @return la_punt_inject_port* for this Punt destination.\n
    ///         nullptr if not initialized.
    virtual const la_punt_inject_port* get_punt_inject_port() const = 0;

    /// @brief Enable/disable mirror to truncate packet.
    ///
    /// Enabling this feature will limit the mirrored packet size up to 225B of the original packet.
    ///
    /// @param[in]      enabled                 True if truncation is enabled; false otherwise.
    ///
    /// @retval         LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval         LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_truncate(bool enabled) = 0;

    /// @brief Get truncate state of the mirror.
    ///
    /// @retval         bool                    True if truncation is enabled; false otherwise.
    virtual bool get_truncate() const = 0;

    /// @brief Set meter on mirror command.
    ///
    /// @param[in]  meter                     Meter object.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Meter is not supported.
    /// @retval     LA_STATUS_EINVAL          The meter type is invalid for this mirror command.
    /// @retval     LA_STATUS_EBUSY           A meter is already in use.
    /// @retval     LA_STATUS_EUNKNOWN        Internal error.
    virtual la_status set_meter(const la_meter_set* meter) = 0;

    /// @brief Get the attached meter to the mirror command.
    ///
    /// @param[out] out_meter                 Meter to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED Meter is not supported.
    /// @retval     LA_STATUS_EUNKNOWN        Internal error.
    virtual la_status get_meter(const la_meter_set*& out_meter) const = 0;

    /// @brief Set the mirror command's counter.
    ///
    /// @param[in]  counter             Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid set size.
    virtual la_status set_counter(la_counter_set* counter) = 0;

    /// @brief Get the mirror command's counter.
    ///
    /// @param[out] out_counter         Counter object.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    virtual la_status get_counter(la_counter_set*& out_counter) const = 0;

protected:
    ~la_l2_mirror_command() override = default;
};
}

/// @}

#endif // __LA_L2_MIRROR_COMMAND_H__
