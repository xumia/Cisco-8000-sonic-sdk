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

#ifndef __LA_METER_ACTION_PROFILE_H__
#define __LA_METER_ACTION_PROFILE_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"

/// @file
/// @brief Leaba Meter Action-Mapping profile API-s.
///
/// Defines API-s for managing a meter action-mapping profile.

namespace silicon_one
{

/// @addtogroup METER
/// @{

/// @brief      Meter action-mapping profile.
///
/// @details    A meter action-mapping profile defines the actions to be taken based on the meter and ethernet rate-limiter results.
///             Meter action profile is initialized with the following parameters for ALL <meter_color, rate_limiter_color> pairs:
///             {drop_enable = true, mark_ecn = true, packet_color = RED, rx_cgm_color = YELLOW}

class la_meter_action_profile : public la_object
{
public:
    /// @brief Set the action to be taken based on the meter and ethernet rate-limiter results.
    ///
    /// Defines the mapping from the meter and ethernet rate-limiter colors to actions to be applied.
    ///
    /// @param[in]  meter_color         The result color of the meter.
    /// @param[in]  rate_limiter_color  The result color of the rate-limiter.
    /// @param[in]  drop_enable         Drop the packet.
    /// @param[in]  mark_ecn            Set ECN in the packet.
    /// @param[in]  packet_color        The new packet color.
    /// @param[in]  rx_cgm_color        The color to indicate to the RX-CGM. Allowed values are #silicon_one::la_qos_color_e::GREEN
    /// and
    /// #silicon_one::la_qos_color_e::YELLOW.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid color parameters.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_action(la_qos_color_e meter_color,
                                 la_qos_color_e rate_limiter_color,
                                 bool drop_enable,
                                 bool mark_ecn,
                                 la_qos_color_e packet_color,
                                 la_qos_color_e rx_cgm_color)
        = 0;

    /// @brief Get the action to be taken based on the meter and ethernet rate-limiter results.
    ///
    /// @param[in]  meter_color         The result color of the meter.
    /// @param[in]  rate_limiter_color  The result color of the rate-limiter.
    /// @param[out] out_drop_enable     Setting of the drop packet to populate.
    /// @param[out] out_mark_ecn        Setting of the ECN in the packet to populate.
    /// @param[out] out_packet_color    The new packet color to populate.
    /// @param[out] out_rx_cgm_color    The color indication to the RX-CGM to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND No action is set.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_action(la_qos_color_e meter_color,
                                 la_qos_color_e rate_limiter_color,
                                 bool& out_drop_enable,
                                 bool& out_mark_ecn,
                                 la_qos_color_e& out_packet_color,
                                 la_qos_color_e& out_rx_cgm_color) const = 0;

protected:
    ~la_meter_action_profile() override = default;

}; // class la_meter_action_profile

/// @}

} // namespace silicon_one

#endif // __LA_METER_ACTION_PROFILE_H__
