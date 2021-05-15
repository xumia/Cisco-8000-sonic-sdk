// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_RX_CGM_SQ_PROFILE_H__
#define __LA_RX_CGM_SQ_PROFILE_H__

#include "api/types/la_cgm_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"
#include <chrono>

/// @file
/// @brief Leaba Source Queue Congestion Management profile API-s.
///
/// Defines API-s for managing a RXCGM SQ Profile.

namespace silicon_one
{

/// @addtogroup RX_CGM_SQ_PROFILE
/// @{

/// @brief      Source Queue Congestion Management profile.
///
/// @details    A SQ profile defines the thresholds and policies for actions on a source queue in RX CGM.
///             A source queue is derived by a port plus a traffic class; thus there are 8 SQ-s per port.
///             Congestion thresholds can be defined for an SQ, and actions can be taken based on the profile thresholds,
///             plus additional thresholds. An SQ profile can:
///             1. Indicate flow control on a queue
///             2. Mark a packet as drop-yellow
///             3. Mark a packet as drop-green
///

class la_rx_cgm_sq_profile : public la_object
{
public:
    /// @brief Internal ID used for the default profile
    enum { LA_RX_CGM_DEFAULT_PROFILE_ID = 0xF };

    /// @brief Set the quantization thresholds for the size in bytes for this SQ profile.
    ///
    /// Set the quantization thresholds that translates the instantaneous size in bytes that this SQ
    /// consumes to regions.
    ///
    /// @param[in]  thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization updated successfully.
    /// @retval     LA_STATUS_EINVAL    Quantization thresholds are out of range or decreasing.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_thresholds(const la_rx_cgm_sq_profile_thresholds& thresholds) = 0;

    /// @brief Get the quantization thresholds for the size in bytes for this SQ profile.
    ///
    /// @param[in]  out_thresholds          Bytes quantization thresholds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Quantization retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_thresholds(la_rx_cgm_sq_profile_thresholds& out_thresholds) const = 0;

    /// @brief   Set the RXCGM policy for a given combination of statuses.
    ///
    /// An RXCGM policy configures actions to be taken based on a combination of three statuses - the status
    /// of CounterA, the status of the SQ counter, and the status of the SQG counter. The thresholds
    /// programmed for each determine their status, which can range from 0-3. The policy can decide
    /// whether to assert flow control, mark as drop yellow, or mark as drop green.
    ///
    /// @param[in] status                        Set of statuses to program this policy for.
    /// @param[in] flow_control                  True if assert flow control for this given set of statuses, false otherwise.
    /// @param[in] drop_yellow                   True if mark drop yellow for this given set of statuses, false otherwise.
    /// @param[in] drop_green                    True if mark drop green for this given set of statuses, false otherwise.
    /// @param[in] fc_trig                       True if trigger flow control state, false otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Policy successfully set.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter supplied.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_rx_cgm_policy(const la_rx_cgm_policy_status& status,
                                        bool flow_control,
                                        bool drop_yellow,
                                        bool drop_green,
                                        bool fc_trig)
        = 0;

    /// @brief   Get the RXCGM policy for a given combination of statuses.
    ///
    /// @param[in]    status                  Set of statuses to get the policy for.
    /// @param[out] out_flow_control          True if flow control is set for given statuses.
    /// @param[out] out_drop_yellow           True if mark drop yellow is set for given statuses.
    /// @param[out] out_drop_green            True if mark drop green is set for given statuses.
    /// @param[out] out_fc_trig               True if trigger FC for given statuses.
    ///
    /// @retval     LA_STATUS_SUCCESS   Policy retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter supplied.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_rx_cgm_policy(const la_rx_cgm_policy_status& status,
                                        bool& out_flow_control,
                                        bool& out_drop_yellow,
                                        bool& out_drop_green,
                                        bool& out_fc_trig) const = 0;

    /// @brief   Set the headroom timer value for this port.
    ///
    /// This API programs the HR timer for any SQ-s using this profile. The resolution of the HR timer internally
    /// is 4ns. This API will fail if the HR management mode is set to threshold.
    ///
    /// @param[in] time        Time to set the HR timer to. Given in nanoseconds.
    ///
    /// @retval     LA_STATUS_SUCCESS   Timer successfully set.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter supplied or HR management mode is incorrect.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_headroom_timer(std::chrono::nanoseconds time) = 0;

    /// @brief   Set the headroom threshold value for this port.
    ///
    /// This API programs the HR threshold for any SQ-s using this profile. Internally, the resolution of the HR
    /// threshold value is in buffers. This API will fail if the HR management mode is set to timer.
    ///
    /// @param[in] threshold        Threshold to set. Given in bytes.
    ///
    /// @retval     LA_STATUS_SUCCESS   Threshold successfully set.
    /// @retval     LA_STATUS_EINVAL    Invalid parameter supplied or HR management mode is incorrect.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_pfc_headroom_threshold(la_uint_t threshold) = 0;

    /// @brief   Get the headroom value for this port.
    ///
    /// The returned value will represent either bytes, or nanoseconds, dependent on the currently
    /// configured HR management mode.
    ///
    /// @param[out] out_value        Current HR value. Given as either bytes or nanoseconds
    ///
    /// @retval     LA_STATUS_SUCCESS   Threshold successfully retrieved.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_pfc_headroom_value(la_uint_t& out_value) const = 0;

protected:
    ~la_rx_cgm_sq_profile() override = default;
}; // class la_rx_cgm_sq_profile

/// @}

} // namespace silicon_one

#endif // __LA_RX_CGM_SQ_PROFILE_H__
