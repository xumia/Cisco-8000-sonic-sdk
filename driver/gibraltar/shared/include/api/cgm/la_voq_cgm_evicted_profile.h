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

#ifndef __LA_VOQ_CGM_EVICTED_PROFILE_H__
#define __LA_VOQ_CGM_EVICTED_PROFILE_H__

#include "api/types/la_cgm_types.h"
#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_qos_types.h"

/// @file
/// @brief Leaba Virtual Output Queue Congestion Management evicted profile API-s.
///
/// Defines API-s for managing a VOQ CGM evicted profile.

namespace silicon_one
{

/// @addtogroup CGM_VOQ_EVICTED_PROFILE
/// @{

/// @brief      Virtual Output Queue Congestion Management evicted profile.
///
/// @details    A VOQ CGM evicted profile defines the packet buffering, congestion management behavior of an evicted VOQ.
///             Based on the VOQ buffer state and packets color, the behavior of a VOQ buffer for an incoming packet can be one of
///             the following:
///                1. Evict the packet for storage in HBM.
///                3. Drop the packet.
///

class la_voq_cgm_evicted_profile : public la_object
{
public:
    /// @brief Set the evicted VOQs drop behavior.
    ///
    /// Sets the evicted VOQs drop behavior for an incoming packet based on the SMS and evicted buffers states.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evicted_buffers_key
    ///
    /// @param[in]  val         The val is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evicted_buffers_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status set_sms_evicted_buffers_drop_behavior(const la_voq_sms_evicted_buffers_key& key,
                                                            const la_voq_sms_evicted_buffers_drop_val& val)
        = 0;

    /// @brief Get the evicted VOQs drop behavior.
    ///
    /// Gets the evicted VOQs drop behavior for an incoming packet based on the SMS and evicted buffers states.
    ///
    /// @param[in]  key         The key is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evicted_buffers_key
    ///
    /// @param[in]  out_val     The val is architecture-dependent.
    ///                         Pacific: Not supported in hardware.
    ///                         Gibraltar: #silicon_one::la_voq_sms_evicted_buffers_drop_val
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE               Quantization regions are out of range.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    /// @retval     LA_STATUS_ENOTIMPLEMENTED           The functionality is not implemented.
    virtual la_status get_sms_evicted_buffers_drop_behavior(const la_voq_sms_evicted_buffers_key& key,
                                                            la_voq_sms_evicted_buffers_drop_val& out_val) const = 0;

    /// @brief Set default behavior values for evicted VOQs.
    ///
    /// Configure the profile behavior to generic default values.
    ///
    /// @note: The default values might change. For consistent behavior configure explicitly using
    /// #silicon_one::la_voq_cgm_evicted_profile::set_sms_evicted_buffers_drop_behavior.
    ///
    /// @retval     LA_STATUS_SUCCESS                   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN                  An unknown error occurred.
    virtual la_status set_default_behavior() = 0;

    /// @}
protected:
    ~la_voq_cgm_evicted_profile() override = default;
}; // class la_voq_cgm_evicted_profile

/// @}

} // namespace silicon_one

#endif // __LA_VOQ_CGM_EVICTED_PROFILE_H__
