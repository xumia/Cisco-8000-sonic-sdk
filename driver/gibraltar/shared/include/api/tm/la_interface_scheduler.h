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

#ifndef __LA_INTERFACE_SCHEDULER_H__
#define __LA_INTERFACE_SCHEDULER_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Interface Scheduler API-s.
///
/// Defines API-s for managing Interface Scheduler's objects.

/// @addtogroup TM_SCH
/// @{

namespace silicon_one
{

/// @brief      Interface scheduler.
///
/// @details    An Interface scheduler defines credit and transmit priorities, weights and rate limits for an interface:
///             MAC port, Recycle port, PCI port.
class la_interface_scheduler : public la_object
{
public:
    /// @brief Retrieve credit Committed Information Rate.
    ///
    /// @param[out]  out_rate                Rate to populate, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_credit_cir(la_rate_t& out_rate) const = 0;

    /// @brief Set credit Committed Information Rate.
    ///
    /// In the Pacific the rate is implemented in gbps. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  rate                Rate to set, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_credit_cir(la_rate_t rate) = 0;

    /// @brief Retrieve transmit Committed Information Rate.
    ///
    /// @param[out] out_rate                Rate retrieved, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_transmit_cir(la_rate_t& out_rate) const = 0;

    /// @brief Set transmit Committed Information Rate.
    ///
    /// In the Pacific the rate is implemented in gbps. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  rate                Rate to set, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_transmit_cir(la_rate_t rate) = 0;

    /// @brief Get credit scheduler's Excess/Peak Information Rate.
    ///
    /// Gets the mode and rate for a scheduler's EIR/PIR rate limiter.
    /// Either EIR or PIR are configured, not both.
    ///
    /// @param[out]  out_rate                Rate in bps.
    /// @param[out]  out_is_eir              Rate is configured as EIR if true, PIR otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_credit_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const = 0;

    /// @brief Set credit scheduler's Excess/Peak Information Rate.
    ///
    /// Sets the mode and rate for a scheduler's EIR/PIR rate limiter.
    /// Either EIR or PIR are configured, not both.
    /// In the Pacific the rate is implemented in gbps. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  rate                Rate to set in bps.
    /// @param[in]  is_eir              Rate is configured as EIR if true, PIR otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note By default the mode is PIR and PIR equals to CIR (Committed Information Rate)
    virtual la_status set_credit_eir_or_pir(la_rate_t rate, bool is_eir) = 0;

    /// @brief Get transmit scheduler's Excess/Peak Information Rate.
    ///
    /// Gets the mode and rate for a scheduler's EIR/PIR rate limiter.
    /// Either EIR or PIR are configured, not both.
    ///
    /// @param[out]  out_rate                Rate in bps.
    /// @param[out]  out_is_eir              Rate is configured as EIR if true, PIR otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_transmit_eir_or_pir(la_rate_t& out_rate, bool& out_is_eir) const = 0;

    /// @brief Set transmit scheduler's Excess/Peak Information Rate.
    ///
    /// Sets the mode and rate for a scheduler's EIR/PIR rate limiter.
    /// Either EIR or PIR are configured, not both.
    /// In the Pacific the rate is implemented in gbps. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  rate                Rate to set in bps.
    /// @param[in]  is_eir              Rate is configured as EIR if true, PIR otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    ///
    /// @note By default the mode is PIR and PIR equals to CIR (Committed Information Rate)
    virtual la_status set_transmit_eir_or_pir(la_rate_t rate, bool is_eir) = 0;

    /// @brief Retrieve Committed credits weight.
    ///
    /// When multiple system ports compete for CIR credits, credits are distributed proportionally
    /// to each port's weight.
    ///
    /// @param[out] out_weight              Retrieved weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_cir_weight(la_wfq_weight_t& out_weight) const = 0;

    /// @brief Set Committed credits weight.
    ///
    /// When multiple system ports compete for CIR credits, credits are distributed proportionally
    /// to each port's weight.
    ///
    /// @param[in]  weight              Weight to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight updated successfully.
    /// @retval     LA_STATUS_EINVAL    Weight is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_cir_weight(la_wfq_weight_t weight) = 0;

    /// @brief Retrieve Excess credits weight.
    ///
    /// When multiple system ports compete for EIR credits, credits are distributed proportionally
    /// to each port's weight.
    ///
    /// @param[out] out_weight              Retrieved weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_eir_weight(la_wfq_weight_t& out_weight) const = 0;

    /// @brief Set Excess credits weight.
    ///
    /// When multiple system ports compete for EIR credits, credits are distributed proportionally
    /// to each port's weight.
    ///
    /// @param[in]  weight              Weight to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight updated successfully.
    /// @retval     LA_STATUS_EINVAL    Weight is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_eir_weight(la_wfq_weight_t weight) = 0;

protected:
    ~la_interface_scheduler() = default;
}; // class la_interface_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_INTERFACE_SCHEDULER_H__
