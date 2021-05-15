// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_LOGICAL_PORT_SCHEDULER_H__
#define __LA_LOGICAL_PORT_SCHEDULER_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Logical port Scheduler API-s.
///
/// Defines API-s for managing logical port scheduler's objects.

/// @addtogroup TM_SCH
/// @{

namespace silicon_one
{

/// @brief      Logical port scheduler.
///
/// @details    A logical port scheduler defines scheduling priorities,
///             weights and rate limits for up to 512 output queues that are part of the given system port.
class la_logical_port_scheduler : public la_object
{
public:
    /// @brief Retrieve all the attached Output Queues and their priority group.
    ///
    /// @param[out] out_oq_vector              Retrieved output queues attached to logical port.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_attached_oqcs(la_oq_pg_vec_t& out_oq_vector) const = 0;

    /// @brief Attach an OQ scheduler to a logical port scheduler.
    ///
    /// @param[in]  oqcs                       Output queue scheduler to attach.
    /// @param[in]  group_id                   Logical port scheduler group.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL           Group ID is out of range.
    /// @retval     LA_STATUS_ERESOURCE        Maximum number of OQ schedulers attached to logical port scheduler.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    ///
    /// @note   Output queues for this API are provided from the IFG-level set of queues,
    ///         with some overlapping with the static TM port schedulers' output queues.
    virtual la_status attach_oqcs(la_output_queue_scheduler* oqcs, la_vsc_gid_t group_id) = 0;

    /// @brief Detach an OQ scheduler from a logical port scheduler.
    ///
    /// @param[in]  oqcs                       Output queue scheduler to detach.
    ///
    /// @retval     LA_STATUS_SUCCESS          Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL           oqcs is null pointer.
    /// @retval     LA_STATUS_ENOTFOUND        oqcs is not attached to this lpse.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    ///
    /// @note   Output queues for this API are provided from the IFG-level set of queues,
    ///         with some overlapping with the static TM port schedulers' output queues.
    virtual la_status detach_oqcs(la_output_queue_scheduler* oqcs) = 0;

    /// @brief Retrieve a logical port scheduler's group Committed credits weight as set by the user.
    ///
    /// When multiple groups compete for CIR credits, credits are distributed proportionally
    /// to each groups's weight.
    ///
    /// @param[in]  group_id                   Group ID.
    /// @param[out] out_weight                 Retrieved weight.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS          Weight size retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           Group is out of range.
    virtual la_status get_group_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Retrieve a logical port scheduler's group Committed credits weight.
    ///
    /// Return the group's actual CIR credits weight as written to the device.
    ///
    /// @param[in]  group_id                   Group ID.
    /// @param[out] out_weight                 Retrieved weight.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS          Weight size retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           Group is out of range.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_group_actual_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Set a logical port scheduler's group Committed credits weight.
    ///
    /// When multiple groups compete for CIR credits, credits are distributed proportionally
    /// to each groups's weight.
    ///
    /// @param[in]  group_id                   Group ID.
    /// @param[in]  weight                     Weight to set.
    ///
    /// @retval     LA_STATUS_SUCCESS          Weight updated successfully.
    /// @retval     LA_STATUS_EINVAL           Group is out of range or weight is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_group_cir_weight(la_vsc_gid_t group_id, la_wfq_weight_t weight) = 0;

    /// @brief Retrieve a logical port scheduler's group Excess credits weight as set by the user.
    ///
    /// When multiple groups compete for EIR credits, credits are distributed proportionally
    /// to each groups's weight.
    ///
    /// @param[in]  group_id                   Group ID.
    /// @param[out] out_weight                 Retrieved weight.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS          Weight retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           Group is out of range.
    virtual la_status get_group_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Retrieve a logical port scheduler's group Excess credits weight.
    ///
    /// Return the group's actual EIR credits weight as written to the device.
    ///
    /// @param[in]  group_id                   Group ID.
    /// @param[out] out_weight                 Retrieved weight.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS          Weight size retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           Group is out of range.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_group_actual_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Set a logical port scheduler's group Excess credits weight.
    ///
    /// When multiple groups compete for EIR credits, credits are distributed proportionally
    /// to each groups's weight.
    ///
    /// @param[in]  group_id                   Group ID.
    /// @param[in]  weight                     Weight to set.
    ///
    /// @retval     LA_STATUS_SUCCESS          Weight updated successfully.
    /// @retval     LA_STATUS_EINVAL           Group is out of range.
    ///                                        Weight is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_group_eir_weight(la_vsc_gid_t group_id, la_wfq_weight_t weight) = 0;

    /// @brief Retrieve a logical port scheduler's output queue Committed Information Rate.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[out] out_rate                   Retrieved rate, in bps.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS          Rate retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           oqcs is null pointer.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_oqcs_cir(la_output_queue_scheduler* oqcs, la_rate_t& out_rate) const = 0;

    /// @brief Set a logical port scheduler's output queue Committed Information Rate.
    ///
    /// In the Pacific the rate is implemented with variable precision. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[in]  rate                       Rate to set, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS          Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL           oqcs is null pointer or rate is unsupported.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_oqcs_cir(la_output_queue_scheduler* oqcs, la_rate_t rate) = 0;

    /// @brief Retrieve a logical port scheduler's output queue burst size.
    ///
    /// Controls the size of the credits bucket.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[out] out_burst                  Burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS          Burst size retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           oqcs is null pointer.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_oqcs_burst_size(la_output_queue_scheduler* oqcs, size_t& out_burst) const = 0;

    /// @brief Set a logical port scheduler's output queue burst size.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[in]  burst                      Burst size to configure.
    ///
    /// @retval     LA_STATUS_SUCCESS          Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL           oqcs is null pointer or burst is unsupported.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_oqcs_burst_size(la_output_queue_scheduler* oqcs, size_t burst) = 0;

    /// @brief Retrieve a logical port scheduler's output queue Excess/Peak Information Rate.
    ///
    /// Retrieves the mode and rate for a logical port scheduler's EIR/PIR output queue rate limiter.
    /// Per output queue, either EIR or PIR are configured, not both.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[out] out_rate                   Retrieved rate, in bps.
    /// @param[out] out_is_eir                 Rate is configured as EIR if true, PIR otherwise.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS          Rate retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           oqcs is null pointer.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_oqcs_eir_or_pir(la_output_queue_scheduler* oqcs, la_rate_t& out_rate, bool& out_is_eir) const = 0;

    /// @brief Set a logical port scheduler's output queue Excess/Peak Information Rate.
    ///
    /// Sets the mode and rate for a logical port scheduler's EIR/PIR output queue rate limiter.
    /// Per output queue, either EIR or PIR are configured, not both.
    /// In the Pacific the rate is implemented with variable precision. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[in]  rate                       Rate to set, in bps.
    /// @param[in]  is_eir                     Rate is configured as EIR if true, PIR otherwise.
    ///
    /// @retval     LA_STATUS_SUCCESS          Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL           Scheduler is corrupt/invalid, oqcs is null pointer or rate is unsupported.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_oqcs_eir_or_pir(la_output_queue_scheduler* oqcs, la_rate_t rate, bool is_eir) = 0;

    /// @brief Retrieve a logical port scheduler's output queue Excess/Peak burst size.
    ///
    /// Retrieves the max bucket size for a logical port scheduler's EIR/PIR output queue.
    /// Per output queue, either EIR or PIR are configured, not both.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[out] out_burst                  Burst size to populate.
    ///
    /// @return     status.
    /// @retval     LA_STATUS_SUCCESS          Burst size retrieved successfully.
    /// @retval     LA_STATUS_EINVAL           oqcs is null pointer.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device.
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status get_oqcs_eir_or_pir_burst_size(la_output_queue_scheduler* oqcs, size_t& out_burst) const = 0;

    /// @brief Set a logical port scheduler's output queue Excess/Peak burst size.
    ///
    /// @param[in]  oqcs                       Output queue scheduler.
    /// @param[in]  burst                      Burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS          Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL           Scheduler is corrupt/invalid or oqcs is null pointer.
    /// @retval     LA_STATUS_EOUTOFRANGE      burst is out of range.
    /// @retval     LA_STATUS_EDIFFERENT_DEVS  output queue scheduler is on a different device
    /// @retval     LA_STATUS_EUNKNOWN         An unknown error occurred.
    virtual la_status set_oqcs_eir_or_pir_burst_size(la_output_queue_scheduler* oqcs, size_t burst) = 0;

protected:
    ~la_logical_port_scheduler() override = default;
}; // class la_logical_port_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_LOGICAL_PORT_SCHEDULER_H__
