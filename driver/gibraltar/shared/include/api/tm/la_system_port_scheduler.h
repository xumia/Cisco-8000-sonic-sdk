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

#ifndef __LA_SYSTEM_PORT_SCHEDULER_H__
#define __LA_SYSTEM_PORT_SCHEDULER_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba System port Scheduler API-s.
///
/// Defines API-s for managing system port scheduler's objects.

/// @addtogroup TM_SCH
/// @{

namespace silicon_one
{

/// @brief      System port scheduler.
///
/// @details    A System port scheduler defines scheduling priorities,
///             weights and rate limits for all 8 output queues that are part of the given system port.
class la_system_port_scheduler : public la_object
{
public:
    /// @brief  System port scheduler priority group.
    ///
    /// @details    Each System port scheduler has 8 different scheduling groups,
    ///             with credits being distributed between the groups based on weights.
    ///             Inside each group, credits are distributed in a round-robin manner.
    enum class priority_group_e {
        SINGLE0 = 0, ///< Single output queue scheduler for OQCS 0
        SINGLE1,     ///< Single output queue scheduler for OQCS 1
        SINGLE2,     ///< Single output queue scheduler for OQCS 2
        SINGLE3,     ///< Single output queue scheduler for OQCS 3
        SP2,         ///< Strict priority between 2 output queue schedulers
        SP4,         ///< Strict priority between 4 output queue schedulers
        SP6,         ///< Strict priority between 6 output queue schedulers
        SP8,         ///< Strict priority between 8 output queue schedulers
        NONE,
    };

    /// @brief Retrieve priority propagation mode.
    ///
    /// When enabled, a system port scheduler requests credits separately for CIR and EIR traffic.
    /// When disabled, a single request is made, combining both.
    ///
    /// @param[out] out_enabled         Priority propagation mode retrieved.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_priority_propagation(bool& out_enabled) const = 0;

    /// @brief Set priority propagation mode for a system port scheduler.
    ///
    /// When enabled, a system port scheduler requests credits separately for CIR and EIR traffic.
    /// When disabled, a single request is made, combining both.
    ///
    /// @param[in]  enabled             Priority propagation mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_priority_propagation(bool enabled) = 0;

    /// @brief Retrieved logical port mode .
    ///
    /// When enabled, a system port scheduler lower output queues are allocated as logical port queues.
    /// Each logical port supports up to 512 output queue schedulers.
    ///
    /// @param[out]  out_enabled        Retrieved Logical port mode.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_logical_port_enabled(bool& out_enabled) const = 0;

    /// @brief Set logical port mode for a system port scheduler.
    ///
    /// When enabled, a system port scheduler lower output queues are allocated as logical port queues.
    /// Each logical port supports up to 512 output queue schedulers.
    ///
    /// @param[in]  enabled             Logical port mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode set successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_logical_port_enabled(bool enabled) = 0;

    /// @brief Retrieve a system port scheduler's OQ Priority group.
    ///
    /// Each priority group is a strict-priority scheduler.
    /// CIR credits are distributed in a round-robin manner between priority groups.
    /// EIR credits are distributed in a weighted manner between priority groups.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[out] out_pg              Priority group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Priority group retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Output queue is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_oq_priority_group(la_oq_id_t oid, priority_group_e& out_pg) const = 0;

    /// @brief Set a system port scheduler's OQ Priority group.
    ///
    /// Each priority group is a strict-priority scheduler.
    /// CIR credits are distributed in a round-robin manner between priority groups.
    /// EIR credits are distributed in a weighted manner between priority groups.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[in]  pg                  Priority group.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Output queue is out of range.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_oq_priority_group(la_oq_id_t oid, priority_group_e pg) = 0;

    /// @brief Retrieve OQ Credit Peak Information Rate.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[out] out_rate            Retrieved rate, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_credit_pir(la_oq_id_t oid, la_rate_t& out_rate) const = 0;

    /// @brief Set OQ Credit Peak Information Rate.
    ///
    /// In the Pacific the rate is implemented with variable precision. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[in]  rate                Rate to set, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_credit_pir(la_oq_id_t oid, la_rate_t rate) = 0;

    /// @brief Get credit scheduler's burst size.
    ///
    /// Controls the size of the credits bucket.
    ///
    /// @param[in]  oid                 Output Queue ID to get its burst size.
    /// @param[out] out_burst           Burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Burst size retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_credit_pir_burst_size(la_oq_id_t oid, size_t& out_burst) const = 0;

    /// @brief Set credit scheduler's burst size.
    ///
    /// @param[in]  oid                     Output Queue ID to configure.
    /// @param[in]  burst                   Burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS       Rate updated successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Burst size is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_credit_pir_burst_size(la_oq_id_t oid, size_t burst) = 0;

    /// @brief Retrieve OQ transmit Peak Information Rate.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[out] out_rate            Retrieved rate, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_transmit_pir(la_oq_id_t oid, la_rate_t& out_rate) const = 0;

    /// @brief Set OQ transmit Peak Information Rate.
    ///
    /// In the Pacific the rate is implemented with variable precision. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[in]  rate                Rate to set, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_transmit_pir(la_oq_id_t oid, la_rate_t rate) = 0;

    /// @brief Get transmit scheduler's burst size.
    ///
    /// Controls the size of the transmits bucket.
    ///
    /// @param[in]  oid                 Output Queue ID to get its burst size.
    /// @param[out] out_burst           Burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Burst size retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_transmit_pir_burst_size(la_oq_id_t oid, size_t& out_burst) const = 0;

    /// @brief Set transmit scheduler's burst size.
    ///
    /// @param[in]  oid                     Output Queue ID to configure.
    /// @param[in]  burst                   Burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS       Rate updated successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Burst size is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_transmit_pir_burst_size(la_oq_id_t oid, size_t burst) = 0;

    /// @brief Retrieve OQ transmit unicast/multicast queue weights.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[out] out_ucw             Unicast weight.
    /// @param[out] out_mcw             Multicast weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weights retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t& out_ucw, la_wfq_weight_t& out_mcw) const = 0;

    /// @brief Set OQ transmit unicast/multicast queue weights.
    ///
    /// @param[in]  oid                 Output Queue ID.
    /// @param[in]  ucw                 Unicast weight.
    /// @param[in]  mcw                 Multicast weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weights updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_transmit_uc_mc_weight(la_oq_id_t oid, la_wfq_weight_t ucw, la_wfq_weight_t mcw) = 0;

    /// @brief Retrieve a system port scheduler's priority group Peak Information Rate.
    ///
    /// @param[in]  pg                  Priority group.
    /// @param[out] out_rate            Retrieved rate, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_priority_group_credit_cir(priority_group_e pg, la_rate_t& out_rate) const = 0;

    /// @brief Set a system port scheduler's priority group Peak Information Rate.
    ///
    /// In the Pacific the rate is implemented with variable precision. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  pg                  Priority group.
    /// @param[in]  rate                Rate to set, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_priority_group_credit_cir(priority_group_e pg, la_rate_t rate) = 0;

    /// @brief Retrieve a system port scheduler's priority group burst size.
    ///
    /// Controls the size of the credits bucket.
    ///
    /// @param[in]  pg                  Priority group to get its burst size.
    /// @param[out] out_burst           Burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_priority_group_credit_burst_size(priority_group_e pg, size_t& out_burst) const = 0;

    /// @brief Set a system port scheduler's priority group burst size.
    ///
    /// @param[in]  pg                      Priority group to configure.
    /// @param[in]  burst                   Burst size to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Rate updated successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Burst size is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_priority_group_credit_burst_size(priority_group_e pg, size_t burst) = 0;

    /// @brief Retrieve a system port scheduler's priority group Peak Information Rate.
    ///
    /// @param[in]  pg                  Priority group.
    /// @param[out] out_rate            Retrieved rate, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_priority_group_transmit_cir(priority_group_e pg, la_rate_t& out_rate) const = 0;

    /// @brief Set a system port scheduler's priority group Peak Information Rate.
    ///
    /// In the Pacific the rate is implemented with variable precision. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  pg                  Priority group.
    /// @param[in]  rate                Rate to set, in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate updated successfully.
    /// @retval     LA_STATUS_EINVAL    Rate is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_priority_group_transmit_cir(priority_group_e pg, la_rate_t rate) = 0;

    /// @brief Retrieve a system port scheduler's priority group burst size.
    ///
    /// Controls the size of the transmits bucket.
    ///
    /// @param[in]  pg                  Priority group to get its burst size.
    /// @param[out] out_burst           Burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Rate retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_priority_group_transmit_burst_size(priority_group_e pg, size_t& out_burst) const = 0;

    /// @brief Set a system port scheduler's priority group burst size.
    ///
    /// @param[in]  pg                      Priority group to configure.
    /// @param[in]  burst                   Burst size to set.
    ///
    /// @retval     LA_STATUS_SUCCESS       Rate updated successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Burst size is out of range.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_priority_group_transmit_burst_size(priority_group_e pg, size_t burst) = 0;

    /// @brief Retrieve a system port scheduler's priority group Excess credits weight as set by the user.
    ///
    /// When multiple priority groups compete for EIR credits, credits are distributed proportionally to each group's weight.
    ///
    /// @param[in]  pg                  Priority group.
    /// @param[out] out_weight          Retrieved weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_priority_group_eir_weight(priority_group_e pg, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Set a system port scheduler's priority group Excess credits weight.
    ///
    /// When multiple priority groups compete for EIR credits, credits are distributed proportionally to each group's weight.
    ///
    /// @param[in]  pg                  Priority group.
    /// @param[in]  weight              Weight to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight updated successfully.
    /// @retval     LA_STATUS_EINVAL    Weight is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_priority_group_eir_weight(priority_group_e pg, la_wfq_weight_t weight) = 0;

    /// @brief Retrieve a system port scheduler's priority group Excess credits weight.
    ///
    /// Return the actual priority group's weight as written to the device.
    ///
    /// @param[in]  pg                  Priority group.
    /// @param[out] out_weight          Retrieved weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_priority_group_eir_actual_weight(priority_group_e pg, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Get an Output Queue scheduler.
    ///
    /// @param[in]  oqid                Output queue ID.
    /// @param[out] out_oq_sch          Pointer to #silicon_one::la_output_queue_scheduler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_oq_sch contains the OQ scheduler.
    /// @retval     LA_STATUS_EINVAL    Output queue ID is out of range;
    ///                                 out_oq_sch is NULL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_output_queue_scheduler(la_oq_id_t oqid, la_output_queue_scheduler*& out_oq_sch) const = 0;

    /// @brief Get a Logical Port scheduler.
    ///
    /// @param[out] out_lp_sch          Pointer to #silicon_one::la_logical_port_scheduler to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully. out_lp_sch contains the LP scheduler.
    /// @retval     LA_STATUS_EINVAL    out_lp_sch is NULL.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_logical_port_scheduler(la_logical_port_scheduler*& out_lp_sch) const = 0;

protected:
    ~la_system_port_scheduler() override = default;
}; // class la_system_port_credit_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_SYSTEM_PORT_SCHEDULER_H__
