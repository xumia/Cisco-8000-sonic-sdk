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

#ifndef __LA_OUTPUT_QUEUE_SCHEDULER_H__
#define __LA_OUTPUT_QUEUE_SCHEDULER_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Output queue scheduler API-s.
///
/// Defines API-s for managing output queue scheduler's objects.

/// @addtogroup TM_SCH
/// @{

namespace silicon_one
{

/// @brief      Output Queue scheduler.
///
/// @details    An output queue scheduler defines scheduling priorities,
///             weights and rate limits for up to 16k VOQ-s that are assigned to the given output queue.
class la_output_queue_scheduler : public la_object
{
public:
    /// @brief  Output queue scheduler mode.
    ///
    /// @details    An output queue scheduler allocates credits to 4 or 8 VSC groups,
    ///             in a mix of strict priority and weighted queuing.
    ///             The scheduling mode defines the exact mix.
    ///
    /// @note   When an output queue is mapped to a logical port, use the LP_* values.
    ///         When an output queue is mapped to TPSE, use the DIRECT_* values.
    enum class scheduling_mode_e {
        FIRST_TPSE_MAP = 0,          ///< Scheduling modes available when OQSE mapped to TPSE.
        DIRECT_4SP = FIRST_TPSE_MAP, ///< Strict priority between all VSC groups.
        DIRECT_3SP_2WFQ,             ///< Two groups are grouped using WFQ; SP between remaining groups and the new group.
        DIRECT_2SP_3WFQ,             ///< Three groups are grouped using WFQ; SP between remaining group and the new group.
        DIRECT_4WFQ,                 ///< WFQ between groups.

        FIRST_LPSE_2P_MAP,            ///< Scheduling modes available when OQSE mapped to LPSE 2P.
        LP_SP_SP = FIRST_LPSE_2P_MAP, ///< Logical port mode; groups 0-1, 2-3 in SP mode.
        LP_SP_WFQ,                    ///< Logical port mode; groups 0-1 in SP mode, 2-3 in WFQ mode.
        LP_WFQ_SP,                    ///< Logical port mode; groups 0-1 in WFQ mode, 2-3 in SP mode.
        LP_WFQ_WFQ,                   ///< Logical port mode; groups 0-1, 2-3 in WFQ mode.

        FIRST_LPSE_4P_MAP,          ///< Scheduling modes available when OQSE mapped to LPSE 4P.
        LP_4SP = FIRST_LPSE_4P_MAP, ///< Strict priority between all VSC groups.
        LP_3SP_2WFQ,                ///< Two groups are grouped using WFQ; SP between remaining groups and the new group.
        LP_2SP_3WFQ,                ///< Three groups are grouped using WFQ; SP between remaining group and the new group.
        LP_4WFQ,                    ///< WFQ between groups.
                                    ///
        FIRST_LPSE_8P_MAP,          ///< Scheduling modes available when OQSE mapped to LPSE 2P.
        LP_8SP = FIRST_LPSE_8P_MAP, ///< Strict priority between all VSC groups.
        LP_7SP_2WFQ,                ///< Two groups are grouped using WFQ; SP between remaining groups and the new group.
        LP_6SP_3WFQ,                ///< Three groups are grouped using WFQ; SP between remaining group and the new group.
        LP_5SP_4WFQ,                ///< Four groups are grouped using WFQ; SP between remaining group and the new group.
        LP_4SP_5WFQ,                ///< Five groups are grouped using WFQ; SP between remaining group and the new group.
        LP_3SP_6WFQ,                ///< Six groups are grouped using WFQ; SP between remaining group and the new group.
        LP_2SP_7WFQ,                ///< Seven groups are grouped using WFQ; SP between remaining group and the new group.
        LP_8WFQ,                    ///< WFQ between eight groups.
    };

    /// @brief Get an output queue scheduler's scheduling mode.
    ///
    /// @param[out] out_mode            Mode to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode updated successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_scheduling_mode(scheduling_mode_e& out_mode) const = 0;

    /// @brief Set an output queue scheduler's scheduling mode.
    ///
    /// Sets the scheduling mode to a mix between strict priority and WFQ.
    /// For OQ schedulers in logical ports, should use one of the logical port scheduling modes.
    ///
    /// @param[in]  mode                Mode to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Mode updated successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid scheduling mode.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_scheduling_mode(scheduling_mode_e mode) = 0;

    /// @brief Retrieve an output queue scheduler's group credits weight as set by the user.
    ///
    /// When multiple groups compete for credits, credits are distributed proportionally
    /// to each group's weight.
    ///
    /// @param[in]  group_id            Group ID.
    /// @param[out] out_weight          Retrieved weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    Group ID is out of range;
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_group_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Set an output queue scheduler's group credits weight.
    ///
    /// When multiple groups compete for credits, credits are distributed proportionally
    /// to each group's weight.
    ///
    /// @param[in]  group_id            Group ID.
    /// @param[in]  weight              Weight to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight updated successfully.
    /// @retval     LA_STATUS_EINVAL    Group ID is out of range;
    ///                                 Weight is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_group_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t weight) = 0;

    /// @brief  Retrieve an output queue scheduler's group credits weight.
    ///
    /// Return the actual group's weight as written to the device.
    ///
    /// @param[in]  group_id            Group ID.
    /// @param[out] out_weight          Retrieved weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_group_actual_weight(la_oqcs_group_id_t group_id, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Retrieve a vector of all the attached Virtual Scheduler Connection's and their properties.
    ///
    /// @param[out]  out_vsc_vector                 Retrieved all the vsc's attached to OQ.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_attached_vscs(la_vsc_oq_vec_t& out_vsc_vector) const = 0;

    /// @brief Attach a Virtual Scheduler Connection (VSC) to an output queue scheduler.
    ///
    /// @param[in]  vsc                 Virtual Scheduler Connection to attach.
    /// @param[in]  mapping             Select round-robin groups VSC is mapped to.
    /// @param[in]  ingress_device      Device ingress VOQ is located on.
    /// @param[in]  ingress_slice       Slice ingress VOQ is located on.
    /// @param[in]  ingress_voq_id      Ingress VOQ ID.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    VSC, ingress device, ingress slice or ingress VOQ are out of range;
    /// @retval     LA_STATUS_ERESOURCE Maximum number of VSC-s attached to output queue scheduler.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status attach_vsc(la_vsc_gid_t vsc,
                                 la_oq_vsc_mapping_e mapping,
                                 la_device_id_t ingress_device,
                                 la_slice_id_t ingress_slice,
                                 la_voq_gid_t ingress_voq_id)
        = 0;

    /// @brief Detach a Virtual Scheduler Connection (VSC) to an output queue scheduler.
    ///
    /// @param[in]  vsc                 Virtual Scheduler Connection to detach.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_ENOTFOUND VSC is not attached to given OQCS.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status detach_vsc(la_vsc_gid_t vsc) = 0;

    /// @brief Retrieve an output queue scheduler's VSC Peak Information Rate.
    ///
    /// @param[in]  vsc                 Virtual Scheduler Connection to configure.
    /// @param[out] out_rate            Credit rate in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    VSC is out of range.
    /// @retval     LA_STATUS_ENOTFOUND VSC is not attached to given OQCS.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vsc_pir(la_vsc_gid_t vsc, la_rate_t& out_rate) const = 0;

    /// @brief Set an output queue scheduler's VSC Peak Information Rate.
    ///
    /// In the Pacific the rate is implemented with variable precision. Actual rate is round-down to nearest mark.
    ///
    /// @param[in]  vsc                 Virtual Scheduler Connection to configure.
    /// @param[in]  rate                Credit rate in bps.
    ///
    /// @retval     LA_STATUS_SUCCESS   Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL    VSC is out of range.
    /// @retval     LA_STATUS_ENOTFOUND VSC is not attached to given OQCS.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_vsc_pir(la_vsc_gid_t vsc, la_rate_t rate) = 0;

    /// @brief Get credit scheduler's burst size.
    ///
    /// Controls the size of the credits bucket.
    ///
    /// @param[in]  vsc                 Virtual Scheduler Connection to get its burst size.
    /// @param[out] out_burst           Burst size to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS   Burst size retrieved successfully.
    /// @retval     LA_STATUS_EINVAL    VSC is not attached to this oqsc.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_vsc_burst_size(la_vsc_gid_t vsc, size_t& out_burst) const = 0;

    /// @brief Set credit scheduler's burst size.
    ///
    /// @param[in]  vsc                     Virtual Scheduler Connection to configure.
    /// @param[in]  burst                   Burst size.
    ///
    /// @retval     LA_STATUS_SUCCESS       Rate updated successfully.
    /// @retval     LA_STATUS_EOUTOFRANGE   Burst size is out of range.
    /// @retval     LA_STATUS_EINVAL        VSC is not attached to this oqsc.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status set_vsc_burst_size(la_vsc_gid_t vsc, size_t burst) = 0;

    /// @brief Get slice used by this output queue scheduler.
    ///
    /// @return #la_slice_id_t.
    virtual la_slice_id_t get_slice() const = 0;

    /// @brief Get IFG used by this output queue scheduler.
    ///
    /// @return #la_ifg_id_t.
    virtual la_ifg_id_t get_ifg() const = 0;

protected:
    ~la_output_queue_scheduler() = default;
}; // class la_output_queue_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_OUTPUT_QUEUE_SCHEDULER_H__
