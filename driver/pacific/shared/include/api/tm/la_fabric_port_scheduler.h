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

#ifndef __LA_FABRIC_PORT_SCHEDULER_H__
#define __LA_FABRIC_PORT_SCHEDULER_H__

#include "api/types/la_object.h"
#include "api/types/la_tm_types.h"

/// @file
/// @brief Leaba Fabric port Scheduler API-s.
///
/// Defines API-s for managing fabric port scheduler's objects.

namespace silicon_one
{

/// @addtogroup TM_SCH
/// @{

/// @brief      Fabric port scheduler.
///
/// @details    A Fabric port scheduler defines scheduling weights for fabric output queueus that are part of the given fabric port.
class la_fabric_port_scheduler : public la_object
{
public:
    /// @brief  Fabric port scheduler output queues.
    ///
    /// @details    Each fabric port scheduler has 3 different output queues, with credits being distributed between the queues
    ///             based on weights.
    enum class fabric_ouput_queue_e {
        PLB_UC_HIGH, ///< Packet load-balancing, UC high priority traffic queue
        PLB_UC_LOW,  ///< Packet load-balancing, UC low priority traffic queue
        PLB_MC       ///< Packet load-balancing, MC traffic queue
    };

    /// @brief Retrieve a fabric port scheduler's output queue credits weight.
    ///
    /// @param[in]  oq                  Fabric output queue.
    /// @param[out] out_weight          Retrieved weight.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight retrieved successfully.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status get_output_queue_weight(fabric_ouput_queue_e oq, la_wfq_weight_t& out_weight) const = 0;

    /// @brief Set a fabric port scheduler's output queue credits weight.
    ///
    /// When multiple output queues compete for credits, credits are distributed proportionally to each queue's weight.
    ///
    /// @param[in]  oq                  Fabric output queue.
    /// @param[in]  weight              Weight to set.
    ///
    /// @retval     LA_STATUS_SUCCESS   Weight updated successfully.
    /// @retval     LA_STATUS_EINVAL    Weight is unsupported.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    virtual la_status set_output_queue_weight(fabric_ouput_queue_e oq, la_wfq_weight_t weight) = 0;

protected:
    ~la_fabric_port_scheduler() override = default;
}; // class la_fabric_port_scheduler

} // namespace silicon_one

/// @}

#endif // __LA_FABRIC_PORT_SCHEDULER_H__
