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

#ifndef __COMMON_RESOURCE_MONITOR_H__
#define __COMMON_RESOURCE_MONITOR_H__

#include "api/types/la_system_types.h"
#include "cereal_utils.h"
#include "common_fwd.h"
#include "la_function.h"
#include "la_status.h"
#include <functional>
#include <stddef.h>

#include <memory>

namespace silicon_one
{

/// @brief Resource monitor.
///
/// The resource monitor class provides a mechanism to track usage of a resource
/// and trigger a utilization notification when the usage of resource crosses the
/// configured thresholds.
/// This is achieved by assocating a resource_monitor with an existing object. The
/// monitored object is responsible for calling this->resource_monitor->update_size()
/// when its utilization changes.
///
/// The monitor has N states, where N is the number of notification thresholds configured.
/// Notification thresholds are configured as a pair of low and high watermarks.
///
/// Starting state is 0.
/// State increments when utilization rises above the high-watermark of threhsold[state].
/// State decrements when utilization falls below the low-watermark of threshold[state].
class resource_monitor
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    using action_cb = la_function<la_status(size_t state, size_t max_size, size_t current_size)>;
    using action_cb_sptr = std::shared_ptr<resource_monitor::action_cb>;

    /// @brief Constructor gets the full capacity of the resource and its current status.
    ///
    /// Its high/low thresholds are initialized to 1,0 respectively.
    resource_monitor(const action_cb_sptr& notify,
                     size_t max_size,
                     size_t current_size,
                     size_t resource_type,
                     size_t resource_instance_idx);
    resource_monitor() = default; // For serialization purposes only

    typedef la_resource_thresholds resource_thresholds;

    /// @brief Sets the high/low thresholds for notifications.
    ///
    /// param[in]       high_threshold      Resource utilization threshold to send notification.
    /// param[in]       low_threshold       Resource utilization threshold for cleanup.
    la_status set_thresholds(const std::vector<resource_thresholds>& thresholds_vec);

    /// @brief Gets the high/low thresholds for notifications.
    ///
    /// param[in]       out_high_threshold      Resource utilization high threshold to populate.
    /// param[in]       out_low_threshold       Resource utilization low threshold to populate.
    void get_thresholds(std::vector<resource_thresholds>& out_thresholds_vec) const;

    /// @brief Update resource's current size.
    ///
    /// param[in]       new_size        Resource new utilization.
    void update_size(size_t new_size);

    /// @brief Update resource's max size.
    ///
    /// Used when amount of entries of the resource instance is changed.
    ///
    /// param[in]       new_max_size    Resource new number of entries.
    void update_max_size(size_t new_max_size);

    /// @brief Retrieve the number of entries in use.
    ///
    /// @retval Entries in use.
    size_t get_size() const;

    /// @brief Retrieve the total number of entries.
    ///
    /// @retval Total number of entries.
    size_t get_max_size() const;

    /// @brief Retrieve the state.
    ///
    /// @retval Monitor state.
    size_t get_state() const;

    /// @brief Retrieve the resource type enum.
    ///
    /// @retval resource type enum numerical value.
    size_t get_resource_type() const;

    /// @brief Retrieve the resource instance idx.
    ///
    /// @retval resource instance idx.
    size_t get_resource_instance_idx() const;

    /// @brief update the current_size by offset
    ///
    /// @param[in]      offset      size offset to increase/decrease
    void offset_size(int offset);

private:
    // Check if notification should be sent.
    bool check_change();

    // CB to notify the monitor's user.
    action_cb_sptr m_notify;

    // Number of Maximum entries of the resouce.
    size_t m_max_size;

    // Resource currently utilization.
    size_t m_current_size;

    // Notification thresholds.
    std::vector<resource_thresholds> m_thresholds_vec;

    // Resource state. Indicates Wheter to send notification or not.
    size_t m_state;

    // The resource type enum numerical value.
    size_t m_resource_type;

    // The resource instance index
    size_t m_resource_instance_idx;
};

} // namespace silicon_one

#endif
