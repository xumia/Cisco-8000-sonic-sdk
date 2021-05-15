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

#ifndef __HLD_RESOURCE_HANDLER_H__
#define __HLD_RESOURCE_HANDLER_H__

#include "api/types/la_system_types.h"
#include "common/cereal_utils.h"
#include "common/la_function.h"
#include "common/la_status.h"
#include "common/resource_monitor.h"
#include "hld_types_fwd.h"
#include <memory>
#include <vector>

namespace silicon_one
{

class la_device_impl;

class resource_handler : public std::enable_shared_from_this<resource_handler>
{

public:
    explicit resource_handler(const la_device_impl_wptr& device);
    ~resource_handler();

    /// @brief Initialize the resource handler.
    ///
    /// Map resource type to its granularity and assign monitor to each resource instance.
    ///
    /// @retval     LA_STATUS_SUCCESS           All resources and their granularity were initialize successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    la_status initialize();

    /// @brief Get resource's granularity.
    ///
    /// param[in]   resource_type               Resource type.
    /// param[out]  out_granularity             Granularity of the resource in the pacific.
    ///
    /// @retval     LA_STATUS_SUCCESS           Resource granularity was retreived successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    la_status get_granularity(la_resource_descriptor::type_e resource_type, la_resource_granularity& out_granularity) const;

    // la_device API-s
    la_status get_resource_usage(la_resource_usage_descriptor_vec& out_descriptors) const;
    la_status get_resource_usage(la_resource_descriptor::type_e resource_type,
                                 la_resource_usage_descriptor_vec& out_descriptors) const;
    la_status get_resource_usage(const la_resource_descriptor& descriptor, la_resource_usage_descriptor& out_descriptor) const;
    la_status set_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                   const std::vector<la_resource_thresholds>& thresholds_vec);
    la_status get_resource_notification_thresholds(la_resource_descriptor::type_e resource_type,
                                                   std::vector<la_resource_thresholds>& out_thresholds_vec) const;

    // Helper classes/structs
    // Due to Cereal limitation res_monitor_action_cb must be public
    struct res_monitor_action_cb : public resource_monitor::action_cb {
        res_monitor_action_cb() = default; // For serialization purpose
        res_monitor_action_cb(const resource_handler_sptr& parent, const la_resource_descriptor& res_desc);
        la_status operator()(size_t state, size_t max_size, size_t current_size);

        resource_handler_wptr m_parent;
        la_resource_descriptor m_res_desc;
    };

protected:
    // a helper function called by set_resource_notification_thresholds
    la_status set_single_notification_threshold(size_t i,
                                                la_resource_descriptor::type_e resource_type,
                                                const std::vector<la_resource_thresholds>& thresholds_vec);

private:
    // Helper functions

    // Initialize all resources and their granularity
    la_status initialize_resources_types();

    // Assign monitor to each resource instatnce
    la_status initialize_resources_instances();
    la_status allocate_resource_monitor(const la_resource_descriptor& descriptor,
                                        size_t max_size,
                                        size_t size,
                                        resource_monitor_sptr& out_resource_monitor);

    /// @brief Add resource instance to be monitored.
    ///
    /// Attach monitor to resource instance and classify it by the descriptor.
    ///
    /// param[in]   resource_instance           Resource instance to be monitored.
    /// param[in]   descriptor                  Type and index of the resource.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    template <class _Resource_Type>
    la_status add_resource(const _Resource_Type& resource_instance, const la_resource_descriptor& descriptor);
    la_status add_resource_monitored_by_device(const size_t max_size, const size_t size, const la_resource_descriptor& descriptor);

    /// @brief Nofity on resource that crossed the thresshold.
    ///
    /// param[in]   monitor_id                  Resource type.
    /// param[in]   max_size                    Resource capacity.
    /// param[in]   current_size                New resource size.
    /// param[in]   threshold                   Resource notification threshold.
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    la_status notify(const la_resource_descriptor& descriptor, size_t state, size_t max_size, size_t current_size);

    resource_monitor_sptr get_resource_monitor(const la_resource_descriptor& descriptor) const;
    la_status get_instance_index(const la_resource_descriptor& descriptor, la_resource_instance_index_t& out_index) const;
    la_status get_num_instances(la_resource_granularity granularity, size_t& out_num_instances) const;

    /// @brief Get the table usage (total and used) by poll the table. Used for dependent table resources
    template <class _Table>
    la_status get_usage_from_table_instance(const _Table& table, la_resource_usage_descriptor& out_descriptor) const;
    /// @brief Get the table total by poll the table. Used for dependent table resources
    template <class _Table>
    la_status get_total_from_table_instance(const _Table& table,
                                            la_resource_usage_descriptor& out_descriptor,
                                            const size_t resource_used) const;

    /// @brief a helper function, which returns the relevant indices based on granularity
    ///
    /// param[in]   granularity                 Resource granularity.
    /// param[out]  out_ind_vect                Must point to an empty vector when passed to the function.
    ///                                         The relevant indices for this granularity
    ///
    /// @retval     LA_STATUS_SUCCESS           Operation completed successfully.
    /// @retval     LA_STATUS_EUNKNOWN          An unknown error occurred.
    using index_vect = std::vector<size_t>;
    la_status get_enabled_indices(la_resource_granularity granularity, index_vect& out_ind_vect) const;

    // Device this resource handler belongs to
    la_device_impl_wptr m_device;

    struct resource_monitor_entry {
        std::vector<resource_monitor_sptr> monitors;
        la_resource_granularity granularity;
    };

    // All monitors which are managed by the resource_handler.
    std::vector<resource_monitor_entry> m_resource_monitors;

    // Serialization helpers
    resource_handler() = default; // For serialization purposes only
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    CEREAL_SUPPORT_PRIVATE_CLASS(res_monitor_action_cb)
    CEREAL_SUPPORT_PRIVATE_CLASS(resource_monitor_entry)
};

} // namespace silicon_one

#endif // __HLD_RESOURCE_HANDLER_H__
