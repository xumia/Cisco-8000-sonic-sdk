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

#ifndef __RESOLUTION_CONFIGURATOR_H__
#define __RESOLUTION_CONFIGURATOR_H__

#include "api/types/la_common_types.h"
#include "api/types/la_object.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "nplapi/device_tables.h"
#include "nplapi/npl_types.h"
#include <boost/variant.hpp>

/// @file resolution_configurator.h
/// @brief Resolution stage configuration encapsulation
///
/// Defines a uniform API for accessing and configuring the different stages of the resolution phase.
/// API is exposed through the class "resolution_configurator" which faclitates the access to the multiple tables (EM/AD) in each
/// stage

namespace silicon_one
{
// Helper class needed for internal management of "resolution_configurator"
struct resolution_assoc_data_table_addr_t {
    static constexpr la_uint32_t INVALID_LINE_INDEX = -1;
    bool is_valid() const
    {
        return index != INVALID_LINE_INDEX;
    }

    void set_invalid()
    {
        index = INVALID_LINE_INDEX;
    }

    la_uint32_t index = INVALID_LINE_INDEX; // line index
    la_uint8_t select;                      // entry index within the line
};

// A handle provided (filled) by "resolution_configurator" per configuration
// Also needed for internal management and auto-deletion upon resolution teardown
struct resolution_cfg_handle_t {
    static constexpr la_uint8_t INVALID_STAGE_INDEX = -1;
    bool is_valid() const
    {
        return stage_index != INVALID_STAGE_INDEX;
    }
    void set_invalid()
    {
        stage_index = INVALID_STAGE_INDEX;
        ad_entry_addr.set_invalid();
    }

    la_uint8_t stage_index = INVALID_STAGE_INDEX;
    la_uint32_t common_data = 0;
    resolution_assoc_data_table_addr_t ad_entry_addr;
    la_object_wcptr in_stage_dest;
    boost::variant<boost::blank,
                   npl_stage0_assoc_data_table_t::entry_wptr_type,
                   npl_stage1_assoc_data_table_t::entry_wptr_type,
                   npl_stage2_assoc_data_table_t::entry_wptr_type,
                   npl_stage3_assoc_data_table_t::entry_wptr_type>
        ad_table_entry = boost::blank();
    boost::variant<boost::blank,
                   npl_stage0_em_table_t::entry_wptr_type,
                   npl_stage1_em_table_t::entry_wptr_type,
                   npl_stage2_em_table_t::entry_wptr_type,
                   npl_stage3_em_table_t::entry_wptr_type>
        em_table_entry = boost::blank();
};

// Forward delcarations
template <typename stage_trait>
class resolution_configurator_impl;
struct resolution_stage0_trait_t;
struct resolution_stage1_trait_t;
struct resolution_stage2_trait_t;
struct resolution_stage3_trait_t;

class resolution_configurator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    resolution_configurator();
    ~resolution_configurator();

    /// @brief Initialize the object to access the desired
    /// resolution stage
    ///
    /// @param[in]  stage           Resolution stage index to be managed by the object
    /// @param[in]  device_tables   Device tables
    ///
    /// @retval     LA_STATUS_SUCCESS   Object initialized successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid arguments.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status initialize(int stage, const la_device_impl_wptr& device);

    /// @brief Applies a destination mapping resolution configuration which consists of EM-entry and AD-entry
    ///
    /// @param[in]  dest             Full destination ID
    /// @param[in]  value            A templated parameter that can be any of the following types:
    ///                                1- npl_resolution_stage_assoc_data_narrow_entry_t
    ///                                2- npl_resolution_stage_assoc_data_wide_entry_t
    ///                                3- npl_resolution_stage_assoc_data_narrow_protection_record_t
    ///                                4- npl_resolution_stage_assoc_data_wide_protection_record_t
    /// @param[inout] cfg_handle     A semi-opaque handle object filled and used internally by the class
    /// @param[in]  npl_em_common_data  Common data to be placed in the EM entry
    ///
    /// @retval     LA_STATUS_SUCCESS   Object initialized successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid arguments.
    /// @retval     LA_STATUS_EOUTOFMEMORY Memory allocations failures.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    template <typename table_value_type>
    la_status configure_dest_map_entry(const destination_id& dest,
                                       const table_value_type& value,
                                       resolution_cfg_handle_t& cfg_handle,
                                       const npl_em_common_data_t& common_data = npl_em_common_data_t{{0}});

    /// @brief Applies a load balancing resolution configuration which consists of EM-entry and AD-entry
    ///
    /// @param[in]  group_id         Load balancing (ECMP/DSPA) group ID.
    /// @param[in]  member_id        Load balancing member ID within the group.
    /// @param[in]  value            A templated parameter that can be any of the following types:
    ///                                1- npl_resolution_stage_assoc_data_narrow_entry_t
    ///                                2- npl_resolution_stage_assoc_data_wide_entry_t
    ///                                3- npl_resolution_stage_assoc_data_narrow_protection_record_t
    ///                                4- npl_resolution_stage_assoc_data_wide_protection_record_t
    /// @param[inout] cfg_handle     A semi-opaque handle object filled and used internally by the class
    /// @param[in]  npl_em_common_data  Common data to be placed in the EM entry
    ///
    /// @retval     LA_STATUS_SUCCESS   Object initialized successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid arguments.
    /// @retval     LA_STATUS_EOUTOFMEMORY Memory allocations failures.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    template <typename table_value_type>
    la_status configure_lb_entry(const la_uint32_t group_id,
                                 const la_uint32_t member_id,
                                 const table_value_type& value,
                                 resolution_cfg_handle_t& cfg_handle,
                                 const npl_em_common_data_t& common_data = npl_em_common_data_t{{0}});

    /// @brief Applies a load balancing resolution configuration that point to an in-stage (local to the stage) destinaion which
    /// consists of EM-entry only.
    ///        Common data is auto-copied from the in-stage destination object (also tracks and auto-updates it).
    ///
    /// @param[in]  group_id         Load balancing (ECMP/DSPA) group ID.
    /// @param[in]  member_id        Load balancing member ID within the group.
    /// @param[in]  in_stage_dest    In-stage destination for the given (group,memmber) entry
    /// @param[inout] cfg_handle     A semi-opaque handle object filled and used internally by the class
    ///
    /// @retval     LA_STATUS_SUCCESS   Object initialized successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid arguments.
    /// @retval     LA_STATUS_EOUTOFMEMORY Memory allocations failures.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status configure_in_stage_lb_entry(const la_uint32_t group_id,
                                          const la_uint32_t member_id,
                                          const la_object_wcptr& in_stage_dest,
                                          resolution_cfg_handle_t& cfg_handle);

    /// @brief Applies a load balancing resolution configuration that point to an in-stage (local to the stage) destinaion which
    /// consists of EM-entry only.
    ///        Caller is responsible for the common_data (neither copy nor updates tracking from in-stage-dest object is done)
    ///
    /// @param[in]  group_id         Load balancing (ECMP/DSPA) group ID.
    /// @param[in]  member_id        Load balancing member ID within the group.
    /// @param[in]  in_stage_dest    In-stage destination for the given (group,memmber) entry
    /// @param[inout] cfg_handle     A semi-opaque handle object filled and used internally by the class
    ///
    /// @retval     LA_STATUS_SUCCESS   Object initialized successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid arguments.
    /// @retval     LA_STATUS_EOUTOFMEMORY Memory allocations failures.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status configure_in_stage_lb_entry(const la_uint32_t group_id,
                                          const la_uint32_t member_id,
                                          const la_object_wcptr& in_stage_dest,
                                          resolution_cfg_handle_t& cfg_handle,
                                          const npl_em_common_data_t& common_data);

    /// @brief Applies a load balancing resolution configuration that point to an in-stage (local to the stage) destinaion which
    /// consists of EM-entry only.
    ///        Caller is responsible for the common_data (neither copy nor tracking from in-stage-dest object is done)
    ///
    /// @param[in]  group_id         Load balancing (ECMP/DSPA) group ID.
    /// @param[in]  member_id        Load balancing member ID within the group.
    /// @param[in]  in_stage_dest    In-stage destination for the given (group,memmber) entry
    /// @param[inout] cfg_handle     A semi-opaque handle object filled and used internally by the class
    ///
    /// @retval     LA_STATUS_SUCCESS   Object initialized successfully.
    /// @retval     LA_STATUS_EINVAL    Invalid arguments.
    /// @retval     LA_STATUS_EOUTOFMEMORY Memory allocations failures.
    /// @retval     LA_STATUS_EUNKNOWN  An unknown error occurred.
    la_status unconfigure_entry(resolution_cfg_handle_t& cfg_handle);

    la_status set_group_size(const la_uint32_t group_id, const la_uint32_t group_size, npl_lb_consistency_mode_e consistency_mode);

    la_status get_group_size(const la_uint32_t group_id,
                             la_uint32_t& out_group_size,
                             npl_lb_consistency_mode_e& out_consistency_mode);

    la_status erase_group_size(const la_uint32_t group_id);

    la_status configure_protection_monitor(const la_protection_monitor_gid_t& monitor_id,
                                           npl_resolution_protection_selector_e selector);

    la_status unconfigure_protection_monitor(const la_protection_monitor_gid_t& monitor_id);

private:
    std::unique_ptr<resolution_configurator_impl<resolution_stage0_trait_t> > m_stage0_impl;
    std::unique_ptr<resolution_configurator_impl<resolution_stage1_trait_t> > m_stage1_impl;
    std::unique_ptr<resolution_configurator_impl<resolution_stage2_trait_t> > m_stage2_impl;
    std::unique_ptr<resolution_configurator_impl<resolution_stage3_trait_t> > m_stage3_impl;
    int m_stage;
};

} // namespace silicon_one

#endif // __RESOLUTION_CONFIGURATOR_H__
