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

#ifndef __LEABA_LOGICAL_LPM_H__
#define __LEABA_LOGICAL_LPM_H__

#include "common/la_status.h"
#include "common/resource_monitor.h"
#include "lld/lld_fwd.h"

#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/lpm_settings.h"
#include "hw_tables/lpm_types.h"

/// @file
/// @brief Leaba LPM DB interface
///
/// Defines API-s for managing the LPM algorithm.

namespace silicon_one
{

class lpm_distributor;
class bucketing_tree;
class lpm_core;
class lpm_tcam;
class ll_device;

/// @brief Logical LPM.
///
/// Set of LPM cores, with a distributor TCAM.
/// Updates the LPM tables on both SW and HW, according to given list containing entries to insert, remove and modify.
class logical_lpm
{
public:
    virtual ~logical_lpm() = default;

    /// @brief      Get #ll_device.
    ///
    /// @return     #ll_device.
    virtual const ll_device_sptr& get_ll_device() const = 0;

    /// @name Update API-s
    /// @{

    /// @brief Insert entry to LPM and calculate HW updates.
    ///
    /// @param[in]      key                     Key of entry to insert.
    /// @param[in]      payload                 Payload of entry to insert.
    ///
    /// @return #la_status.
    virtual la_status insert(const lpm_key_t& key, lpm_payload_t payload) = 0;

    /// @brief Remove entry from LPM and calculate HW updates.
    ///
    /// @param[in]      key                     Key of entry to remove.
    ///
    /// @return #la_status.
    virtual la_status remove(const lpm_key_t& key) = 0;

    /// @brief Modify an entry's payload and calculate HW updates.
    ///
    /// @param[in]      key                     Key of entry to modify.
    /// @param[in]      payload                 New payload.
    ///
    /// @return #la_status.
    virtual la_status modify(const lpm_key_t& key, lpm_payload_t payload) = 0;

    /// @brief Calculate and instruct HW updates as a result of a series of actions.
    ///
    /// @param[in]      actions                 Action list to perform on core.
    /// @param[out]     out_count_success       Returns the number of successfully programmed routes.
    ///
    /// @return #la_status.
    virtual la_status update(const lpm_action_desc_vec_t& actions, size_t& out_count_success) = 0;

    /// @}

    /// @name Data access
    /// @{

    /// @brief Find longest prefix match of given key.
    ///
    /// If no match found, hit key and hit payload are set to be zero width bit vectors.
    ///
    /// @param[in]      key             Key to lookup.
    /// @param[out]     out_hit_key         Key of hit entry.
    /// @param[out]     out_hit_payload     Payload of hit entry.
    ///
    /// @return #la_status.
    virtual la_status lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload) const = 0;

    /// @brief Get core.
    ///
    /// @param[in]      idx             LPM core index.
    ///
    /// @return Pointer to core object.
    virtual lpm_core_scptr get_core(size_t idx) const = 0;

    /// @brief Get the LPM tree.
    ///
    /// @return Pointer to the tree object.
    virtual bucketing_tree_scptr get_tree() const = 0;

    /// @brief Get number of cores.
    ///
    /// @return number of LPM cores.
    virtual size_t get_num_cores() const = 0;

    /// @brief Get cores utilization.
    ///
    /// @return Vector containing number of entries per core index.
    virtual vector_alloc<size_t> get_cores_utilization() const = 0;

    /// @brief Sets the rebalancing interval in terms of per-core updates.
    /// Rebalancing moves data between LPM cores to ensure equal load.
    /// Setting the interval length provides an ability to control the frequency of rebalance invocations.
    ///
    /// @param[in]      num_of_updates      Number of core updates, after which rebalancing procedure is called.
    virtual void set_rebalance_interval(size_t num_of_updates) = 0;

    /// @brief Gets the rebalancing interval in terms of per-core updates.
    ///
    /// @return Number of core updates, after which rebalancing procedure is called.
    virtual size_t get_rebalance_interval() const = 0;

    /// @brief Sets the rebalance start threshold in terms of deviation between the cores.
    ///
    /// Set the deviation percentage between the most and least utilized cores. Acceptable range is [0..1].
    /// Rebalance will be triggered if fairness is below this number.
    ///
    /// @param[in]      threshold       Threshold for cores' deviation.
    virtual void set_rebalance_start_fairness_threshold(double threshold) = 0;

    /// @brief Gets the rebalance start fairness threshold.
    ///
    /// @return the rebalance start fairness threshold.
    virtual double get_rebalance_start_fairness_threshold() const = 0;

    /// @brief Sets the rebalance end threshold in terms of deviation between the cores.
    ///
    /// Set the deviation percentage between the most and least utilized cores. Acceptable range is [0..1].
    /// Rebalance will stop if fairness is above this number.
    ///
    /// @param[in]      threshold       Threshold for cores' deviation.
    virtual void set_rebalance_end_fairness_threshold(double threshold) = 0;

    /// @brief Gets the rebalance stop fairness threshold.
    ///
    /// @return the rebalance end fairness threshold.
    virtual double get_rebalance_end_fairness_threshold() const = 0;

    /// @brief Sets the max number of rebalance retries triggered by an update fail.
    ///
    /// @param[in]       max_retries         Max number of retries.
    virtual void set_max_retries_on_fail(size_t max_retries) = 0;

    /// @brief Gets th max number of rebalance retries triggered by an update fail.
    ///
    /// @return Max number of rebalance retries.
    virtual size_t get_max_retries_on_fail() = 0;

    /// @brief Rebalance subtrees core distribution to improve overall utilization.
    ///
    /// @return #la_status.
    virtual la_status rebalance() = 0;

    /// @brief Find index of the core by group index.
    ///
    /// @param[in]      group_index     Index of the group.
    ///
    /// @return Requested core index.
    virtual size_t get_core_index_by_group(size_t group_index) const = 0;

    /// @brief Return LPM distributer object.
    ///
    /// @return Pointer to distributer object.
    virtual const lpm_distributor& get_distributer() const = 0;

    /// @brief Retrieve maximum LPM fullness indicator value.
    ///
    /// @retval Maximum fullness value.
    virtual size_t max_size() const = 0;

    /// @brief LPM-HBM statistics collection entry point.
    ///
    /// Should be called periodically.
    virtual void lpm_hbm_collect_stats() = 0;

    /// @brief LPM-HBM cache update entry point.
    ///
    /// Should be called periodically.
    virtual void lpm_hbm_do_caching() = 0;

    /// @brief Clear and unmask LPM L2 ECC error registers.
    ///
    /// Should be called periodically.
    virtual void unmask_and_clear_l2_ecc_interrupt_registers() const = 0;

    /// @brief Set resource monitor.
    ///
    /// @param[in]  resource_monitor            Resource monitor.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    virtual la_status set_resource_monitor(const resource_monitor_sptr& monitor) = 0;

    /// @brief Get resource monitor.
    ///
    /// @param[out] out_resource_monitor        Resource monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    virtual la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const = 0;

    /// @brief Retrieve number indicating LPM fullness.
    ///
    /// @retval Fullness indicator between 0 to max_size().
    virtual size_t size() const = 0;

    /// @brief Save current LPM state to file.
    ///
    /// File includes the full LPM SW model
    ///
    /// @param[in]  file_name               File name to write the state to.
    ///                                     If file already exists, it will be overwritten.
    ///                                     Supports .gz file
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Couldn't open the file.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status save_state(std::string file_name) const = 0;

    /// @brief Load LPM state from a file.
    ///
    /// File includes the full LPM SW model
    ///
    /// @param[in]  file_name               File name to read the state from.
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Couldn't open the file.
    /// @retval     LA_STATUS_EUNKNOWN      Internal error.
    virtual la_status load_state(const std::string& file_name) = 0;

    /// @brief Get distribution and length of LPM prefixes.
    ///
    /// File includes the distribution and the length of the lpm
    /// prefixes.
    ///
    /// @param[in]  file_name               File name to write the state to.
    ///                                     If file already exists, it will be overwritten.
    ///                                     Supports .gz file
    ///
    /// @retval     LA_STATUS_SUCCESS       Operation completed successfully.
    /// @retval     LA_STATUS_EINVAL        Couldn't open the file.
    /// @retval     LA_STATUS_EUNKNOWN      An unknown error occurred.
    virtual la_status get_prefixes_statistics(std::string file_name) const = 0;

    /// @brief Retrieve percentage of the physical usage out of the total physical resource based on the table's type and it's
    /// number of logical entries.
    ///
    /// @param[in]  table_type                      IPv4/6 table type.
    /// @param[in]  num_of_table_logical_entries    Number of the logical entries that inserted to the LPM through this table.
    ///
    /// @retval     Percentage of the physical usage.
    virtual size_t get_physical_usage(lpm_ip_protocol_e table_type, size_t num_of_table_logical_entries) const = 0;

    /// @brief Retrieve estimation of the available entries left for table based on it's type.
    ///
    /// @param[in]  table_type                      IPv4/6 table type.
    ///
    /// @retval     Estimate of available entries for the table.
    virtual size_t get_available_entries(lpm_ip_protocol_e table_type) const = 0;
};
/// @brief Create a #silicon_one::logical_lpm object.
///
/// This API creates a #silicon_one::logical_lpm, and performs its initialization.
///
/// @param[in]   ldevice           Low level device to write to.
/// @param[in]   settings          Settings for the logical LPM.
///
/// @return      logical_lpm_sptr.
logical_lpm_sptr create_logical_lpm(const ll_device_sptr& ldevice, const lpm_settings& settings);

/// @brief Create a #silicon_one::logical_lpm empty object.
///
/// This API creates a place-holder #silicon_one::logical_lpm.
///
/// @param[in]      ldevice                       Low level device to write to.
logical_lpm_sptr create_logical_lpm(const ll_device_sptr& ldevice);

} // namespace silicon_one

#endif
