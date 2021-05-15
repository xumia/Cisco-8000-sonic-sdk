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

#ifndef __LEABA_LOGICAL_LPM_IMPL_H__
#define __LEABA_LOGICAL_LPM_IMPL_H__

#include <memory>

#include "bucketing_tree.h"
#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/logical_lpm.h"
#include "lpm_distributor.h"
#include "lpm_internal_types.h"

/// @file

namespace silicon_one
{

class lpm_distributor;
class lpm_tcam;
class lpm_top_hw_writer;
class ll_device;

/// @brief Logical LPM implementation.
///
/// Set of LPM cores, with a distributor TCAM.
/// Updates the LPM tables on both SW and HW, according to given list containing entries to insert, remove and modify.
class logical_lpm_impl : public logical_lpm
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // Lifecycle
    /// @brief Create a #silicon_one::logical_lpm object.
    ///
    /// This API creates a #silicon_one::logical_lpm, and performs its initialization.
    ///
    /// @param[in]     ldevice     Low level device to write to.
    /// @param[in]     settings    Settings for logical LPM.
    logical_lpm_impl(const ll_device_sptr& ldevice, const lpm_settings& settings);

    /// @brief Logical LPM destructor.
    ~logical_lpm_impl();

    // logical_lpm_impl API-s
    const ll_device_sptr& get_ll_device() const override;
    la_status insert(const lpm_key_t& key, lpm_payload_t payload) override;
    la_status remove(const lpm_key_t& key) override;
    la_status modify(const lpm_key_t& key, lpm_payload_t payload) override;
    la_status update(const lpm_action_desc_vec_t& actions, size_t& out_count_success) override;
    la_status lookup(const lpm_key_t& key, lpm_key_t& out_hit_key, lpm_payload_t& out_hit_payload) const override;
    lpm_core_scptr get_core(size_t idx) const override;
    bucketing_tree_scptr get_tree() const override;
    size_t get_num_cores() const override;
    vector_alloc<size_t> get_cores_utilization() const override;
    void set_rebalance_interval(size_t num_of_updates) override;
    size_t get_rebalance_interval() const override;
    void set_rebalance_start_fairness_threshold(double threshold) override;
    double get_rebalance_start_fairness_threshold() const override;
    void set_rebalance_end_fairness_threshold(double threshold) override;
    double get_rebalance_end_fairness_threshold() const override;
    void set_max_retries_on_fail(size_t max_retries) override;
    size_t get_max_retries_on_fail() override;
    la_status rebalance() override;
    size_t get_core_index_by_group(size_t group_index) const override;
    const lpm_distributor& get_distributer() const override;
    size_t max_size() const override;
    void lpm_hbm_collect_stats() override;
    void lpm_hbm_do_caching() override;
    void unmask_and_clear_l2_ecc_interrupt_registers() const override;
    la_status set_resource_monitor(const resource_monitor_sptr& monitor) override;
    la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const override;
    size_t size() const override;
    la_status save_state(std::string file_name) const override;
    la_status get_prefixes_statistics(std::string file_name) const override;
    la_status load_state(const std::string& file_name) override;
    size_t get_physical_usage(lpm_ip_protocol_e table_type, size_t num_of_table_logical_entries) const override;
    size_t get_available_entries(lpm_ip_protocol_e table_type) const override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    logical_lpm_impl();

    /// @brief Cache of groups' load.
    struct cached_values {
        vector_alloc<size_t> load_per_group; ///< Vector counting load of the current group.
        vector_alloc<bool> is_valid;         ///< Bit per group indicates whether load_per_group is valid.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cached_values)

    using key_to_group_core_unordered_map = unordered_map_alloc<lpm_key_t, lpm_core_group_data>;

    /// @brief Distributor's logical state used for rebalance.
    struct distributor_state {
        ranged_index_generator free_indexes;                      ///< Index generator.
        key_to_group_core_unordered_map used_distributor_entries; ///< Map holding key to index/group and core mapping.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(distributor_state)

    /// @brief Rebalance subtrees core distribution for a given protocol.
    ///
    /// @param[in]      protocol                Protocol to perform rebalance on.
    /// @param[in]      src_core                If different from CORE_ID_NONE, rebalance will try to move entries out of this core.
    ///
    /// @return #la_status.
    la_status rebalance(lpm_ip_protocol_e protocol, size_t src_core);

    /// @brief Rebalance subtrees core distribution to improve overall utilization.
    ///
    /// @param[in]      src_core                If different from CORE_ID_NONE, rebalance will try to move entries out of this core.
    ///
    /// @return #la_status.
    la_status rebalance(size_t src_core);

    /// @brief Compute fairness of cores.
    ///
    /// @param[in]      protocol                    Which protocol to check.
    ///
    /// @return fairness of cores.
    double compute_cores_fairness(lpm_ip_protocol_e protocol) const;

    /// @brief Check whether cores are balanced.
    ///
    /// @param[in]      protocol                    Which protocol to check.
    /// @param[in]      fairness_threshold          According to which threshold to compare.
    ///
    /// @return True if all the cores are balanced.
    bool are_cores_balanced(lpm_ip_protocol_e protocol, double fairness_threshold) const;

    /// @brief Find group and core index that contain given key.
    ///
    /// @param[in]       key                     Key to find its relevant group.
    /// @param[out]      out_core_group          Core and group that contain key.
    void get_containing_group_and_core(const lpm_key_t& key, lpm_core_group_data& out_core_group) const;

    /// @brief Calculate and instruct HW updates as a result of a series of actions.
    ///
    /// @param[in]      actions               Action list to perform on core.
    /// @param[in]      start_index           Start index in the action list.
    /// @param[out]     out_failed_core       In case of OOR failure, which core has failed.
    /// @param[out]     out_count_success     Returns the number of successfully programmed routes.
    ///
    /// @return Status indicating if operation succeeded.
    la_status do_update(const lpm_implementation_desc_vec& actions,
                        size_t start_index,
                        size_t& out_failed_core,
                        size_t& out_count_success);

    /// @brief Update cores according to an action descriptor vector per core.
    ///
    /// @param[in]      actions                         Action desctiptors vector.
    /// @param[out]     out_failed_core                 In case of OOR failure, which core has failed.
    ///
    /// @return Status indicating if operation succeeded.
    la_status update_cores(const lpm_implementation_desc_vec& actions, size_t& out_failed_core);

    /// @brief update last operation failed.
    ///
    /// We keep this data to skip trying to push more routes before removing some routes.
    ///
    /// @param[in]      actions                         action desctiptors of the failed actions.
    void update_last_insert_oor_per_protocol(const lpm_implementation_desc_vec& actions);

    /// @name Load balancing main algorithms
    /// {

    /// @brief Remove a group and break the most utilized group to two new groups.
    /// The group to be removed is the one to cause best improvement in group utilization balance.
    ///
    /// @param[in]       protocol                   Protocol to operate on.
    /// @param[in]       src_core                   Which core to move entries from. If CORE_ID_NONE is specified will move entries
    /// from most utilized core.
    /// @param[out]      did_improve                Core load distribution has improved.
    ///
    /// @return #la_status.
    la_status move_a_subtree_to_least_utilized_core(lpm_ip_protocol_e protocol, size_t src_core, bool& did_improve);

    /// @brief Move given group to given core.
    ///
    /// @param[in]      protocol                   Protocol to operate on.
    /// @param[in]      key_to_move                Group root key to move between cores.
    /// @param[in]      to_core                    Core to move group to.
    ///
    /// @return #la_status.
    la_status move_group_to_core(lpm_ip_protocol_e protocol, const lpm_key_t& key_to_move, size_t to_core);

    /// @brief Try to move a whole group to the least utilized core.
    ///
    /// It's triggered if non of the groups are erasable.
    ///
    /// @param[in]       protocol                   Protocol to operate on.
    /// @param[in]       src_core                   Core to move group from. If CORE_ID_NONE is specified, will select most utilized
    /// core.
    ///
    /// @return #la_status.
    la_status move_a_whole_group_to_least_utilized_core(lpm_ip_protocol_e protocol, size_t src_core);

    /// @brief Free a group by merging a group with its parent.
    ///
    /// @param[in]      protocol                        Which kind of groups to consider (protocol-wise).
    ///
    /// @return #la_status.
    la_status free_a_group_by_merging_two_groups(lpm_ip_protocol_e protocol);

    /// @brief Hang a given group on its parent group and clear distributer line.
    ///
    /// @param[in]      protocol                        Which kind of groups to consider (protocol-wise).
    /// @param[in]      group_root_key                  Group to root key.
    /// @param[in]      from_group_core                 Group and core index to merge.
    /// @param[in]      to_group_core                   Group and core index to move the removed group entries to.
    ///
    /// @return #la_status.
    la_status merge_group_with_parent(lpm_ip_protocol_e protocol,
                                      const lpm_key_t& group_root_key,
                                      const lpm_core_group_data& from_group_core,
                                      const lpm_core_group_data& to_group_core);

    /// @brief Cut a new group out of src core and move it to least utilized core.
    ///
    /// @param[in]       protocol                     Protocol of the group to break.
    /// @param[in]       most_utilized_core           Most utilized core index.
    ///
    /// @return #la_status.
    la_status move_a_subtree_to_least_utilized_core_using_new_group(lpm_ip_protocol_e protocol, size_t most_utilized_core);

    /// @brief Cut a new group out of src core and move it to least utilized core.
    ///
    /// @param[in]       protocol                     Protocol of the group to break.
    /// @param[in]       src_core                     Core to take subtree from.
    /// @param[in]       dst_core                     Core to move subtree to.
    /// @param[in]       requested_size               Size (in weighted TCAM lines) to cut from src_core.
    ///
    /// @return #la_status.
    la_status break_a_group_subtree_with_given_size(lpm_ip_protocol_e protocol,
                                                    size_t src_core,
                                                    size_t dst_core,
                                                    size_t requested_size);

    /// @brief Find a group to free by merging with its parent.
    ///
    /// @param[in]      protocol                        Which kind of groups to consider (protocol-wise).
    /// @param[in]      group_exclude_list              List of groups to exclude.
    /// @param[out]     group_key                       Group root key.
    /// @param[out]     out_from_group_core             Group and core index to move from.
    /// @param[out]     out_to_group_core               Group and core index to move to.
    void find_optimal_group_root_to_be_merged_with_parent(lpm_ip_protocol_e protocol,
                                                          const vector_alloc<bool> group_exclude_list,
                                                          lpm_key_t& group_key,
                                                          lpm_core_group_data& out_from_group_core,
                                                          lpm_core_group_data& out_to_group_core) const;

    /// @brief Get group and core indet that cover the entries of the given group.
    ///
    /// @param[in]       group_root                     Group root key to find its covering group and core.
    /// @param[out]      out_core_group                 Core and group that cover group root key.
    void get_covering_core_group(const lpm_key_t& group_root, lpm_core_group_data& out_core_group) const;

    /// @brief Allocate a free group of a given protocol type.
    ///
    /// @param[in]      protocol                        Group protocol.
    /// @param[out]     free_group_id                   Allocated group.
    ///
    /// @return #la_status.
    la_status allocate_free_group(lpm_ip_protocol_e protocol, size_t& free_group_id);

    /// @brief Find least utilized core considering nodes from a give protocol only.
    ///
    /// @param[in]      protocol                        Group protocol.
    /// @param[out]     out_most_utilized_core          Most utilized core ID.
    /// @param[out]     out_least_utilized_core         Least utilized core ID.
    /// @param[out]     out_max_core_utilization        Utilization of most utilized core.
    /// @param[out]     out_min_core_utilization        Utilization of least utilized core.
    void get_most_and_least_utilized_cores(lpm_ip_protocol_e protocol,
                                           size_t& out_most_utilized_core,
                                           size_t& out_least_utilized_core,
                                           size_t& out_max_core_utilization,
                                           size_t& out_min_core_utilization) const;

    /// @brief Calculate all the cores' utilization in terms of TCAM lines.
    void calculate_cores_utilization();

    /// @brief Calculate core's load in terms of TCAM lines.
    ///
    /// @param[in]      protocol                        Group protocol.
    /// @param[in]      core                            Core to calculate its utilization.
    ///
    /// @return TCAM utilization in the given core.
    size_t get_core_tcam_load(lpm_ip_protocol_e protocol, size_t core) const;

    /// @brief Find a subtree of a group with given size (in weighted TCAM lines).
    ///
    /// @param[in]      core                            Core to search a subtree in.
    /// @param[in]      protocol                        Group protocol.
    /// @param[in]      requested_weighted_size         The required weighted size of the group's subtree.
    /// @param[out]     out_from_group                  The group the returened subtree belongs to.
    /// @param[out]     out_new_group_key               The key of the subtree that will become a new group.
    /// @param[out]     out_achieved_weighted_size      The achieved weighted size of the group's subtree.
    void find_a_group_subtree_with_given_size(size_t from_core,
                                              lpm_ip_protocol_e protocol,
                                              size_t requested_weighted_size,
                                              size_t& out_from_group,
                                              lpm_key_t& out_new_group_key,
                                              size_t& out_achieved_weighted_size) const;

    /// }

    /// @name General load balance helper functions
    /// {

    /// @brief Move given entries between cores, update TCAM.
    ///
    /// This function handles rebalance entries movements.
    /// Only rebalance actions are legal.
    ///
    /// @param[in]      action                          Action to perform by the tree.
    /// @param[in]      from_core                       Core to remove entries from.
    /// @param[in]      to_core                         Core to move entries to.
    /// @param[in]      distributor_actions             Actions to perform by the distributor.
    ///
    /// @return #la_status.
    la_status move_entries_between_cores(const lpm_action_desc_internal& action,
                                         size_t from_core,
                                         size_t to_core,
                                         const lpm_implementation_desc_vec& distributor_actions);

    /// @brief Print state of distributor.
    void log_distibutor() const;

    bool sanity() const;

    /// @brief Utility to check integrity of internal data structures.
    ///
    /// @return True if all distributer entries are set in the trees as group roots.
    bool check_groups_roots_keys() const;

    /// @brief Utility to check integrity of internal data structures.
    ///
    /// @return True if all payloads of all groups' roots are correct.
    bool check_groups_roots_payload() const;

    /// @brief Check integrity of group sizes.
    ///
    /// @return True if stored group sizes are equal to computed sizes.
    bool sanity_group_sizes() const;

    /// @brief Save groups to core and keys state.
    void save_flat_members(json_t* json_repr) const;

    /// @brief Load groups to core and keys state.
    void load_flat_members(json_t* json_repr);

    /// @brief Reset state of all members.
    void reset_members();

    /// @brief Return if the group is the catch-all group.
    ///
    /// @param[in]      group_root      Group root.
    ///
    /// @return True if it's the catch-all group.
    bool is_default_group(const lpm_key_t& group_root) const;

    /// @brief Create insert or modify action descriptor for the distributor.
    ///
    /// We need different distributor's actions to Pacific/GB vs AKPG becuase of HW implementation:
    /// Pacific/GB distributor's implementation is key-->group and group-->core.
    /// AKPG distributor's implementation is simply key-->core.
    ///
    /// @param[in]      action      Action to perform.
    /// @param[in]      key         Key for the action.
    /// @param[in]      group       Group id.
    /// @param[in]      core        Core id.
    ///
    /// @return Insert or modify action descriptor for the distributor.
    lpm_action_desc_internal create_insert_modify_distributor_action_desc(lpm_implementation_action_e action,
                                                                          const lpm_key_t& key,
                                                                          size_t group,
                                                                          size_t core);

    /// }

    // Members
    ll_device_sptr m_ll_device; ///< ll_device this LPM belongs to.

    // Parameters
    size_t m_number_of_cores;                    ///< Number of cores in LPM.
    size_t m_number_of_groups;                   ///< Number of groups in LPM distributor.
    bool m_has_hbm;                              ///< Predicate specify whether HBM is enabled.
    size_t m_rebalance_interval;                 ///< Number of core updates to invoke rebalancing.
    double m_rebalance_start_fairness_threshold; ///< Fairness threshold for starting rebalance.
    double m_rebalance_end_fairness_threshold;   ///< Fairness threshold for ending rebalance.
    size_t m_max_retries_on_fail;                ///< How many time to try balancing on update failure before giving up.
    size_t m_tcam_single_width_key_weight;       ///< Weighted load on TCAM of a single width key.
    size_t m_tcam_double_width_key_weight;       ///< Weighted load on TCAM of a double width key.
    size_t m_tcam_quad_width_key_weight;         ///< Weighted load on TCAM of a quad width key.

    // Trap ID
    const lpm_payload_t m_trap_destination;

    // Data members
    lpm_core_tcam_utils_scptr m_core_tcam_utils;                  ///< TCAM utils object.
    bucketing_tree_sptr m_tree;                                   ///< Tree containing the nodes and buckets in the LPM.
    vector_alloc<lpm_core_sptr> m_cores;                          ///< Vector of LPM cores.
    std::unique_ptr<lpm_distributor> m_distributor;               ///< Distributor TCAM.
    std::unique_ptr<lpm_top_hw_writer> m_hw_writer;               ///< LPM top writer.
    size_t m_actions_counter;                                     ///< Counts actions in LPM.
    size_t m_distributor_row_width;                               ///< Max width of distributor.
    std::array<distributor_state, 2> m_distributor_logical_state; ///< Distributor logical state per protocol.

    // State members
    vector_alloc<size_t> m_load_per_core[2];               ///< Vector per protocol counting number of weighted entries in core
                                                           /// weighted according to their resource consumption.
    resource_type m_resource_type_to_use_for_rebalance[2]; /// resource type per protocol for the current iteration.
    mutable cached_values m_load_per_group;                ///< Cached values of groups' load.
    std::array<bool, 2> m_last_insert_oor_per_protocol;    ///< Array holding whether last insert failed pre protocol.

    // Resource Monitor
    resource_monitor_sptr m_resource_monitor;
    size_t m_num_tcam_cells_per_core;
    size_t m_num_l2_bucket_per_core;
};

} // namespace silicon_one

#endif // __LEABA_LOGICAL_LPM_IMPL_IMPL_H__
