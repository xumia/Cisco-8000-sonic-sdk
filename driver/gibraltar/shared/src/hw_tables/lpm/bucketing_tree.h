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

#ifndef __LEABA_BUCKETING_TREE_H__
#define __LEABA_BUCKETING_TREE_H__

#include <array>

#include "binary_lpm_tree.h"
#include "common/la_status.h"
#include "common/ranged_index_generator.h"
#include "hw_tables/lpm_types.h"
#include "lld/ll_device.h"
#include "lpm/lpm_internal_types.h"
#include "lpm_bucketing_data.h"
#include "lpm_buckets_bucket.h"
#include "lpm_common.h"
#include "lpm_core_tcam_utils_base.h"
#include "lpm_hbm_cache_manager.h"
#include "lpm_hw_index_allocator_adapter.h"
#include "lpm_nodes_bucket.h"

/// @file

struct json_t;

namespace silicon_one
{

/// @brief LPM tree.
///
/// An LPM binary tree holding entries and their forwarding addresses, divided to buckets.
///
/// An LPM tree handles insertion, removal and modification of existing prefixes.
/// It performs grouping of prefixes into buckets.
///
/// Tree operations produce a changelist in bucket roots for higher-level trees ot TCAMs.
class bucketing_tree
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // static constexpr const char mambers:
    static constexpr const char* JSON_UNIQUE_PREFIXES_PER_LENGTH = "unique_prefixes_per_length";
    static constexpr const char* JSON_ENTRIES_PER_LENGTH = "entries_per_length";
    static constexpr const char* KEY_VALUE_KEY = "key";
    static constexpr const char* KEY_WIDTH_KEY = "key_width";
    static constexpr const char* ROOT_KEY = "root";
    static constexpr const char* SW_INDEX_KEY = "sw_index";
    static constexpr const char* HW_INDEX_KEY = "hw_index";
    static constexpr const char* DEFAULT_PAYLOAD_KEY = "default_payload";
    static constexpr const char* IS_VALID_KEY = "is_valid";
    static constexpr const char* PAYLOAD_KEY = "payload";
    static constexpr const char* TREE_SIZE_KEY = "tree_size";
    static constexpr const char* BUCKETING_DATA_KEY = "bucketing_data";
    static constexpr const char* L1_SW_INDEX_KEY = "l1_sw_index";
    static constexpr const char* L2_SW_INDEX_KEY = "l2_sw_index";
    static constexpr const char* GROUP_ID_KEY = "group_id";
    static constexpr const char* IS_BALANCED_KEY = "is_balanced";
    static constexpr const char* IS_SRAM_ONLY_KEY = "is_sram_only";
    static constexpr const char* BUCKETING_STATE_KEY = "bucketing_state";
    static constexpr const char* LEFT_KEY = "left";
    static constexpr const char* RIGHT_KEY = "right";
    static constexpr const char* BUCKETS_KEY = "buckets";
    static constexpr const char* L1_BUCKETS_KEY = "l1_buckets";
    static constexpr const char* L2_BUCKETS_KEY = "l2_buckets";
    static constexpr const char* CORE_KEY = "core";
    static constexpr const char* TREE_KEY = "tree";

    struct bucketing_tree_level_parameters {
        size_t num_of_sram_buckets;       ///< Number of buckets in SRAM.
        size_t num_of_hbm_buckets;        ///< Number of buckets in HBM.
        size_t buckets_per_sram_line;     ///< How many buckets in each SRAM row
        size_t bucket_num_fixed_entries;  ///< Maximum number of fixed entries in the bucket (cannot be shared with paired bucket).
        size_t bucket_num_shared_entries; ///< Maximum number of shared (with paired bucket) entries in the bucket.
        size_t num_of_sw_buckets;         ///< Maximum number of buckets to manipulate during iterations.
        bool support_double_entries;      ///< Indication whether double entries are allowed in the tree.
        lpm_bucket_ptr_vec bucket_vector; ///< Vector of buckets.
    };

    /// @brief Construct an empty LPM tree.
    ///
    /// @param[in]      ldevice                             Low level device this LPM tree is attached to.
    /// @param[in]      num_of_cores                        Number of cores in the device.
    /// @param[in]      num_of_groups                       Number of groups in the device.
    /// @param[in]      l2_double_bucket_size               Fixed L2 double bucket size. Buckets are stored in
    ///                                                     pairs; each pair size shouln't exceed this argument.
    /// @param[in]      l2_max_bucket_size                  Fixed maximum L2 bucket size allowed in tree.
    /// @param[in]      l2_max_num_of_sram_buckets          Fixed maximum L2 number of buckets in tree which can be stored in on-die
    /// SRAM.
    /// @param[in]      l2_max_num_of_hbm_buckets           Fixed maximum number of L2 buckets in tree which can be stored in HBM.
    /// @param[in]      l2_buckets_per_sram_line            Number of L2 buckets in a single SRAM row.
    /// @param[in]      l2_support_double_width_entries     Boolean specifies if double entries are allowed in level 2 of this tree.
    /// @param[in]      l1_double_bucket_size               Fixed double bucket size. Buckets are stored in
    ///                                                     pairs; each pair size shouln't exceed this argument.
    /// @param[in]      l1_max_bucket_size                  Fixed L1 maximum bucket size allowed in tree.
    /// @param[in]      l1_max_num_of_buckets               Fixed maximum number of L1 buckets in tree.
    /// @param[in]      l1_buckets_per_sram_line            Number of L1 buckets in a single SRAM row.
    /// @param[in]      l1_support_double_width_entries     Boolean specifies if double entries are allowed in level 1 of this tree.
    /// @param[in]      max_bucket_depth                    Fixed maximum number of bits comparable in a bucket.
    /// @param[in]      tcam_single_width_key_weight        Weighted load on TCAM of a single width key.
    /// @param[in]      tcam_double_width_key_weight        Weighted load on TCAM of a double width key.
    /// @param[in]      tcam_quad_width_key_weight          Weighted load on TCAM of a quad width key.
    /// @param[in]      trap_destination                    Payload of destination to raise a trap.
    /// @param[in]      core_tcam_utils                     Pointer to TCAM utils object.
    bucketing_tree(const ll_device_sptr& ldevice,
                   size_t num_of_cores,
                   size_t num_of_groups,
                   size_t l2_double_bucket_size,
                   size_t l2_max_bucket_size,
                   size_t l2_max_num_of_sram_buckets,
                   size_t l2_max_num_of_hbm_buckets,
                   size_t l2_buckets_per_sram_line,
                   bool l2_support_double_width_entries,
                   size_t l1_double_bucket_size,
                   size_t l1_max_bucket_size,
                   size_t l1_max_num_of_buckets,
                   size_t l1_buckets_per_sram_line,
                   bool l1_support_double_width_entries,
                   size_t max_bucket_depth,
                   size_t tcam_single_width_key_weight,
                   size_t tcam_double_width_key_weight,
                   size_t tcam_quad_width_key_weight,
                   lpm_payload_t trap_destination,
                   const lpm_core_tcam_utils_scptr& core_tcam_utils);

    /// @brief Destroy a tree.
    ~bucketing_tree();

    /// @brief      Get device of this LPM tree
    ///
    /// @return     ll_device_sptr of the LPM tree's device
    const ll_device_sptr& get_ll_device() const;

    /// @name LPM update API-s
    /// @{

    /// @brief Insert entry to tree.
    ///
    /// Insert entry to tree, rearrange in buckets and generate changes to the next level.
    ///
    /// @param[in]      key                     Key of entry to insert.
    /// @param[in]      payload                 Payload of entry to insert.
    /// @param[out]     out_actions_per_core    L2/L1 changes in the tree.
    ///
    /// @return #la_status.
    la_status insert(const lpm_key_t& key, lpm_payload_t payload, lpm_implementation_desc_vec_levels_cores& out_actions_per_core);

    /// @brief Remove entry from tree.
    ///
    /// Remove entry from tree, rearrange in buckets and generate changes to the next level.
    ///
    /// @param[in]      key                     Key of entry to remove.
    /// @param[out]     out_actions_per_core    L2/L1 changes in the tree.
    ///
    /// @return #la_status.
    la_status remove(const lpm_key_t& key, lpm_implementation_desc_vec_levels_cores& out_actions_per_core);

    /// @brief Modify an entry's payload.
    ///
    /// Modify a speciefic entry's payload, no changes to the next level.
    ///
    /// @param[in]      key                     Key of entry to modify.
    /// @param[in]      payload                 New payload.
    /// @param[out]     out_actions_per_core    L2/L1 changes in the tree.
    ///
    /// @return #la_status.
    la_status modify(const lpm_key_t& key, lpm_payload_t payload, lpm_implementation_desc_vec_levels_cores& out_actions_per_core);

    /// @brief Bulk update.
    ///
    /// API to perform multiple updates of various actions, rearrange in buckets and generate changes to the next level.
    ///
    /// @param[in]      actions                 Actions vector containing updates.
    /// @param[out]     out_actions_per_core    L2/L1 changes in the tree.
    /// @param[out]     out_failed_core         In case of OOR failure, which core has failed.
    ///
    /// @return Next level actions needed as a result of this level changes.
    la_status update(const lpm_implementation_desc_vec& actions,
                     lpm_implementation_desc_vec_levels_cores& out_actions_per_core,
                     size_t& out_failed_core);

    /// @brief Withdraw tree to the state before last update (nodes and buckets).
    void withdraw();

    /// The changes cannot be withdrawn after calling this function.
    void commit();

    /// @}

    /// @name LPM data access
    /// @{

    /// @brief Get bucket according to the given core and HW index.
    ///
    /// @param[in]      core_id                 Core this bucket belongs to.
    /// @param[in]      level                   Level of the requested bucket.
    /// @param[in]      hw_index                HW index of bucket to get.
    ///
    /// @return Requested bucket.
    lpm_bucket* get_bucket_by_hw_index(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index);

    /// @brief Get const bucket according to the given core and HW index.
    ///
    /// @param[in]      core_id                 Core this bucket belongs to.
    /// @param[in]      level                   Level of the requested bucket.
    /// @param[in]      hw_index                HW index of bucket to get.
    ///
    /// @return Requested const bucket.
    const lpm_bucket* get_bucket_by_hw_index(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index) const;

    /// @brief Get neighbor bucket of the bucket with the given HW index on the given core.
    ///
    /// @param[in]      core_id                 Core the buckets belong to.
    /// @param[in]      level                   Level of the requested bucket.
    /// @param[in]      hw_index                HW index of the bucket whose neighbor is to be returned.
    ///
    /// @return Neighbor bucket.
    lpm_bucket* get_neighbor_bucket(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index);

    /// @brief Get const neighbor bucket of the bucket with the given HW index on the given core.
    ///
    /// @param[in]      core_id                 Core the buckets belong to.
    /// @param[in]      level                   Level of the requested bucket.
    /// @param[in]      hw_index                HW index of the bucket whose neighbor is to be returned.
    ///
    /// @return const Neighbor bucket.
    const lpm_bucket* get_neighbor_bucket(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index) const;

    /// @brief Get all tree buckets.
    ///
    /// @param[in]      level                   Level of the requested buckets.
    ///
    /// @return List of all tree buckets.
    lpm_bucket_const_ptr_vec get_buckets(lpm_level_e level) const;

    /// @brief Get group to core mapping.
    ///
    /// @return group to core vector.
    const vector_alloc<size_t>& get_group_to_core() const;

    /// @brief Assign a new HW index to bucket according to new location.
    ///
    /// @param[in]      core_id                     Core this bucket belongs to.
    /// @param[in]      src_hw_index                HW index of the bucket to move.
    /// @param[in]      destination                 Destination of movement.
    /// @param[out]     out_l2_bucket               L2 bucket to be written to HW.
    /// @param[out]     out_l1_changed_buckets      Vector of L1 that affected by moving the L2 bucket to be written to HW.
    ///
    /// @return #la_status.
    la_status move_l2_bucket_between_sram_and_hbm(size_t core_id,
                                                  lpm_bucket_index_t src_hw_index,
                                                  l2_bucket_location_e destination,
                                                  lpm_bucket*& out_l2_bucket,
                                                  lpm_bucket_raw_ptr_vec& out_l1_changed_buckets);

    /// @brief Assign a given HW index to bucket.
    ///
    /// @param[in]      core_id                     Core this bucket belongs to.
    /// @param[in]      src_hw_index                HW index of the bucket to move.
    /// @param[in]      new_hw_index                HW index to be assigned.
    /// @param[out]     out_l2_bucket               L2 bucket to be written to HW.
    /// @param[out]     out_l1_changed_buckets      Vector of L1 that affected by moving the L2 bucket to be written to HW.
    ///
    /// @return #la_status.
    la_status move_l2_bucket_to_row(size_t core_id,
                                    lpm_bucket_index_t src_hw_index,
                                    lpm_bucket_index_t new_hw_index,
                                    lpm_bucket*& out_l2_bucket,
                                    lpm_bucket_raw_ptr_vec& out_l1_changed_buckets);

    /// @brief Collect and update the affected L1 buckets due the l2_bucket HW index change.
    ///
    /// @param[in]      l2_bucket               Bucket to be moved.
    /// @param[out]     out_l1_changed_buckets  Vector of L1 that affected by moving the L2 bucket to be written to HW.
    void update_l1_buckets_after_moving_l2_bucket(lpm_bucket* l2_bucket, lpm_bucket_raw_ptr_vec& out_l1_changed_buckets);

    /// @brief Get root node.
    ///
    /// @return Root node.
    const lpm_node* get_root_node() const;

    /// @brief Find a node in tree according to key.
    ///
    /// Find a node or (if node doesn't exist) a node insertion spot in tree according to a given key.
    ///
    /// @param[in]      key             Key of requested node or insertion spot.
    ///
    /// @return Requested node, or insertion spot of requested node.
    const lpm_node* find_node(const lpm_key_t& key) const;

    /// @brief Get the default destination for a specific key.
    ///
    /// @param[in]      key       Root of the bucket.
    ///
    /// @return default payload.
    lpm_payload_t get_l2_default_payload(const lpm_key_t& key) const;

    /// @brief Get the payload inherited by the given node.
    ///
    /// @param[in]      node       Node to find its payload.
    ///
    /// @return ancestor payload.
    lpm_payload_t get_node_ancestor_payload(const lpm_node* node) const;

    /// @brief Get the default L2 bucket for a specific key.
    ///
    /// @param[in]      key       Root of the bucket.
    ///
    /// @return default L2 bucket.
    const lpm_bucket* get_l1_default_bucket(const lpm_key_t& key) const;

    /// @brief Get the group this node belongs to.
    ///
    /// @param[in]      node        Node to look its group.
    ///
    /// @return Group ID containing the node.
    size_t get_owner_group(const lpm_node* node) const;

    /// @brief Find a node's bucket in the tree.
    ///
    /// @param[in]      node            Node to search its bucket.
    /// @param[in]      level           Level of the requested bucket.
    ///
    /// @return Requested bucket, if exists, otherwise nullptr.
    lpm_bucket* get_bucket(const lpm_node* node, lpm_level_e level) const;

    /// @brief Find a key's bucket in the tree.
    ///
    /// @param[in]      key            Node to search its bucket.
    /// @param[in]      level          Level of the requested bucket.
    ///
    /// @return Requested bucket, if exists, otherwise undefined.
    lpm_bucket* get_bucket(const lpm_key_t& key, lpm_level_e level) const;

    /// @brief Find longest prefix match of given key as returned by the HW.
    ///
    /// Lookup in the given bucket as the HW does and return its payload.
    ///
    /// @param[in]      key                     Key to lookup.
    /// @param[in]      core_id                 Core to perform the lookup.
    /// @param[in]      level                   Level of the lookup.
    /// @param[in]      hw_bucket_index         Payload representing HW index of bucket to look in.
    /// @param[out]     out_hit_key             Key of hit entry.
    /// @param[out]     out_hit_payload         Payload of hit entry.
    /// @param[out]     out_is_default          True if the bucket returns its default value, false if hit a contained entry.
    ///
    /// @return #la_status.
    la_status lookup(const lpm_key_t& key,
                     size_t core_id,
                     lpm_level_e level,
                     lpm_payload_t hw_bucket_index,
                     lpm_key_t& out_hit_key,
                     lpm_payload_t& out_hit_payload,
                     bool& out_is_default) const;

    /// @brief Find subtree with requested weighted size.
    ///
    /// Find key of a subtree, whose size is the closest to given size, without crossing group's border.
    ///
    /// @param[in]      requested_weighted_size     Requested subtree weighted size.
    /// @param[in]      from_core_group_roots_keys  Group roots of all candidate groups.
    /// @param[in]      max_width                   Max allowed key width to break at (due to distributor hardware limitation).
    /// @param[out]     out_from_group              The group the returened subtree belongs to.
    /// @param[out]     out_subtree_key             Key of subtree of group which is as closest to requested_weighted_size as
    /// possible.
    /// @param[out]     out_achieved_weighted_size  Closes weighted size to requested_weighted_size that could be achieved.
    void find_subtree_with_given_weighted_size(const resource_descriptor& requested_weighted_size,
                                               const lpm_key_vec& from_core_group_roots_keys,
                                               size_t max_width,
                                               size_t& out_from_group,
                                               lpm_key_t& out_subtree_key,
                                               size_t& out_achieved_weighted_size) const;

    /// @brief Get load of all the cores.
    ///
    /// Get load on each core related to the given protocol.
    ///
    /// @param[in]      protocol                Calculate load of prefixes only from this protocol.
    /// @param[out]     out_load_per_core       Load per core.
    void calculate_prefixes_load_per_core(lpm_ip_protocol_e protocol, vector_alloc<size_t>& out_load_per_core) const;

    /// @brief Get load of a group according to the given resource.
    ///
    /// @param[in]       group_id                    Group ID.
    /// @param[in]       group_root_key              Key which is root of the group.
    /// @param[in]       resource                    Load resource to check prefixes/TCAM.
    ///
    /// @return Load of this group.
    size_t get_load_of_group(size_t group_id, const lpm_key_t group_root_key, resource_type resource) const;

    /// @brief Get reference to HBM cache manager of a given core.
    ///
    /// @param[in]       core_id            Core of the requested HBM cache manager.
    ///
    /// @return Reference to HBM cache manager.
    lpm_hbm_cache_manager& get_hbm_cache_manager(size_t core_id);

    lpm_hw_index_allocator_adapter_sptr get_hw_index_allocator(size_t core_id, lpm_level_e level) const;

    /// @brief Get number of free SRAM bucekts in the given core..
    ///
    /// @param[in]      core_id                Core of the requested free SRAM space.
    ///
    /// @return Number of free SRAM buckets.
    size_t get_free_space_in_sram(size_t core_id) const;

    /// @brief Get all L1 buckets which their default is affected by L2 bucket change.
    ///
    /// @param[in]      l2_bucket       Changed L2 bucket
    ///
    /// @return Vector of L1 buckets affected by the L2 change.
    lpm_bucket_raw_ptr_vec get_l1_buckets_default_changed(const lpm_bucket* l2_bucket);

    /// @}

    /// @name Statistics generation.
    /// @{

    /// @brief Get LPM tree parameters.
    ///
    /// @param[in]      level               Level to query its parameters.
    ///
    /// @return Number of free SRAM buckets.
    bucketing_tree::bucketing_tree_level_parameters get_parameters(lpm_level_e level) const;

    /// @brief Get the maximum supported bucket depth.
    ///
    /// Bucket depth is the longest distance between a bucket root width and its longest entry's width.
    ///
    /// @return Maximum supported bucket depth.
    size_t get_max_bucket_depth() const;

    /// @brief Get LPM tree current occupancy.
    ///
    /// @param[in]      level                  Level to get its occupancy.
    core_buckets_occupancy_vec get_occupancy(lpm_level_e level) const;

    /// @brief Get last update input actions type distribution.
    lpm_action_statistics get_action_distribution_stats() const;

    /// @brief Get total input actions type distribution.
    lpm_action_statistics get_total_action_distribution_stats() const;

    /// @}

    /// @brief Utility to check integrity of internal data structures.
    bool sanity() const;

    /// @brief Creates a JSON representation of the tree.
    ///
    /// @retval JSON representation of the tree
    json_t* tree_to_json() const;

    /// @brief Creates a JSON representation of LPM statistics that
    /// includes distribution and length of prefixes.
    ///
    /// @retval JSON representation of the lpm entries distribution
    /// and lengths.
    json_t* prefixes_statistics_to_json() const;

    /// @brief Check for unbalanced violation.
    ///
    /// Unbalanced is property of node which indicates whether all subtree below it is maximum utilized.
    /// Check recursively that for given node there is no balanced node above unbalanced node.
    ///
    /// @param[in]      node             Node to check.
    ///
    /// @return True if all unbalanced nodes are above all the balanced ones.
    bool sanity_check_is_balanced_integrity(const lpm_node* node) const;

    /// @brief Check L2 buckets integrity.
    ///
    /// @return True if all buckets are legal buckets.
    bool sanity_l2_buckets() const;

    /// @brief Check L1 buckets integrity.
    ///
    /// @return True if all buckets are legal buckets.
    bool sanity_l1_buckets() const;

    /// @brief Check all nodes' integrity.
    ///
    /// @return True if all nodes' data structure is valid.
    bool sanity_nodes() const;

    /// @brief Utility to check node belonging to bucket.
    ///
    /// @return True iff node is HW destined and bucketed correctly.
    bool sanity_node_belong_to_bucket(const lpm_node* node) const;

    /// @brief Check all nodes bucketing data.
    ///
    /// @return True if all nodes' data structure is valid.
    bool sanity_bucketing_data() const;

    /// @brief Check if tree is empty.
    ///
    /// Check if the tree root node has no valid children.
    ///
    /// @return true if empty, false otherwise.
    bool empty() const;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    bucketing_tree();

    /// @brief Enum used to track changes.
    enum lpm_change_e {
        BUCKET_CHANGED,  ///< Bucket has been changed. After the change, it should be written at a different location. As an
                         ///< implication, upper level tree should be updated as well.
        BUCKET_REFRESHED ///< Bucket has been refreshed. It should be re-written. Can be done at the same location. There are no
        ///< implications to the upper level tree.
    };

    static constexpr size_t HBM_REFRACTORY_PERIOD_USEC = 10; ///< Time to wait before reusing a HBM bucket.

    using lpm_hbm_cache_manager_vec = vector_alloc<lpm_hbm_cache_manager>;
    using time_point_vec = vector_alloc<std::chrono::steady_clock::time_point>;
    using lpm_bucket_index_set = set_alloc<lpm_bucket_index_t>;
    using lpm_bucket_index_vec = vector_alloc<lpm_bucket_index_t>;
    using lpm_l2_buckets_set = set_alloc<lpm_nodes_bucket*>;
    using lpm_node_set = set_alloc<lpm_node*>;
    using lpm_key_set = set_alloc<lpm_key_t, key_less_operator>;
    using key_to_index_map = map_alloc<lpm_key_t, size_t, key_less_operator>;
    using key_to_index_map_vec = vector_alloc<map_alloc<lpm_key_t, size_t, key_less_operator> >;
    using key_to_bucketing_data_vec = vector_alloc<std::pair<lpm_key_t, lpm_bucketing_data> >;
    using key_to_valid_state = vector_alloc<std::pair<lpm_key_t, bool> >;

    using node_and_l2_bucket = std::pair<lpm_node*, lpm_nodes_bucket*>;
    using node_and_l2_bucket_vec = vector_alloc<node_and_l2_bucket>;

    // Help struct for tracking changes in bucket.
    // Contains the original data of the bucket to restore it in case of withdraw.
    struct lpm_changed_bucket_data {
        lpm_key_t root;
        lpm_bucket_index_t hw_index;
        size_t core_id;
        size_t hotness_level;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(lpm_changed_bucket_data)

    struct changed_bucket_data {
        lpm_bucket_index_t bucket_index;     ///< Changed bucket's SW index.
        lpm_change_e change_type;            ///< Type of change: REFRESHED/CHANGED.
        lpm_changed_bucket_data bucket_data; ///< Old bucket's data.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(changed_bucket_data)

    using changed_bucket_data_vec = vector_alloc<changed_bucket_data>;

    /// @brief Decision how to rebucket.
    enum class merge_decision_e {
        NEW,        ///< Create new bucket.
        PULL_LEFT,  ///< Pull left child's buckets.
        PULL_RIGHT, ///< Pull right child's buckets.
        MERGE,      ///< Merge 2 children's buckets.
        NONE,       ///< Close both buckets.
    };

    /// @brief Enum representing the relation between L2 bucket and prefix.
    enum class key_depth_class {
        SINGLE_ENTRY, ///< Key will be written in single entry.
        DOUBLE_ENTRY, ///< Key will be written in double entry.
        NOT_IN_RANGE, ///< Key is too deep or not contained by the root.
    };

    // Helper struct for return values of the recursion find_subtree_with_given_size_rec_help().
    // Contains returned node, returned size and total subtree size.
    struct find_subtree_ret_data {
        const lpm_node* ret_node = nullptr;
        size_t ret_weighted_size = 0 /* ret_weighted_size (don't care if ret_node is nullptr) */;
        size_t subtree_weighted_size = 0;
    };

    struct sw_bucket_allocator {
        mutable lpm_bucket_ptr_vec bucket_vector; ///< Vector of buckets.
        ranged_index_generator free_indices;      ///< Vector holding the free slots in the buckets' vector.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(sw_bucket_allocator)

    struct hw_bucket_allocator {
        lpm_hw_index_allocator_adapter_sptr hw_index_allocator;
        lpm_bucket_index_vec hw_index_to_sw_index; ///< Vector mapping from Hw index to bucket' vector index.
        time_point_vec bucket_release_time;        ///< Time of bucket release.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(hw_bucket_allocator)

    using hw_bucket_allocator_array = std::array<hw_bucket_allocator, NUM_LEVELS>;
    using hw_bucket_allocator_array_vec = vector_alloc<hw_bucket_allocator_array>;

    struct bucketing_tree_level_iteration_members {
        bit_vector affected_buckets_bitmap;                 ///< Bitmap indicator for buckets that should be written to HW.
        vector_alloc<size_t> bucket_sw_idx_to_changed_data; ///< Map from bucket's SW index to its changed_data.
        changed_bucket_data_vec affected_buckets_data;      ///< Bucket's data from the beginning of the iteration.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(bucketing_tree_level_iteration_members)

    /// @name Main algorithms
    /// @{

    /// @brief Perform bulk update.
    ///
    /// Perform multiple updates of various actions, rearrange in buckets and generate
    /// changes to the next level.
    ///
    /// @param[out]     out_l1_actions          Changes related to L1 buckets.
    /// @param[out]     out_l2_actions          Changes related to L2 buckets.
    ///
    /// @return Next level actions needed as a result of this level changes.
    la_status do_update(lpm_implementation_desc_vec& out_l1_actions, lpm_implementation_desc_vec& out_l2_actions);

    /// @brief Group tree to buckets.
    ///
    /// Recursively go over every unbucketed node in tree bottom up, group them to buckets.
    ///
    /// Update flows are done by invoking a series of update_tree_topology calls, then calling rebucket to finilize bucket
    /// configuration.
    ///
    /// @param[in]      core_id         Core to take the HW resources from.
    /// @param[in]      node            Node to start from.
    ///
    /// @return #la_status.
    la_status rebucket(size_t core_id, lpm_node* node);

    /// @brief Check and rebucket/skip node.
    ///
    /// Checks what should be done for the a given node after both children are bucketed and does it.
    ///
    /// @param[in]      core_id         Core to take the HW resources from.
    /// @param[in]      node            Node to bucket.
    ///
    /// @return #la_status.
    la_status rebucket_node(size_t core_id, lpm_node* node);

    /// @brief Rebucket/skip node.
    ///
    /// Perform rebucketing as defines by the given instructions.
    ///
    /// @param[in]      core_id         Core to take the HW resources from.
    /// @param[in]      node            Node to bucket.
    /// @param[in]      merge_decision  Rebuck information containing L2 bucketing action.
    /// @param[out]     out_l2_bucket   L2 bucket contains this node after rebucketing.
    ///
    /// @return #la_status.
    la_status rebucket_l2(size_t core_id, lpm_node* node, merge_decision_e merge_decision, lpm_nodes_bucket*& out_l2_bucket);

    /// @brief Rebucket the L2 bucket contains this node into L1 bucket.
    ///
    /// Performs L1 bucketing based on provided instruction.
    ///
    /// @param[in]      core_id                 Core to take the HW resources from.
    /// @param[in]      node                    Node to bucket its L2 bucket.
    /// @param[in]      merge_decision          Rebucket information containing L1 bucketing action.
    /// @param[in]      add_new_l2_bucket       If not nullptr, L2 bucket to add the the chosen L1 bucket.
    ///
    /// @return #la_status.
    la_status rebucket_l1(size_t core_id, lpm_node* node, merge_decision_e merge_decision, bool add_new_l2_bucket);

    /// @brief Iterate over all actions and update tree topology.
    ///
    /// As side effect, unbucket all paths to all nodes.
    ///
    /// @param[in]      actions            Actions to execute.
    ///
    /// @return #la_status.
    la_status update_tree_topology(const lpm_implementation_desc_vec& actions);

    /// @brief Insert a new node and unbucket the path from the root to it.
    ///
    /// Insert a new node with key and payload to tree, unbucketing every node in path to new node.
    ///
    /// @param[in]      key             Key of new node.
    /// @param[in]      payload         Payload of new node.
    /// @param[in]      sram_only       Predicate indicates whether is SRAM only.
    ///
    /// @return #la_status.
    la_status insert_node(const lpm_key_t& key, lpm_payload_t payload, bool sram_only);

    /// @brief Insert a new distributor node.
    ///
    /// Insert a new group root node with key, payload and group_id.
    ///
    /// @param[in]      insertion_point     The insertion point in the tree.
    /// @param[in]      key                 Key of the new group root.
    /// @param[in]      core_id             Core ID this group belongs to.
    /// @param[in]      group_id            Group ID of the distributer node.
    ///
    /// @return The new group root node.
    lpm_node* insert_group_root_to_tree(lpm_node* insertion_point, const lpm_key_t& key, size_t core_id, size_t group_id);

    /// @brief Fix bucketing_data integrity after creating new group root.
    ///
    /// Adding new group root might cause a new invalid node creation. This node's bucketing_data should be updated as it can be in
    /// the middle of a bucket.
    /// Handles the new-just-created parent of the new group root.
    ///
    /// @param[in]      group_root_node     The just created group root node.
    /// @param[in]      insertion_point     Insertion point of the group_root_node.
    void fix_bucketing_data_after_new_group_root(lpm_node* group_root_node, lpm_node* insertion_point);

    /// @brief Mark all nodes as unbucketed within an empty group.
    ///
    /// Handles old invalid nodes that is now part of the group.
    ///
    /// @param[in]      group_root_node     Starting point to unbucket.
    void unbucket_invalid_nodes_within_an_empty_group(lpm_node* group_root_node);

    /// @brief Remove a valid node from the tree.
    ///
    /// Remove an existing node with specific key from tree.
    ///
    /// @param[in]      key                 Key of new node.
    ///
    /// @return #la_status.
    la_status remove_node(const lpm_key_t& key);

    /// @brief Remove a distributor node from the tree.
    ///
    /// @param[in]      key                 Key of new node.
    ///
    /// @return #la_status.
    la_status remove_group_root(const lpm_key_t& key);

    /// @brief Modify the core of the given group.
    ///
    /// @param[in]      group_root_key            Key of the group root.
    /// @param[in]      group_id                  Group to change its core.
    /// @param[in]      core_id                   Core to move the group to.
    ///
    /// @return #la_status.
    la_status modify_group_to_core(const lpm_key_t& group_root_key, size_t group_id, size_t core_id);

    /// @brief Starting with a given node unbucket all nodes within its group's region.
    ///
    /// @param[in]      cut_node            Node to start unbucking from.
    void cut_l1_l2_buckets(lpm_node* cut_node);

    /// @brief Go over changed buckets and add them to the changed-bucket-list.
    ///
    /// @param[in]      l1_bucket           L1 bucket that might have changed.
    /// @param[in]      l2_buckets          Set of L2 buckets that might have changed.
    void mark_changed_buckets(lpm_buckets_bucket* l1_bucket, const lpm_l2_buckets_set& l2_buckets);

    /// @brief Fix bucketing data after cutting L1 in the middle.
    ///
    /// @param[in]      l1_bucket           L1 bucket that was cut.
    /// @param[in]      l2_bucket           L2 bucket that was cut.
    /// @param[in]      cut_node            Node where it was cut.
    void fix_bucketing_data_after_cut_l1_l2_buckets(lpm_buckets_bucket* l1_bucket, lpm_nodes_bucket* l2_bucket, lpm_node* cut_node);

    /// @brief Unbucket the path to a given key.
    ///
    /// Unbucket every node starting the root of the given ye.
    ///
    /// @param[in]      key                     Key for the path to unbuckets.
    ///
    /// @return #la_status.
    la_status unbucket(const lpm_key_t& key);

    /// @brief Modify a node's payload.
    ///
    /// @param[in]      key             Key of node to be modified.
    /// @param[in]      payload         Payload to write in requested node.
    ///
    /// @return #la_status.
    la_status do_modify(const lpm_key_t& key, lpm_payload_t payload, bool is_modify_group);

    /// @brief Perform node modification.
    ///
    /// Update the node default, marking its bucket as refreshed and notify lower buckets on default change if needed.
    ///
    /// @param[in]      node            Node to change its payload.
    /// @param[in]      payload         Payload to write in requested node.
    ///
    /// @return #la_status.
    la_status modify_node(lpm_node* node, lpm_payload_t payload);

    /// @brief Remove Node from an L2 bucket.
    ///
    /// Remove node from the bucket and legalize the tree data stucture.
    ///
    /// @param[in]      l2_bucket           Bucket contains the node.
    /// @param[in]      node                Node to remove.
    void fast_remove_node_from_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* node);

    /// @brief Remove node from an L2 bucket in case it's the only prefix in it.
    ///
    /// Remove node from the bucket and release it.
    ///
    /// @param[in]      l2_bucket           Bucket contains the node.
    /// @param[in]      node                Node to remove.
    void fast_remove_release_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* current_node);

    /// @brief Remove node from an L2 bucket in case it's the bucket's top node.
    ///
    /// @param[in]      l2_bucket           Bucket contains the node.
    /// @param[in]      current_node        Node to remove.
    void fast_remove_top_node_from_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* current_node);

    /// @brief Remove node from an L2 bucket where the node's parent belongs to the bucket.
    ///
    /// @param[in]      l1_bucket           L1 bucket contains the node.
    /// @param[in]      l2_bucket           L2 bucket contains the node.
    /// @param[in]      node                Node to remove.
    void fast_remove_node_bottom_up(lpm_buckets_bucket* l1_bucket, lpm_nodes_bucket* l2_bucket, lpm_node* node);

    /// @brief Fix tree integrity after L2 bucket release.
    ///
    /// @param[in]      l1_bucket           L1 bucket containing the L2 released bucket.
    /// @param[in]      l2_bucket           Bucket that was released.
    /// @param[in]      node                Node to remove.
    void clear_bucketing_data_after_release_l2_bucket(lpm_buckets_bucket* l1_bucket, lpm_nodes_bucket* l2_bucket, lpm_node* node);

    /// @brief Updates node's bucketing_data after its remove from L2 bucket.
    ///
    /// Assumes this node is no longer belongs to l2 bucket and checks whether it in range of l1 bucket.
    ///
    /// @param[in]      node                Node to remove.
    /// @param[in]      l1_bucket           L1 bucket contains the L2 bucket that used to contain the node.
    void downgrade_bucketing_state(lpm_node* node, lpm_buckets_bucket* l1_bucket);

    /// @brief Check if L1 bucket has members (L2 buckets' roots) below a given key.
    ///
    /// @param[in]      l1_bucket           Bucket to check its members.
    /// @param[in]      key                 Key to check the members against.
    ///
    /// @return True if L1 bucket has at least one L2 root below key, false otherwise.
    bool does_l1_has_l2_below_key(lpm_buckets_bucket* l1_bucket, const lpm_key_t& key) const;

    /// @brief Check if node and its parent belong to the same L2 bucket.
    ///
    /// @param[in]      node                 Node to check.
    ///
    /// @return True if node and its parent belong to same bucket, false otherwise.
    bool does_node_belong_to_same_l2_bucket_as_its_parent(const lpm_node* node) const;

    /// @brief Check if node is a distributer group point.
    ///
    /// @param[in]      node                 Node to check.
    ///
    /// @return True if node is a distributer node, false otherwise.
    static inline bool is_node_group_root(const lpm_node* node);

    /// @brief Check if node is in bucket's region (L1 or L2).
    ///
    /// @param[in]      node                 Node to check.
    ///
    /// @return True if node is a distributer node, false otherwise.
    bool is_node_in_bucket_region(const lpm_node* node) const;

    /// @brief Insert group root to the tree.
    ///
    /// @param[in]      group_root_key          Group root to add to the tree.
    /// @param[in]      group_id                Group ID of the new group.
    /// @param[in]      core_id                 Core this group belongs to.
    ///
    /// @return #la_status.
    la_status add_group_root(const lpm_key_t& group_root_key, size_t group_id, size_t core_id);

    /// @brief Generate L1/L2 level actions according to modified buckets.
    ///
    /// Go over every modified bucket, and choose an action for it (insert/remove/modify).
    ///
    /// @param[out]     out_actions_per_core    All changes to all cores for L1/L2.
    /// @param[out]     out_failed_core         In case of OOR failure, which core has failed.
    ///
    /// @return #la_status.
    la_status modified_buckets_to_actions(lpm_implementation_desc_vec_levels_cores& out_actions_per_core, size_t& out_failed_core);

    /// @brief Calculate default entries for all changed/refreshed buckets.
    ///
    /// Calculating default entries to all changed/refreshed L1/L2 buckets.
    void calculate_default_entries();

    /// @brief Generate next level actions according to modified buckets.
    ///
    /// Go over every modified bucket, and choose an action for it (insert/remove/modify).
    ///
    /// @param[in]      level                   Level to calculate its changes.
    /// @param[out]     out_actions_per_core    All changes to all cores for L1/L2.
    /// @param[out]     out_failed_core         In case of OOR failure, which core has failed.
    ///
    /// @return #la_status.
    la_status modified_buckets_to_actions(lpm_level_e level,
                                          lpm_implementation_desc_vec_levels_cores& out_actions_per_core,
                                          size_t& out_failed_core);

    /// @brief Release modified buckets.
    ///
    /// Delete empty buckets and return it to the pool.
    void release_empty_buckets();

    /// @brief Create a new software bucket
    ///
    /// @param[in]      level            Level to allocate bucket for.
    /// @param[in]      sw_index         SW index of bucket to allocate.
    ///
    /// @return Allocated bucket.
    lpm_bucket_sptr create_sw_bucket(lpm_level_e level, lpm_bucket_index_t sw_index) const;

    /// @brief Find a node's L1 bucket that contains the L2 bucket of this node.
    ///
    /// @param[in]      node            Node to search its bucket.
    ///
    /// @return Requested bucket, if exists, otherwise nullptr.
    lpm_buckets_bucket* get_l1_bucket(const lpm_node* node) const;

    /// @brief Find a node's L2 bucket in the tree.
    ///
    /// @param[in]      node            Node to search its bucket.
    ///
    /// @return Requested bucket, if exists, otherwise nullptr.
    lpm_nodes_bucket* get_l2_bucket(const lpm_node* node) const;

    /// @brief Find a node's L2 bucket in the tree.
    ///
    /// Under constraint that the the bucket's root must contain the key
    ///
    /// @param[in]      node            Node to search its bucket.
    /// @param[in]      key             Constraint key.
    ///
    /// @return Requested bucket, if exists, otherwise nullptr.
    lpm_nodes_bucket* get_containing_l2_bucket(const lpm_node* node, const lpm_key_t& key) const;

    /// @}

    /// @name Unbucket helper functions
    /// @{

    /// @brief Unbucket the path saved by the last find_node call.
    ///
    /// @param[in]      path_to_unbucket        Path to mark as unbucketed.
    void unbucket_path(const vector_alloc<lpm_node*>& path_to_unbucket);

    /// @brief Mark all nodes in the path spath_to_unbucketaved by the last find_node call as unbalanced.
    ///
    /// @param[in]      path_to_mark            Path of nodes to mark as unbalanced.
    void mark_unbalanced_nodes(const vector_alloc<lpm_node*>& path_to_mark);

    /// @brief Return node to unbucketed mode.
    ///
    /// This prepares the node for full bucketing later on, and is the first step in any change (insert/remove) that might affect
    /// this node.
    ///
    /// @param[in]      node            Node to remove from its bucket.
    /// @param[in]      next            Next node to remove.
    void unbucket_node(lpm_node* node, lpm_node* next);

    /// @brief Unbucket node.
    ///
    /// @param[in]      node            Node to remove from its bucket.
    void unbucket_node(lpm_node* node);

    /// @brief Unbucket all paths that their utilization might not be maximized.
    void unbucket_unbalanced_paths();

    /// @brief Unbucket node and its unbalanced children recursively.
    ///
    /// @param[in]      node            Node to unbucket.
    void unbucket_nodes_rec(lpm_node* node);

    /// @brief Add node to L2 bucket.
    ///
    /// @param[in]      inserted_node   Node to insert.
    /// @param[in]      l2_bucket       L2 bucket to insert the node to.
    void fast_insert_node_to_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* inserted_node);

    /// @brief Fix L2 bucket's data structure attributes.
    ///
    /// If needed fixes the L2 bucket's top_node and all the relevant surrounding nodes' bucketing_data.
    ///
    /// @param[in]      l2_bucket       L2 bucket that the node was inserted to.
    /// @param[in]      inserted_node   Node that was just inserted.
    void fast_insert_fix_buckets_structure(lpm_nodes_bucket* l2_bucket, lpm_node* inserted_node);

    /// @brief Check if fast_insert can be performed.
    ///
    /// Check if the new hw_destined node can be inserted to the L2 bucket without change of the surrounding buckets or the current
    /// bucket's root.
    ///
    /// @param[in]      l2_bucket               L2 bucket to contain the new node.
    /// @param[in]      new_prefix_key          Key of the new inserted prefix.
    /// @param[in]      insertion_point         Insertion point in the tree of the given key.
    ///
    /// @return True if can add node to the L2 bucket without further changes.
    bool can_use_fast_insert(const lpm_nodes_bucket* l2_bucket,
                             const lpm_key_t& new_prefix_key,
                             const lpm_node* insertion_point) const;

    /// @brief Remove all buckets under given node stopping at distributer's nodes.
    ///
    /// @param[in]      node            Starting point.
    /// @param[in]      to_core         Core to move the buckets to.
    void move_bucketed_subtree(lpm_node* node, size_t to_core);

    /// @brief Return node to unbucketed mode.
    ///
    /// This prepares the node for full bucketing later on, and is the first step in any change (insert/remove) that might affect
    /// this node.
    ///
    /// @param[in]      node            Node to remove from its bucket.
    /// @param[in]      next_node       Next node to unbucet.
    /// @param[in]      sibling_node    Sibling node of the next node.
    void unbucket_l1(lpm_node* node, lpm_node* next_node, lpm_node* sibling_node);

    /// @brief Return node to unbucketed mode.
    ///
    /// This prepares the node for full bucketing later on, and is the first step in any change (insert/remove) that might affect
    /// this node.
    ///
    /// @param[in]      node            Node to remove from its bucket.
    /// @param[in]      next_node       Next node to unbucket.
    /// @param[in]      sibling_node    Sibling node of the next node.
    void unbucket_l2(lpm_node* node, lpm_node* next_node, lpm_node* sibling_node);

    /// @brief Split bucket into two different buckets.
    ///
    /// Remove every node that belong to the same bucket from start node and
    /// below to a new bucket.
    ///
    /// @param[in]      l2_bucket       L2 bucket to split.
    /// @param[in]      start_node      Node to start from.
    lpm_nodes_bucket* split_l2_bucket_at_node(lpm_nodes_bucket* l2_bucket, lpm_node* start_node);

    /// @brief Split L1 bucket into two different buckets.
    ///
    /// Remove every L2 bucket that belong to the same bucket from start node and
    /// below to a new bucket.
    ///
    /// @param[in]      from_bucket     Source L1 bucket to take its L2 buckets.
    /// @param[in]      node            Node to start from.
    lpm_buckets_bucket* split_l1_bucket_at_node(lpm_buckets_bucket* from_bucket, lpm_node* node);

    /// @brief Calculates bucket's top_node.
    ///
    /// Starts from the topmost node in the tree within the region of the bucket, calculates the top node of the bucket.
    ///
    /// @note top_node is the lowest point the bucket's root can be written. It's either a hw_destined() node or node with 2
    /// descendents in the bucket.
    ///
    /// @param[in]      bucket          Bucket to calculate its root.
    /// @param[in]      node            Original top node.
    void compute_top_node(lpm_nodes_bucket* bucket, lpm_node* node);

    /// @brief Remove node from tree.
    ///
    /// Topologic remove, no buckets involved. Deletes the removed node.
    ///
    /// @param[in]      node            Node to delete.
    void remove_node_from_tree(lpm_node* node);

    /// @brief Copy bucketing data before removing node.
    ///
    /// @param[in] node Node used to copy bucketing data.
    void copy_bucketing_data_before_removing(lpm_node* node);

    /// @brief Remove group root node from tree.
    ///
    /// Topologic remove, no buckets involved.
    ///
    /// @param[in]      group_root_node            Group root node to delete.
    void remove_group_root_from_tree(lpm_node* group_root_node);

    /// @brief Propagae bucketing_data attributes from the parent to its child.
    ///
    /// Before deleting parent, propagates its attributes to its child as it's the same logical point.
    ///
    /// @param[in]      parent              Node to delete.
    /// @param[in]      child               Node to propagates the parent's attributes.
    void copy_node_attributes_to_child(lpm_node* parent, lpm_node* child);

    /// @}

    /// @name Rebucket helper functions
    /// @{

    /// @brief Choose which child's bucket to add to.
    ///
    /// @param[in]      node            Node to choose which child's bucket to add to.
    ///
    /// @return Struct indicates how/if to rebucket this node.
    merge_decision_e choose_between_childrens_l2_buckets(const lpm_node* node) const;

    /// @brief Choose which child's L1 bucket should own the L2 bucket contains this node.
    ///
    ///
    ///
    /// @param[in]      node            Node to choose which child's bucket to add to.
    /// @param[in]      l2_choice       Rebucket information containing L2 bucketing action.
    ///
    /// @return Struct indicates how/if to rebucket this node.
    merge_decision_e choose_between_childrens_l1_buckets(const lpm_node* node, const merge_decision_e& l2_choice) const;

    /// @brief Check if bucket can contain entry in given length.
    ///
    /// @param[in]      bucket              Bucket to check.
    /// @param[in]      width               Width of the new entry.
    ///
    /// @return True if bucket can contain the entry, false otherwise.
    bool does_entry_fit_in_bucket_depth(const lpm_bucket* bucket, size_t width) const;

    /// @brief Check if bucket can contain entry.
    ///
    /// @param[in]      node                 Node to be added.
    /// @param[in]      child_node           Child node of the node.
    ///
    /// @return True if bucket can contain the entry, false otherwise.
    bool can_add_node_to_l2_bucket(const lpm_node* node, const lpm_node* child_node) const;

    /// @brief Check if L1 bucket can contain new L2 bucket that will be created in the given node.
    ///
    /// @param[in]      l1_bucket           L1 bucket to check.
    /// @param[in]      l2_root_node        Node that the new L2 bucket will be start from.
    ///
    /// @return true if can be added, false otherwise.
    bool can_add_l2_bucket_to_l1_bucket(const lpm_bucket* l1_bucket, const lpm_node* l2_root_node) const;

    /// @brief Count all buckets at the subtree of the given node.
    ///
    /// Count all the buckets at the subtree of the given node, even if hidden below other buckets, including the bucket of the
    /// node.
    ///
    /// @param[in]      node              Root node to start from.
    ///
    /// @return number of subtree buckets.
    size_t count_downstream_buckets(const lpm_node* node) const;

    /// @brief Check if can merge 2 L2 buckets.
    ///
    /// @param[in]      merge_node        Merge node.
    /// @param[in]      entries_to_add    How many entries to add to the combined bucket size during the check.
    ///
    /// @return whether a merge is possible.
    bool can_merge_l2_buckets(const lpm_node* merge_node, size_t entries_to_add) const;

    /// @brief Check if can merge 2 L2 buckets.
    ///
    /// @param[in]      root_width        Common root width.
    /// @param[in]      bucket0           Bucket to merge.
    /// @param[in]      bucket1           Bucket to merge.
    /// @param[in]      l2_change         Change in number of L2 sub-buckets. Can be -1, 0 or 1.
    ///
    /// @return whether a merge is possible.
    bool can_merge_l1_buckets(size_t root_width, const lpm_bucket* bucket0, const lpm_bucket* bucket1, int l2_change) const;

    /// @brief Merge two buckets.
    ///
    /// Move all nodes from the bucket of top_node2 to the bucket of top_node1, and delete the bucket of top_node2.
    ///
    /// @param[in]      to_bucket       Bucket to merge into.
    /// @param[in]      from_bucket     Bucket to delete.
    ///
    /// @return Merged bucket.
    lpm_nodes_bucket* merge_l2_buckets(lpm_nodes_bucket* to_bucket, lpm_nodes_bucket* from_bucket);

    /// @brief Merge two L1 buckets.
    ///
    /// Move all L2 buckets from L1 bucket to another L1 bucket.
    ///
    /// @param[in]      to_bucket       Bucket to merge into.
    /// @param[in]      from_bucket     Bucket to delete.
    ///
    /// @return Merged bucket.
    lpm_buckets_bucket* merge_l1_buckets(lpm_buckets_bucket* to_bucket, lpm_buckets_bucket* from_bucket);

    /// @brief Pull L2 root to the minimum legal width.
    ///
    /// @param[in]      start_node      Node with L2/L1 bucketing data.
    /// @param[in]      illegal_width   Illegal width the L2 root can't reach.
    void pull_l2_root_up(lpm_node* start_node, size_t illegal_width);

    /// @brief Pull L2 root to the minimum legal width.
    ///
    /// @param[in]      start_node      Node with L2/L1 bucketing data.
    /// @param[in]      illegal_width   Illegal width the L2 root can't reach.
    void do_pull_l2_root_up(lpm_node* start_node, size_t illegal_width);

    /// @brief Pull L1 root to the minimum legal width.
    ///
    /// @param[in]      start_node      Node with L1 bucketing data.
    /// @param[in]      stop_node       Node which L1 root can't reach.
    void pull_l1_root_up(lpm_node* start_node, size_t illegal_width);

    /// @brief Pull L1 root to the minimum legal width.
    ///
    /// @param[in]      start_node      Node with L1 bucketing data.
    /// @param[in]      illegal_width   Illegal width the L1 root can't reach.
    void do_pull_l1_root_up(lpm_node* start_node, size_t illegal_width);

    /// @brief Calculate bucket's default value.
    ///
    /// @param[in]      bucket          Bucket to calculate its default entry.
    void update_bucket_default_entry(lpm_bucket* bucket);

    /// @brief Reset bucket to its initial state.
    ///
    /// @param[in]      bucket          Bucket to reset.
    void reset_bucket(lpm_bucket* bucket);

    /// @brief Create a new bucket.
    ///
    /// @param[in]      core_id         The asking core to allocate the new bucket.
    /// @param[in]      level           Level of the requested bucket.
    ///
    /// @return The new bucket.
    lpm_bucket* allocate_bucket(size_t core_id, lpm_level_e level);

    /// @brief Add node to bucket.
    ///
    /// Set node's bucket to bucket. If node is valid then insert it into bucket and finilize bucket.
    ///
    /// @param[in]      node            Node to insert into bucket.
    /// @param[in]      bucket          Bucket to insert node into.
    void add_node_to_bucket(lpm_node* node, lpm_nodes_bucket* bucket);

    /// @brief Move src bucket nodes to dest bucket, starting from start node going down.
    ///
    /// Go over start node descendents and move every one of them that belong to the
    /// same bucket as start node to dest bucket.
    ///
    /// @param[in]      dest_bucket     Bucket to move nodes into.
    /// @param[in]      src_bucket      Bucket to move nodes from.
    /// @param[in]      src_start_node  Node to start from.
    void move_bucket_nodes(lpm_nodes_bucket* dest_bucket, lpm_nodes_bucket* src_bucket, lpm_node* src_start_node);

    /// @}

    /// @name Hardware indices handling
    /// @{

    /// @brief Release HW index.
    ///
    /// @param[in]      core_id            Core of the released HW index.
    /// @param[in]      level              Level of the released HW index.
    /// @param[in]      hw_index           HW index to release.
    void release_hw_index(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index);

    void notify_hw_index_occupancy_changed(const lpm_bucket* bucket);

    /// @brief Allocate a HW index for L2 bucket.
    ///
    /// @param[in]      core_id         Core the given bucket belongs to.
    /// @param[in]      bucket          Bucket to allocate index for.
    /// @param[out]     hw_index        Allocated HW index for bucket.
    ///
    /// @return #la_status.
    la_status allocate_hw_index_for_l2_bucket(size_t core_id, lpm_bucket* bucket, lpm_bucket_index_t& hw_index);

    /// @brief Allocate a HW index for L1 bucket.
    ///
    /// @param[in]      core_id         Core the given bucket belongs to.
    /// @param[in]      bucket          Bucket to allocate index for.
    /// @param[out]     hw_index        Allocated HW index for bucket.
    ///
    /// @return #la_status.
    la_status allocate_hw_index_for_l1_bucket(size_t core_id, lpm_bucket* bucket, lpm_bucket_index_t& hw_index);

    /// @brief Assign HW index for a bucket.
    ///
    /// @param[in]      core_id         Core the given bucket belongs to.
    /// @param[in]      bucket          Bucket to assign its HW index.
    /// @param[in]      hw_index        HW index for the given bucket.
    void allocate_hw_index_for_bucket_common(size_t core_id, lpm_bucket* bucket, lpm_bucket_index_t hw_index);

    /// @brief Check if bucket HW index is free.
    ///
    /// @param[in]     core_id          Core on which to perform the check..
    /// @param[in]     level            Tree level (L1/L2) on which to perform the check.
    /// @param[in]     hw_index         HW index of bucket to check for availability.
    ///
    /// @return Whether the HW index is free.
    bool is_hw_index_free(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index) const;

    /// @}

    /// @brief Get the key depth from bucket root to key.
    ///
    /// If L2 root is not contained in the key return NOT_IN_RANGE.
    ///
    /// @param[in]     bucket           Bucket to compare check the distance class from.
    /// @param[in]     key              Key to the the distance class.
    ///
    /// @return key_depth_class describing the relation between the L2 bucket's root and the key.
    key_depth_class get_key_depth_class(const lpm_bucket* bucket, const lpm_key_t& key) const;

    /// @brief Check if entries can fit into bucket.
    ///
    /// @param[in]      level            Level of the bucket.
    /// @param[in]      num_singles      Number of single entries.
    /// @param[in]      num_doubles      Number of double entries.
    ///
    /// @return True if bucket fit the space, false otherwise.
    bool does_bucket_fit_space(lpm_level_e level, size_t num_singles, size_t num_doubles) const;

    /// @brief Check if entries of a pair of buckets can fit into a double bucket.
    ///
    /// @param[in]      level             Level of the bucket.
    /// @param[in]      num_singles0      Number of single entries of first bucket.
    /// @param[in]      num_doubles0      Number of double entries of first bucket.
    /// @param[in]      num_singles1      Number of single entries of second bucket.
    /// @param[in]      num_doubles1      Number of double entries of second bucket.
    ///
    /// @return True if buckets fit the space, false otherwise.
    bool does_double_bucket_fit_space(lpm_level_e level,
                                      size_t num_singles0,
                                      size_t num_doubles0,
                                      size_t num_singles1,
                                      size_t num_doubles1) const;

    /// @}

    /// @name Changes tracking
    /// @{

    /// @brief Mark bucket as changed according to given change.
    ///
    /// @param[in]      bucket          Bucket to mark as changed.
    /// @param[in]      change          Change in bucket.
    void bucket_changed(lpm_bucket* bucket, lpm_change_e change);

    /// @brief Initialization of change-bucket struct from given bucket
    ///
    /// @param[in]      bucket          Bucket to mark as changed.
    ///
    /// @retval Initialized struct
    lpm_changed_bucket_data init_changed_bucket_struct(const lpm_bucket* bucket);

    /// @brief Mark as changed the buckets whose default is the given node's key.
    ///
    /// @param[in]      node            Node containing default key.
    /// @param[in]      payload         Payload to assign for group root nodes.
    void mark_changed_default_payload(lpm_node* node, lpm_payload_t payload);

    /// @}
    /// @brief Generate next level action according to modified bucket.
    ///
    /// @param[in]      level                  LPM level related to the bucket L1/L2.
    /// @param[in]      bucket                 Modified bucket.
    /// @param[in]      old_data               Old HW index and root of the bucket.
    /// @param[in,out]  out_actions_per_core   Action desctiptor vector to fill.
    /// @param[in,out]  key_to_desc_index      Map from a key to its desc index per core.
    /// @param[out]     out_failed_core        In case of OOR failure, which core has failed.
    ///
    /// @return #la_status.
    la_status modified_bucket_to_action(lpm_level_e level,
                                        lpm_bucket* bucket,
                                        const lpm_changed_bucket_data& old_data,
                                        lpm_implementation_desc_vec_levels_cores& out_actions_per_core,
                                        key_to_index_map_vec& key_to_desc_index,
                                        size_t& out_failed_core);

    /// @brief Get bucket according to SW index (that is regular bucket index).
    ///
    /// @param[in]      level           Level of the requested bucket.
    /// @param[in]      index           Index of bucket to get.
    ///
    /// @return Requested bucket.
    lpm_bucket* get_bucket_by_sw_index(lpm_level_e level, lpm_bucket_index_t index);

    /// @brief Get const bucket according to given index.
    ///
    /// @param[in]      level                   Level of the requested bucket.
    /// @param[in]      index                   Index of bucket to get.
    ///
    /// @return Requested const bucket.
    const lpm_bucket* get_bucket_by_sw_index(lpm_level_e level, lpm_bucket_index_t index) const;

    /// @brief Get the TCAM load of a L1 bucket (how much TCAM it consumes)
    ///
    /// @param[in]      l1_bucket               L1 bucket.
    ///
    /// @return TCAM load of bucket.
    size_t get_tcam_load_of_l1_bucket(const lpm_buckets_bucket* l1_bucket) const;

    // Withdraw function sub functions:

    /// @brief Clear all data needed for the current iteration.
    void clear_iteration_members();

    /// @ Update the HBM cache manager on allocated/released/changed buckets.
    void update_hbm_cache_manager();

    /// @brief Reset all modified/refreshed buckets.
    ///
    /// Refreshed buckets only reset their entries, while modified buckets also reset their hw_indexes and roots.
    void withdraw_reset_bucketing();

    /// @brief Regenerate tree topology.
    void withdraw_regenerate_tree_topology();

    /// @brief Revert insert group root action.
    ///
    /// @param[in]      node            The inserted group root.
    void revert_insert_group_root(lpm_node* node);

    /// @brief Revert remove group root action.
    ///
    /// @param[in]      node            The insertion point of the node.
    /// @param[in]      key             Key of the removed group root.
    /// @param[in]      payload         Payload of the removed group root.
    /// @param[in]      group_id        Group ID of the removed group.
    /// @param[in]      core_id         Core ID this group belongs to.
    void revert_remove_group_root(lpm_node* node, const lpm_key_t& key, lpm_payload_t payload, size_t group_id, size_t core_id);

    /// @brief Regenerate bucket information.
    ///
    /// Sets the original hw_index and roots to all changed_buckets.
    void withdraw_regenerate_buckets_properties();

    /// @brief Regenerate nodes to buckets information.
    void withdraw_repopulate_l2_buckets();

    /// @brief Regenerate L1 bucketing of L2 buckets.
    void withdraw_repopulate_l1_buckets();

    /// @brief Regenerate L1/L2 bucketing_data on all changed nodes.
    void withdraw_bucketing_data();

    /// @brief m_hw_index_allocators withdraw.
    void withdraw_hw_indexes();

    /// @brief Reset all nodes of the given bucket starting the given node.
    void reset_bucket_buckets(lpm_buckets_bucket* l1_bucket);

    // Find subtree helper functions:

    /// @brief Find a subtree with given weighted size recursive helper.
    ///
    /// Recursively find a subtree with the closest size to requested size, without crossing group's border.
    ///
    /// @param[in]      node                       Node of subtree to find subtree in.
    /// @param[in]      requested_weighted_size    Requested weighted subtree size.
    /// @param[in]      max_width                  Max allowed key width to break at (due to distributor hardware limitation).
    ///
    /// @return Struct holding the returned subtree root node, returned subtree size and total subtree size.
    find_subtree_ret_data find_subtree_with_given_weighted_size_rec(const lpm_node* node,
                                                                    const resource_descriptor& requested_weighted_size,
                                                                    size_t max_width) const;
    /// @brief Helper function to recursive find subtree.
    ///
    /// Calculate the returned struct out of left and right returned structs, requested size and current node.
    ///
    /// @param[in]      left_ret                Node's left child subtree returned struct.
    /// @param[in]      right_ret               Node's right child subtree returned struct.
    /// @param[in]      requested_size          Requested subtree size.
    /// @param[in]      node                    Root node of subtree to calculate returned struct for.
    /// @param[in]      max_width               Max allowed key width to break at (due to distributor hardware limitation).
    ///
    /// @return Returned struct for node's subtree.
    find_subtree_ret_data choose_subtree_closest_to_given_weighted_size(const find_subtree_ret_data& left_ret,
                                                                        const find_subtree_ret_data& right_ret,
                                                                        const resource_descriptor& requested_weighted_size,
                                                                        const lpm_node* node,
                                                                        size_t max_width) const;

    /// @brief Helper function to recursive find load of all cores.
    ///
    /// @param[in]      core                    The owner core of the given node.
    /// @param[in]      node                    Current node in the recursion.
    /// @param[in,out]  out_load_per_core       Current load per core.
    ///
    /// @return Vector of load per core.
    void calculate_prefixes_load_per_core_rec(size_t core, const lpm_node* node, vector_alloc<size_t>& out_load_per_core) const;

    /// @brief Calculate the weight of the node according to the requested resource.
    ///
    /// @param[in]      node                    Node to calculate its weight.
    /// @param[in]      resource                Requested resource type.
    ///
    /// @return return the weight of the node.
    size_t get_node_weight(const lpm_node* node, resource_type resource) const;

    /// @brief Find shortest key which separates a node from its parent.
    ///
    /// @param[in]      node                    Node.
    ///
    /// @return Shortest key which separates node from its parent.
    lpm_key_t get_shortest_key_to_separate_from_parent(const lpm_node* node) const;

    /// @brief Check if all sub-entries of L1 bucket has entries.
    ///
    /// @return False if bucket has empty L2 bucket as member.
    bool has_empty_bucket(const lpm_buckets_bucket* l1_bucket) const;

    /// @brief Returns the size of the subtree starting from the given node.
    ///
    /// @param[in] root The root of the subtree to get its size.
    ///
    /// @retval The size of the subtree.
    size_t get_subtree_size(const json_t* root) const;

    /// @brief Creates a JSON representation of a given bucket.
    ///
    /// @param[in] bucket The bucket to create its JSON representation.
    ///
    /// @retval JSON representation of the bucket.
    json_t* bucket_to_json(const lpm_bucket_scptr& bucket) const;

    /// @brief Creates a JSON representation of all non empty buckets of a given level.
    ///
    /// @param[in] level The level of the buckets to represent.
    ///
    /// @note The key of each bucket is it's sw_index (as a string).
    ///
    /// @retval JSON representation of all the buckets.
    json_t* buckets_to_json(lpm_level_e level) const;

    /// @brief Creates a JSON representation of the subtree that its root is a given node.
    ///
    /// @param[in] node The subtree's root.
    ///
    /// @retval JSON object representing the subtree.
    json_t* subtree_to_json(const lpm_node* node) const;

    /// @brief Helper function to get number of entries per length.
    ///
    /// @return Vector of entries number per length.
    std::vector<size_t> get_num_entries_per_length() const;

    /// @brief Helper function to get distribution of lpm prefixes.
    ///
    /// @return Vector of distribution of lpm prefixes.
    std::vector<size_t> get_unique_prefixes_per_length() const;

    // Members

    // Device
    ll_device_sptr m_ll_device;

    // Lpm tree parameters (HW driven)
    //////////////////////////

    size_t m_num_of_cores;  ///< Number of cores.
    size_t m_num_of_groups; ///< Number of distributer nodes.
    std::array<bucketing_tree_level_parameters, NUM_LEVELS> m_tree_parameters;

    size_t m_bucket_depth; ///< Maximum allowed difference between a bucket root width,
    ///  and its longest entry's width.

    // Data members
    ///////////////////////////
    vector_alloc<size_t> m_group_to_core;           ///< Mapping from each group to the owner core.
    lpm_hbm_cache_manager_vec m_hbm_cache_managers; ///< LPM HBM cache managers.

    // State members
    ///////////////////////////

    // Index management (HW and SW)
    std::array<sw_bucket_allocator, NUM_LEVELS> m_sw_bucket_allocator_handler; ///< SW buckets allocators.
    hw_bucket_allocator_array_vec m_hw_index_allocators;                       ///< HW resource allocators per core.

    // Iteration members (filled, used and emptied in an iteration)
    std::array<bucketing_tree_level_iteration_members, (size_t)lpm_level_e::NUM_LEVELS> m_iteration_members;

    key_to_bucketing_data_vec m_changed_keys_to_bucketing_data; ///< Vector of pairs of key and its origin bucketing_data.
    lpm_implementation_desc_vec m_l2_executed_actions;          ///< Actions successfully executed during the last iterations.
    set_alloc<lpm_node*> m_nodes_to_rebucket;                   ///< Set of all nodes that should be rebucketed.

    // Statistics members
    lpm_action_statistics m_stats;       ///< Statistics per last bulk update input.
    lpm_action_statistics m_total_stats; ///< Statistics since TCAM creation.

    size_t m_tcam_single_width_key_weight;
    size_t m_tcam_double_width_key_weight;
    size_t m_tcam_quad_width_key_weight;

    const lpm_payload_t m_trap_destination;                ///< Default trap.
    const bool m_is_hbm_enabled;                           ///< Specifies if HBM is enabled.
    binary_lpm_tree<lpm_bucketing_data> m_binary_lpm_tree; ///< Algorithms for handling lpm_tree.
    lpm_core_tcam_utils_wcptr m_core_tcam_utils;           ///< Tcam utils.
};

} // namespace silicon_one

#endif // __LEABA_BUCKETING_TREE_H__
