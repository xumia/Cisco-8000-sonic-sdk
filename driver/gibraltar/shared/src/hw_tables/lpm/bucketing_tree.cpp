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

#include "bucketing_tree.h"
#include "common/defines.h"
#include "common/gen_operators.h"
#include "common/gen_utils.h"
#include "common/la_profile.h"
#include "common/logger.h"
#include "common/transaction.h"
#include "lpm/lpm_hw_index_allocator_adapter.h"
#include "lpm/lpm_hw_index_allocator_adapter_hbm.h"
#include "lpm_bucket_occupancy_utils.h"
#include "lpm_string.h"

#include <algorithm>
#include <jansson.h>
#include <limits>
#include <string>

using namespace std;

namespace silicon_one
{

la_device_id_t
get_device_id(const bucketing_tree* bucketing_tree)
{
    return bucketing_tree->get_ll_device()->get_device_id();
}

bucketing_tree::bucketing_tree(const ll_device_sptr& ldevice,
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
                               const lpm_core_tcam_utils_scptr& core_tcam_utils)
    : m_ll_device(ldevice),
      m_num_of_cores(num_of_cores),
      m_num_of_groups(num_of_groups),
      m_bucket_depth(max_bucket_depth),
      m_group_to_core(m_num_of_groups, CORE_ID_NONE),
      m_tcam_single_width_key_weight(tcam_single_width_key_weight),
      m_tcam_double_width_key_weight(tcam_double_width_key_weight),
      m_tcam_quad_width_key_weight(tcam_quad_width_key_weight),
      m_trap_destination(trap_destination),
      m_is_hbm_enabled(l2_max_num_of_hbm_buckets > 0),
      m_binary_lpm_tree(std::string("LPM binary tree")),
      m_core_tcam_utils(core_tcam_utils)
{
    dassert_crit((!m_is_hbm_enabled) || (l2_buckets_per_sram_line == 1),
                 "bucketing_tree doesn't support double_buckets when HBM is enabled");

    constexpr size_t LPM_BUCKET_SW_TO_HW_RATIO_MAX = 20;

    const lpm_node* root = m_binary_lpm_tree.get_root();
    lpm_bucketing_data& root_data = const_cast<lpm_node*>(root)->data();
    root_data.payload = m_trap_destination;

    m_tree_parameters[LEVEL1]
        = {.num_of_sram_buckets = l1_max_num_of_buckets,
           .num_of_hbm_buckets = 0,
           .buckets_per_sram_line = l1_buckets_per_sram_line,
           .bucket_num_fixed_entries = l1_double_bucket_size - l1_max_bucket_size,
           .bucket_num_shared_entries = l1_max_bucket_size - (l1_double_bucket_size - l1_max_bucket_size),
           .num_of_sw_buckets = (l2_max_num_of_sram_buckets + l2_max_num_of_hbm_buckets) * LPM_BUCKET_SW_TO_HW_RATIO_MAX
                                * m_num_of_cores, /* it's intentionally l2_ params, we do bucketing together */
           .support_double_entries = l1_support_double_width_entries};

    m_tree_parameters[LEVEL2]
        = {.num_of_sram_buckets = l2_max_num_of_sram_buckets,
           .num_of_hbm_buckets = l2_max_num_of_hbm_buckets,
           .buckets_per_sram_line = l2_buckets_per_sram_line,
           .bucket_num_fixed_entries = l2_double_bucket_size - l2_max_bucket_size,
           .bucket_num_shared_entries = l2_max_bucket_size - (l2_double_bucket_size - l2_max_bucket_size),
           .num_of_sw_buckets
           = (l2_max_num_of_sram_buckets + l2_max_num_of_hbm_buckets) * LPM_BUCKET_SW_TO_HW_RATIO_MAX * m_num_of_cores,
           .support_double_entries = l2_support_double_width_entries};

    for (size_t level : {LEVEL1, LEVEL2}) {
        m_sw_bucket_allocator_handler[level]
            = {.bucket_vector = lpm_bucket_ptr_vec(m_tree_parameters[level].num_of_sw_buckets, nullptr),
               .free_indices
               = ranged_index_generator(0 /* lower bound */, m_tree_parameters[level].num_of_sw_buckets /* upper bound */)};
    }

    std::string base_allocator_name = std::string("HW_INDEX_ALLOCATOR CORE=");

    m_hw_index_allocators.resize(m_num_of_cores);
    m_hbm_cache_managers.reserve(m_num_of_cores);
    size_t num_l1_hw_index = m_tree_parameters[LEVEL1].num_of_sram_buckets;
    size_t num_l2_hw_index = m_tree_parameters[LEVEL2].num_of_sram_buckets + m_tree_parameters[LEVEL2].num_of_hbm_buckets;
    for (size_t core_id = 0; core_id < m_num_of_cores; core_id++) {
        for (lpm_level_e level : {lpm_level_e::L1, lpm_level_e::L2}) {
            size_t level_idx = static_cast<size_t>(level);
            std::string allocator_name = base_allocator_name + std::to_string(core_id) + " LEVEL=" + to_string(level);
            m_hw_index_allocators[core_id][level_idx].hw_index_allocator
                = create_hw_index_allocator_adapter(allocator_name,
                                                    m_ll_device,
                                                    level,
                                                    m_tree_parameters[level_idx].num_of_sram_buckets / 2,
                                                    m_tree_parameters[level_idx].buckets_per_sram_line,
                                                    m_tree_parameters[level_idx].num_of_hbm_buckets,
                                                    m_tree_parameters[level_idx].bucket_num_fixed_entries,
                                                    m_tree_parameters[level_idx].bucket_num_shared_entries);

            size_t num_index = (level == lpm_level_e::L1) ? num_l1_hw_index : num_l2_hw_index;
            m_hw_index_allocators[core_id][level_idx].hw_index_to_sw_index = lpm_bucket_index_vec(num_index, LPM_NULL_INDEX);
            m_hw_index_allocators[core_id][level_idx].bucket_release_time = time_point_vec(num_index);
        }

        std::string hbm_allocator_name("LPM HBM Cache Manager - Core " + std::to_string(core_id));
        m_hbm_cache_managers.emplace_back(ldevice, hbm_allocator_name, l2_max_num_of_sram_buckets, l2_max_num_of_hbm_buckets);
    }

    m_iteration_members[LEVEL1]
        = {.affected_buckets_bitmap = bit_vector(), /* bit_vector width changes dynamically */
           .bucket_sw_idx_to_changed_data = vector_alloc<size_t>(m_tree_parameters[LEVEL1].num_of_sw_buckets)};
    m_iteration_members[LEVEL1].affected_buckets_data.reserve(m_tree_parameters[LEVEL1].num_of_sw_buckets);

    m_iteration_members[LEVEL2]
        = {.affected_buckets_bitmap = bit_vector(), /* bit_vector width changes dynamically */
           .bucket_sw_idx_to_changed_data = vector_alloc<size_t>(m_tree_parameters[LEVEL2].num_of_sw_buckets)};
    m_iteration_members[LEVEL2].affected_buckets_data.reserve(m_tree_parameters[LEVEL1].num_of_sw_buckets);
}

bucketing_tree::~bucketing_tree()
{
}

bucketing_tree::bucketing_tree() : m_trap_destination(), m_is_hbm_enabled()
{
}

const ll_device_sptr&
bucketing_tree::get_ll_device() const
{
    return m_ll_device;
}

la_status
bucketing_tree::insert(const lpm_key_t& key, lpm_payload_t payload, lpm_implementation_desc_vec_levels_cores& out_actions_per_core)
{
    lpm_action_desc_internal action(lpm_implementation_action_e::INSERT, key, payload);
    lpm_implementation_desc_vec actions(1 /* size */, action);

    size_t dummy_failure_core;
    return update(actions, out_actions_per_core, dummy_failure_core);
}

la_status
bucketing_tree::remove(const lpm_key_t& key, lpm_implementation_desc_vec_levels_cores& out_actions_per_core)
{
    lpm_action_desc_internal action(lpm_implementation_action_e::REMOVE, key);
    lpm_implementation_desc_vec actions(1 /* size */, action);

    size_t dummy_failure_core;
    return update(actions, out_actions_per_core, dummy_failure_core);
}

la_status
bucketing_tree::modify(const lpm_key_t& key, lpm_payload_t payload, lpm_implementation_desc_vec_levels_cores& out_actions_per_core)
{
    lpm_action_desc_internal action(lpm_implementation_action_e::MODIFY, key, payload);
    lpm_implementation_desc_vec actions(1 /* size */, action);

    size_t dummy_failure_core;
    return update(actions, out_actions_per_core, dummy_failure_core);
}

la_status
bucketing_tree::update(const lpm_implementation_desc_vec& actions,
                       lpm_implementation_desc_vec_levels_cores& out_actions_per_core,
                       size_t& out_failed_core)
{
    // The way update works is as follows:
    // 1. Go over each action:
    //    a. Insert: fast_insert/unbucket_path-from-the-group_root-containing-the-key-to-the-key.
    //    b. Remove: fast_remove --> remove node from the tree.
    //    c. Modify: update the node.
    //
    //    At this point all unbucket nodes have unbucket path to their groups' roots.
    //
    // 2. Recursive run bucketing from all unbucketed groups roots to their unbucketed subtree.
    //
    //    At this point we already bucketed all the tree.
    //
    // 3. We allocate HW location to each bucket.
    //
    // 4. The only left thing to do is to calculate each bucket's default (if changed) and release SW resources.

    start_profiling("Tree update");
    la_status status = update_tree_topology(actions);
    return_on_error(status);

    transaction txn;
    txn.on_fail([=]() { withdraw(); });
    for (lpm_node* node : m_nodes_to_rebucket) {
        dassert_crit(is_node_group_root(node), "recursive rebucket works within a group and must start from group_root.");
        const lpm_bucketing_data& node_data = node->data();
        size_t core_id = m_group_to_core[node_data.group];
        dassert_crit(core_id != CORE_ID_NONE);
        txn.status = rebucket(core_id, node);
        return_on_error(txn.status);
    }

    txn.status = modified_buckets_to_actions(out_actions_per_core, out_failed_core);
    return_on_error(txn.status);

    calculate_default_entries();

    release_empty_buckets();

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::update_tree_topology(const lpm_implementation_desc_vec& actions)
{
    start_profiling("Performing tree actions and unbucketing");
    size_t action_index = 0;
    size_t actions_size = actions.size();
    transaction txn;
    txn.on_fail([=]() {
        log_debug(TABLES, "bucketing_tree::%s Ended with error status. Starting withdraw", __func__);
        withdraw();
    });

    while (txn.status == LA_STATUS_SUCCESS && action_index != actions_size) {
        const lpm_action_desc_internal& action_desc(actions[action_index++]);
        lpm_implementation_action_e action(action_desc.m_action);

        switch (action) {
        case lpm_implementation_action_e::INSERT:
            m_stats.insertions++;
            txn.status = insert_node(action_desc.m_key, action_desc.m_payload, action_desc.m_sram_only);
            break;

        case lpm_implementation_action_e::REMOVE:
            m_stats.removals++;
            txn.status = remove_node(action_desc.m_key);
            break;

        case lpm_implementation_action_e::MODIFY:
            m_stats.modifications++;
            txn.status = do_modify(action_desc.m_key, action_desc.m_payload, false /* is_modify_group */);
            break;

        case lpm_implementation_action_e::REMOVE_GROUP_ROOT:
            txn.status = remove_group_root(action_desc.m_key);
            break;

        case lpm_implementation_action_e::ADD_GROUP_ROOT:
            txn.status = add_group_root(action_desc.m_key, action_desc.m_group_id, action_desc.m_core_id);
            break;

        case lpm_implementation_action_e::MODIFY_GROUP_TO_CORE:
            modify_group_to_core(action_desc.m_key, action_desc.m_group_id, action_desc.m_core_id);
            break;
        case lpm_implementation_action_e::REFRESH:
            // Nothing needs to be done here.
            // The only actions is taken during HW update.
            m_stats.refreshes++;
            break;
        }
    }

    return_on_error(txn.status);

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::modified_buckets_to_actions(lpm_implementation_desc_vec_levels_cores& out_actions_per_core, size_t& out_failed_core)
{
    start_profiling("Assigning HW indexes");

    out_actions_per_core.resize(m_num_of_cores);

    la_status status = modified_buckets_to_actions(lpm_level_e::L2, out_actions_per_core, out_failed_core);
    return_on_error(status);

    status = modified_buckets_to_actions(lpm_level_e::L1, out_actions_per_core, out_failed_core);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::modified_buckets_to_actions(lpm_level_e level,
                                            lpm_implementation_desc_vec_levels_cores& out_actions_per_core,
                                            size_t& out_failed_core)
{
    // out_actions_per_core is used for 2 purposes:
    // 1. HW writing: for that we only need to know which buckets we need to write.
    // 2. TCAM update - this is the tricky one.
    //    During unbucket we can remove L1_bucket_root. It means that we need to erase its entry in the TCAM.
    //    But in the end, a new bucket might get the same root, so from the TCAM it looks like MODIFY (same root key - different
    //    location).
    //    We build the actions to the TCAM one-by-one. for each bucket (we get the buckets unordered) we check:
    //      if it was existed at the beginning of the iteration and we need to remove it
    //      if we need to write it (if it's not an empty bucket).
    //    We also using a map from the key to the TCAM action to change the description from INSERT/REMOVE to MODIFY if we have the
    //    INSERT + REMOVE on the same key.
    key_to_index_map_vec key_to_desc_index(m_num_of_cores);

    changed_bucket_data_vec& changed_data_vec = m_iteration_members[size_t(level)].affected_buckets_data;

    if (level == lpm_level_e::L2) {
        std::sort(changed_data_vec.begin(),
                  changed_data_vec.end(),
                  [&](changed_bucket_data& lchanged_data, changed_bucket_data& rchanged_data) {
                      lpm_changed_bucket_data& old_data_a = lchanged_data.bucket_data;
                      lpm_changed_bucket_data& old_data_b = rchanged_data.bucket_data;
                      size_t hotness_a = old_data_a.hotness_level;
                      size_t hotness_b = old_data_b.hotness_level;
                      return hotness_a > hotness_b;
                  });
    }

    for (changed_bucket_data& changed_data : changed_data_vec) {
        lpm_bucket_index_t index = changed_data.bucket_index;
        lpm_bucket* bucket = get_bucket_by_sw_index(level, index);
        if (changed_data.change_type == lpm_change_e::BUCKET_REFRESHED) {
            size_t core_id = bucket->get_core();
            size_t level_idx = static_cast<size_t>(level);
            out_actions_per_core[core_id][level_idx].push_back(lpm_action_desc_internal(
                lpm_implementation_action_e::REFRESH, bucket->get_root(), INVALID_PAYLOAD, bucket->get_hw_index()));
        } else /* modify */ {
            lpm_changed_bucket_data& old_data = changed_data.bucket_data;
            la_status status
                = modified_bucket_to_action(level, bucket, old_data, out_actions_per_core, key_to_desc_index, out_failed_core);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::modified_bucket_to_action(lpm_level_e level,
                                          lpm_bucket* bucket,
                                          const lpm_changed_bucket_data& old_data,
                                          lpm_implementation_desc_vec_levels_cores& out_actions_per_core,
                                          key_to_index_map_vec& key_to_desc_index,
                                          size_t& out_failed_core)
{
    // If BUCKET_CHANGED but old_key is different from new_key then we should remove and insert.
    lpm_bucket_index_t old_hw_index = old_data.hw_index;
    bool remove = (old_hw_index != LPM_NULL_INDEX);
    bool insert = (!bucket->empty());

    size_t level_idx = static_cast<size_t>(level);

    // If remove is needed on an inserted key, then the insertion should become modify.
    if (remove) {
        const lpm_key_t& old_key = old_data.root;
        size_t old_core_id = old_data.core_id;
        if (key_to_desc_index[old_core_id].count(old_key) == 0) {
            key_to_desc_index[old_core_id][old_key] = out_actions_per_core[old_core_id][level_idx].size();
            out_actions_per_core[old_core_id][level_idx].push_back(
                lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, old_key, INVALID_PAYLOAD, old_hw_index));
        } else {
            size_t action_desc_idx = key_to_desc_index[old_core_id][old_key];
            lpm_action_desc_internal& desc(out_actions_per_core[old_core_id][level_idx][action_desc_idx]);
            desc.m_action = lpm_implementation_action_e::MODIFY;
        }
    }

    // If insert is needed on a removed key, then the removal should become modify (with the appropriate payload).
    if (insert) {
        size_t new_core_id = bucket->get_core();
        lpm_bucket_index_t hw_index;
        la_status status;
        if (level == lpm_level_e::L2) {
            status = allocate_hw_index_for_l2_bucket(new_core_id, bucket, hw_index);
        } else {
            status = allocate_hw_index_for_l1_bucket(new_core_id, bucket, hw_index);
        }
        if (status != LA_STATUS_SUCCESS) {
            out_failed_core = new_core_id;
            return status;
        }

        lpm_payload_t payload = hw_index;
        const lpm_key_t& new_key = bucket->get_root();
        if (key_to_desc_index[new_core_id].count(new_key) == 0) {
            key_to_desc_index[new_core_id][new_key] = out_actions_per_core[new_core_id][level_idx].size();
            out_actions_per_core[new_core_id][level_idx].push_back(
                lpm_action_desc_internal(lpm_implementation_action_e::INSERT, new_key, payload, hw_index));
        } else {
            size_t action_desc_idx = key_to_desc_index[new_core_id][new_key];
            lpm_action_desc_internal& desc(out_actions_per_core[new_core_id][level_idx][action_desc_idx]);
            desc.m_action = lpm_implementation_action_e::MODIFY;
            desc.m_payload = payload;
            desc.m_index = hw_index;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::insert_node(const lpm_key_t& key, lpm_payload_t payload, bool sram_only)
{
    if (payload == INVALID_PAYLOAD) {
        return LA_STATUS_EINVAL;
    }

    log_debug(
        TABLES, "bucketing_tree::%s key=0x%s/%zu, payload=0x%x ", __func__, key.to_string().c_str(), key.get_width(), payload);

    // The new node will be create above or equal to the current_node.
    vector_alloc<lpm_node*> path_to_mark = m_binary_lpm_tree.get_path(key, is_node_group_root);
    lpm_node* current_node = path_to_mark.back();
    // path_to_mark.back() node is not compatible with insert_node_to_tree().
    const lpm_key_t& current_last_key = current_node->get_key();
    if (key != current_last_key) {
        current_node = m_binary_lpm_tree.find_node(key, current_node);
    }

    dassert_crit(current_node != nullptr);
    const lpm_key_t& current_key = current_node->get_key();

    lpm_bucketing_data bucketing_data;
    bool node_exists = (key == current_key);
    if (node_exists) {
        lpm_bucketing_data& current_node_data = current_node->data();
        if (current_node_data.is_user_prefix) {
            // Node with given key exists.
            return LA_STATUS_EEXIST;
        }

        if (is_node_group_root(current_node)) {
            // No need to handle bucketing or tree structure.
            dassert_crit(!current_node_data.is_user_prefix);
            mark_changed_default_payload(current_node, payload);

            m_l2_executed_actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
            current_node_data.payload = payload;
            current_node_data.is_user_prefix = true;
            return LA_STATUS_SUCCESS;
        }

        bucketing_data = current_node_data;
    }

    bool use_fast_insert = true;
    lpm_nodes_bucket* l2_bucket = nullptr;
    if (use_fast_insert) {
        l2_bucket = get_containing_l2_bucket(current_node, key);
        dassert_crit((l2_bucket == nullptr) || (is_contained(l2_bucket->get_root(), key)));
        use_fast_insert = can_use_fast_insert(l2_bucket, key, current_node);
    }

    lpm_node* group_root_node = path_to_mark.front();
    m_nodes_to_rebucket.insert(group_root_node);

    mark_unbalanced_nodes(path_to_mark);

    if (!use_fast_insert) {
        unbucket_nodes_rec(group_root_node);
        bucketing_data = lpm_bucketing_data();
    }

    bucketing_data.payload = payload;
    bucketing_data.is_user_prefix = true;
    bucketing_data.is_sram_only = sram_only;
    current_node = m_binary_lpm_tree.insert_node_to_tree(current_node, key, bucketing_data);

    dassert_crit(current_node != nullptr);
    m_l2_executed_actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    if (use_fast_insert) {
        // bucket_changed must be before the action itself as it's used in withdraw flow.
        fast_insert_node_to_bucket(l2_bucket, current_node);
        bucket_changed(l2_bucket, BUCKET_REFRESHED);
        lpm_bucketing_data& current_node_data = current_node->data();
        lpm_buckets_bucket* l1_bucket = current_node_data.l1_bucket.get();
        const lpm_key_t& current_key = current_node->get_key();
        if ((l1_bucket != nullptr) && (l1_bucket->get_root() == current_key)) {
            // This bucket_changed is only to update default payload for consistency.
            // The default will never get hit but we want it to be correct anyway.
            bucket_changed(l1_bucket, BUCKET_REFRESHED);
        }
    }

    lpm_node* left_child = current_node->get_left_child();
    lpm_node* right_child = current_node->get_right_child();
    mark_changed_default_payload(left_child, payload);
    mark_changed_default_payload(right_child, payload);

    return LA_STATUS_SUCCESS;
}

lpm_node*
bucketing_tree::insert_group_root_to_tree(lpm_node* insertion_point, const lpm_key_t& key, size_t core_id, size_t group_id)

{
    const lpm_key_t& insertion_point_key = insertion_point->get_key();
    log_debug(TABLES,
              "bucketing_tree::%s insertion_point=%s, key=%s, core_id=%lu, group_id=%zu",
              __func__,
              insertion_point_key.to_string().c_str(),
              key.to_string().c_str(),
              core_id,
              group_id);

    // The new node will be create above or equal to the insertion_point.
    dassert_crit(insertion_point != nullptr);
    dassert_crit(m_group_to_core[group_id] == CORE_ID_NONE);
    bool exists_and_valid = (insertion_point_key == key) && insertion_point->is_valid();
    lpm_node* group_root_node;
    if (exists_and_valid) {
        group_root_node = insertion_point;
    } else {
        lpm_bucketing_data bucketing_data;
        bucketing_data.is_user_prefix = false;
        group_root_node = m_binary_lpm_tree.insert_node_to_tree(insertion_point, key, bucketing_data);
        lpm_bucketing_data& node_data = group_root_node->data();
        node_data.payload = get_node_ancestor_payload(group_root_node);
        dassert_crit(group_root_node != nullptr);
    }

    lpm_bucketing_data& group_root_node_data = group_root_node->data();
    group_root_node_data.group = group_id;

    // If a new invalid node was created fix bucketing data.
    const lpm_key_t& group_root_node_key = group_root_node->get_key();
    bool new_invalid_node_was_created
        = ((!is_contained(insertion_point_key, group_root_node_key)) && (!is_contained(group_root_node_key, insertion_point_key)));
    if (new_invalid_node_was_created) {
        fix_bucketing_data_after_new_group_root(group_root_node, insertion_point);
    }

    lpm_action_desc_internal l2_executed_action(lpm_implementation_action_e::ADD_GROUP_ROOT, key);
    m_l2_executed_actions.push_back(l2_executed_action);

    return group_root_node;
}

void
bucketing_tree::revert_insert_group_root(lpm_node* group_root_node)
{
    dassert_crit(is_node_group_root(group_root_node));
    lpm_bucketing_data& group_root_node_data = group_root_node->data();
    size_t group_id = group_root_node_data.group;
    m_group_to_core[group_id] = CORE_ID_NONE;
    group_root_node_data.group = GROUP_ID_NONE;
    if (!group_root_node_data.is_user_prefix) {
        group_root_node_data.payload = INVALID_PAYLOAD;
        m_binary_lpm_tree.remove_node_from_tree(group_root_node);
    }
}

void
bucketing_tree::fix_bucketing_data_after_new_group_root(lpm_node* group_root_node, lpm_node* insertion_point)
{
    lpm_node* new_parent_node = group_root_node->get_parent_node();
    const lpm_key_t& new_parent_node_key = new_parent_node->get_key();
    lpm_bucketing_data& new_parent_node_data = new_parent_node->data();
    m_changed_keys_to_bucketing_data.push_back({new_parent_node_key, new_parent_node_data});
    const lpm_node* new_parents_parent_node = new_parent_node->get_parent_node();
    new_parent_node_data.is_balanced = new_parents_parent_node->data().is_balanced;
    new_parent_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG;

    bool is_insertion_point_group_root = is_node_group_root(insertion_point);
    bool is_bucketed = is_node_in_bucket_region(insertion_point);
    if (is_bucketed && (!is_insertion_point_group_root)) {
        dassert_crit(new_parent_node_data.l2_bucket == nullptr);
        dassert_crit(new_parent_node_data.l1_bucket == nullptr);

        const lpm_key_t& insertion_point_key = insertion_point->get_key();
        lpm_bucketing_data& insertion_point_data = insertion_point->data();
        m_changed_keys_to_bucketing_data.push_back({insertion_point_key, insertion_point_data});

        auto l1_bucket = insertion_point_data.l1_bucket;
        bool propagate_l1_bd = ((!l1_bucket) || (l1_bucket->get_root_width() <= new_parent_node->get_width()));
        if (propagate_l1_bd) {
            insertion_point_data.l1_bucket = nullptr;
            new_parent_node_data.l1_bucket = l1_bucket;
            new_parent_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET;
        }

        auto l2_bucket = insertion_point_data.l2_bucket;
        bool propagate_l2_bd
            = (insertion_point_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS)
              && ((!l2_bucket) || (l2_bucket->get_root_width() <= new_parent_node->get_width()));
        if (propagate_l2_bd) {
            insertion_point_data.l2_bucket = nullptr;
            new_parent_node_data.l2_bucket = l2_bucket;
            new_parent_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS;
        }
    }
}

void
bucketing_tree::unbucket_invalid_nodes_within_an_empty_group(lpm_node* group_root_node)
{
    vector_alloc<lpm_node*> wave;
    wave.push_back(group_root_node);

    while (!wave.empty()) {
        lpm_node* curr = wave.back();
        wave.pop_back();
        lpm_bucketing_data& curr_data = curr->data();
        dassert_crit(!curr_data.is_user_prefix);

        lpm_node* left = curr->get_left_child();
        lpm_node* right = curr->get_right_child();

        if (left && (!is_node_group_root(left))) {
            wave.push_back(left);
        }

        if (right && (!is_node_group_root(right))) {
            wave.push_back(right);
        }

        const lpm_key_t& curr_key = curr->get_key();
        m_changed_keys_to_bucketing_data.push_back({curr_key, curr_data});
        curr_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::UNBUCKETED;
    }
}

bool
bucketing_tree::can_use_fast_insert(const lpm_nodes_bucket* l2_bucket,
                                    const lpm_key_t& new_prefix_key,
                                    const lpm_node* insertion_point) const
{
    if (l2_bucket == nullptr) {
        return false;
    }

    lpm_bucket_index_t hw_index = l2_bucket->get_hw_index();
    if (hw_index == LPM_NULL_INDEX) {
        return false;
    }

    // The new node will be created above or equal to the insertion_point.
    // In case we cut L2/L1 bucketing data we just skip the fast_insert to avoid changing bucketing_data of other buckets.
    const lpm_node* current_node = insertion_point;
    const lpm_bucketing_data& current_node_data = current_node->data();
    lpm_nodes_bucket* current_l2_bucket = current_node_data.l2_bucket.get();
    while (current_l2_bucket != l2_bucket) {
        if ((current_l2_bucket != nullptr) || current_node_data.l1_bucket) {
            return false;
        }

        const lpm_node* current_parent = current_node->get_parent_node();
        current_node = current_parent;
        dassert_crit(current_node != nullptr);
        current_l2_bucket = current_node->data().l2_bucket.get();
    }

    key_depth_class depth_class = get_key_depth_class(l2_bucket, new_prefix_key);
    if (depth_class == key_depth_class::NOT_IN_RANGE) {
        return false;
    }

    size_t root_width = l2_bucket->get_root_width();
    bool support_double_entries = m_tree_parameters[LEVEL2].support_double_entries;
    lpm_bucket::occupancy_data occupancy
        = lpm_bucket_occupancy_utils::get_bucket_occupancy(l2_bucket, root_width + m_bucket_depth, support_double_entries);
    if (depth_class == key_depth_class::SINGLE_ENTRY) {
        occupancy.single_entries++;
    } else {
        occupancy.double_entries++;
    }

    lpm_bucket::occupancy_data hw_occupancy
        = lpm_bucket_occupancy_utils::logical_occupancy_to_hardware_occupancy(m_ll_device, lpm_level_e::L2, occupancy);

    size_t core_id = l2_bucket->get_core();
    lpm_bucket::occupancy_data neighbor_occupancy;
    const lpm_bucket* neighbor = get_neighbor_bucket(core_id, lpm_level_e::L2, hw_index);
    if (neighbor != nullptr) {
        size_t root_width = neighbor->get_root_width();
        bool support_double_entries = m_tree_parameters[LEVEL2].support_double_entries;
        neighbor_occupancy = lpm_bucket_occupancy_utils::get_bucket_hw_occupancy(
            m_ll_device, neighbor, root_width + m_bucket_depth, support_double_entries);
    }

    bool fast_insert = does_double_bucket_fit_space(lpm_level_e::L2,
                                                    hw_occupancy.single_entries,
                                                    hw_occupancy.double_entries,
                                                    neighbor_occupancy.single_entries,
                                                    neighbor_occupancy.double_entries);
    return fast_insert;
}

void
bucketing_tree::fast_insert_node_to_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* inserted_node)
{
    const lpm_key_t& inserted_node_key = inserted_node->get_key();
    dassert_crit(is_contained(l2_bucket->get_root(), inserted_node_key));
    l2_bucket->insert(inserted_node);
    fast_insert_fix_buckets_structure(l2_bucket, inserted_node);
}

void
bucketing_tree::fast_insert_fix_buckets_structure(lpm_nodes_bucket* l2_bucket, lpm_node* inserted_node)
{
    lpm_node* original_l2_top_node = l2_bucket->get_top_node();
    const lpm_key_t& original_l2_top_node_key = original_l2_top_node->get_key();
    const lpm_key_t& inserted_node_key = inserted_node->get_key();

    // Fix bucketing state for all nodes from the newly inserted one all the way up to the top node
    const lpm_key_t& new_top_node_key = common_key(original_l2_top_node_key, inserted_node_key);
    lpm_node* current_node = inserted_node;
    size_t new_top_node_key_width = new_top_node_key.get_width();
    while (current_node->get_width() > new_top_node_key_width) {
        lpm_bucketing_data& current_node_data = current_node->data();
        lpm_bucketing_data::node_bucketing_state& current_state = current_node_data.bucketing_state;
        if (current_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS) {
            break;
        } else {
            current_state = lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS;
        }

        dassert_crit(current_node_data.l2_bucket == nullptr);
        dassert_crit(current_node_data.l1_bucket == nullptr);
        current_node = current_node->get_parent_node();
    }

    bool top_node_should_be_changed = (new_top_node_key != original_l2_top_node_key);
    if (top_node_should_be_changed) {
        // First, change the bucket's top_node.
        // Then, move bucketing data to the new bucketing data node.
        // start from original top node and climb up to the new one.
        // If we meet the original bucketing data node in the way, we remember its
        // L1/L2 bucket (in order to migrate to the new bucketing data node)
        // and set its new L1/L2 buckets as null (it's no longer the bucketing data node)
        // If we don't meet the bucketing data node in our climb, this means bucketing data
        // node is still higher that the new top node, so it can remain the bucketing data node.

        lpm_node* new_top_node = current_node;
        l2_bucket->set_top_node(new_top_node->shared_from_this());
        lpm_bucketing_data& new_top_node_data = new_top_node->data();
        new_top_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS;

        lpm_nodes_bucket* current_l2_bucket = nullptr;
        lpm_buckets_bucket* current_l1_bucket = nullptr;
        lpm_node* current_node = original_l2_top_node;
        dassert_crit(is_contained(new_top_node_key, original_l2_top_node_key));
        while (current_node != new_top_node) {
            lpm_bucketing_data& current_node_data = current_node->data();
            if (current_node_data.l2_bucket != nullptr) {
                dassert_crit(current_node_data.l2_bucket.get() == l2_bucket);
                dassert_crit(current_l2_bucket == nullptr);
                current_l2_bucket = l2_bucket;
            }

            if (current_node_data.l1_bucket != nullptr) {
                dassert_crit(current_l1_bucket == nullptr);
                current_l1_bucket = current_node_data.l1_bucket.get();
            }

            current_node_data.l2_bucket = nullptr;
            current_node_data.l1_bucket = nullptr;

            current_node = current_node->get_parent_node();
        }

        if (current_l2_bucket != nullptr) {
            lpm_bucketing_data& current_node_data = current_node->data();
            dassert_crit(current_node_data.l2_bucket == nullptr);
            current_node_data.l2_bucket = typed_shared_from_this(current_l2_bucket);
        }

        if (current_l1_bucket != nullptr) {
            lpm_bucketing_data& current_node_data = current_node->data();
            dassert_crit(current_node_data.l1_bucket == nullptr);
            current_node_data.l1_bucket = typed_shared_from_this(current_l1_bucket);
        }
    }
}

la_status
bucketing_tree::remove_node(const lpm_key_t& key)
{
    log_debug(TABLES, "bucketing_tree::%s, key=0x%s/%zu ", __func__, key.to_string().c_str(), key.get_width());

    vector_alloc<lpm_node*> path_to_unbucket = m_binary_lpm_tree.get_path(key, is_node_group_root);
    lpm_node* current_node = path_to_unbucket.back();
    dassert_crit(current_node != nullptr);
    const lpm_key_t& current_node_key = current_node->get_key();
    lpm_payload_t covering_payload = get_node_ancestor_payload(current_node);

    bool node_exists = (current_node_key == key);
    // Check if node isn't valid.
    lpm_bucketing_data& current_node_data = current_node->data();
    if (!(node_exists && (current_node_data.is_user_prefix))) {
        return LA_STATUS_ENOTFOUND;
    }

    bool is_group_root = (current_node_data.group != GROUP_ID_NONE);
    if (is_group_root) {
        // No need for the bucketing part or the tree structure.
        m_l2_executed_actions.push_back(
            lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, current_node_key, current_node_data.payload));
        current_node_data.is_user_prefix = false;
        mark_changed_default_payload(current_node, covering_payload);
        return LA_STATUS_SUCCESS;
    }

    mark_unbalanced_nodes(path_to_unbucket);

    lpm_nodes_bucket* l2_bucket = static_cast<lpm_nodes_bucket*>(get_bucket(current_node, lpm_level_e::L2));
    bool node_belongs_to_a_l2_bucket = (l2_bucket != nullptr);
    // !node_belongs_to_a_l2_bucket can happen only in a bulk update where we might unbucket some of the nodes.
    if (node_belongs_to_a_l2_bucket) {
        const lpm_key_t& l2_root_key = l2_bucket->get_root();
        dassert_crit(is_contained(l2_root_key, current_node_key));
        fast_remove_node_from_bucket(l2_bucket, current_node);
    }

    lpm_node* left_child = current_node->get_left_child();
    lpm_node* right_child = current_node->get_right_child();
    mark_changed_default_payload(left_child, covering_payload);
    mark_changed_default_payload(right_child, covering_payload);

    m_l2_executed_actions.push_back(
        lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, current_node_key, current_node_data.payload));
    remove_node_from_tree(current_node);

    return LA_STATUS_SUCCESS;
}

void
bucketing_tree::remove_node_from_tree(lpm_node* node)
{
    copy_bucketing_data_before_removing(node);
    lpm_bucketing_data& node_data = node->data();
    node_data.is_user_prefix = false;
    node_data.payload = INVALID_PAYLOAD;
    node_data.group = GROUP_ID_NONE;
    m_binary_lpm_tree.remove_node_from_tree(node);
}

void
bucketing_tree::remove_group_root_from_tree(lpm_node* group_root_node)
{
    log_debug(TABLES, "bucketing_tree::%s node=%s", __func__, group_root_node->to_string().c_str());

    const lpm_key_t& group_root_node_key = group_root_node->get_key();
    lpm_bucketing_data& group_root_node_data = group_root_node->data();
    m_changed_keys_to_bucketing_data.push_back({group_root_node_key, group_root_node_data});

    group_root_node_data.group = GROUP_ID_NONE;
    if (!group_root_node_data.is_user_prefix) {
        group_root_node_data.payload = INVALID_PAYLOAD;
        m_binary_lpm_tree.remove_node_from_tree(group_root_node);
    }
}

void
bucketing_tree::fast_remove_node_from_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* node)
{
    dassert_crit(l2_bucket != nullptr);
    lpm_node* l2_top_node = l2_bucket->get_top_node();
    const lpm_key_t& l2_top_node_key = l2_top_node->get_key();
    const lpm_key_t& node_key = node->get_key();
    dassert_crit(is_contained(l2_top_node_key, node_key));

    l2_bucket->remove(node);

    // bucket_changed must be before the action itself as it's used in withdraw flow.
    if (l2_bucket->empty()) {
        bucket_changed(l2_bucket, BUCKET_CHANGED);
        fast_remove_release_bucket(l2_bucket, node);
    } else {
        bucket_changed(l2_bucket, BUCKET_REFRESHED);
        if (l2_top_node == node) {
            fast_remove_top_node_from_bucket(l2_bucket, node);
        } else {
            lpm_buckets_bucket* l1_bucket = get_l1_bucket(node);
            fast_remove_node_bottom_up(l1_bucket, l2_bucket, node);
        }
    }
}

void
bucketing_tree::fast_remove_top_node_from_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* current_node)
{
    lpm_node* left_child = current_node->get_left_child();
    lpm_node* right_child = current_node->get_right_child();
    bool left_node_belongs_to_same_bucket = does_node_belong_to_same_l2_bucket_as_its_parent(left_child);
    bool right_node_belongs_to_same_bucket = does_node_belong_to_same_l2_bucket_as_its_parent(right_child);
    if (left_node_belongs_to_same_bucket && right_node_belongs_to_same_bucket) {
        return;
    }

    dassert_crit(left_node_belongs_to_same_bucket || right_node_belongs_to_same_bucket);
    lpm_node* new_top_node_candidate = left_node_belongs_to_same_bucket ? left_child : right_child;
    // if node has 2 children it won't be deleted, but will only become invalid, hence no need to move bucketing data from it.
    compute_top_node(l2_bucket, new_top_node_candidate);

    lpm_node* new_bucketing_data_node = new_top_node_candidate;
    if ((left_child == nullptr) || (right_child == nullptr)) {
        const lpm_key_t& new_top_node_candidate_key = new_top_node_candidate->get_key();
        const lpm_bucketing_data& new_top_node_candidate_data = new_top_node_candidate->data();
        m_changed_keys_to_bucketing_data.push_back({new_top_node_candidate_key, new_top_node_candidate_data});
        lpm_bucketing_data& new_bucketing_data_node_data = new_bucketing_data_node->data();
        lpm_bucketing_data& current_node_data = current_node->data();
        new_bucketing_data_node_data.l2_bucket = current_node_data.l2_bucket;
        new_bucketing_data_node_data.l1_bucket = current_node_data.l1_bucket;

        dassert_crit(current_node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS);
        current_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG;
        current_node_data.l2_bucket = nullptr;
        current_node_data.l1_bucket = nullptr;
    }
}

void
bucketing_tree::fast_remove_release_bucket(lpm_nodes_bucket* l2_bucket, lpm_node* node)
{
    // We are going to release the L2 bucket of current_node, and maybe the L1 bucket (if it becomes empty). Steps:
    // 1. Mark L2 bucket as changed (already happened)
    // 2. Remove L2 bucket from L1
    // 3. Clear L2 bucket's top node.
    // 4. Mark L1 bucket as refreshed (normally) or changed (in case it became empty)
    // 5. Tighten the L1/L2 buckets from bellow.
    //     Mark bucketing state of all nodes in path from current_node to bucketing_data node as not belonging to an L2 bucket,
    //     and
    //     maybe not to an L1 bucket (if there is no L2 buckets below them).
    // 6. remove L2 bucket from bucketing data node which pointed to it.
    // 7. Mark bucketing state of all nodes in path from bucketing_data node of L2 bucket to bucketing_data node of L1 bucket as
    // not
    // belonging to an L1 bucket if there is no other L2 bucket below.
    // 8. (In case it became empty) Remove L1 bucket from its bucketing data node.

    dassert_crit(node != nullptr);
    dassert_crit(!does_node_belong_to_same_l2_bucket_as_its_parent(node->get_left_child()));
    dassert_crit(!does_node_belong_to_same_l2_bucket_as_its_parent(node->get_right_child()));

    lpm_buckets_bucket* l1_bucket = static_cast<lpm_buckets_bucket*>(get_bucket(node, lpm_level_e::L1));
    auto l2_bucket_sptr = typed_shared_from_this(l2_bucket);
    l1_bucket->remove(l2_bucket_sptr);

    // bucket_changed must be before the action itself as it's used in withdraw flow.
    bucketing_tree::lpm_change_e l1_change = l1_bucket->empty() ? BUCKET_CHANGED : BUCKET_REFRESHED;
    bucket_changed(l1_bucket, l1_change);

    clear_bucketing_data_after_release_l2_bucket(l1_bucket, l2_bucket, node);
}

void
bucketing_tree::clear_bucketing_data_after_release_l2_bucket(lpm_buckets_bucket* l1_bucket,
                                                             lpm_nodes_bucket* l2_bucket,
                                                             lpm_node* node)
{
    dassert_crit(l2_bucket->empty());
    lpm_node* current_node = node;
    while (current_node->data().l2_bucket == nullptr) {
        downgrade_bucketing_state(current_node, l1_bucket);
        current_node = current_node->get_parent_node();
    }

    lpm_bucketing_data& current_node_data = current_node->data();
    dassert_crit(current_node_data.l2_bucket.get() == l2_bucket);
    const lpm_key_t& current_node_key = current_node->get_key();
    m_changed_keys_to_bucketing_data.push_back({current_node_key, current_node_data});
    current_node_data.l2_bucket = nullptr;
    current_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET;

    while (current_node->data().bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET) {
        lpm_bucketing_data& current_node_data = current_node->data();
        dassert_crit((!current_node_data.l1_bucket) || (current_node_data.l1_bucket.get() == l1_bucket));
        downgrade_bucketing_state(current_node, l1_bucket);
        if (current_node_data.l1_bucket.get() == l1_bucket) {
            if (l1_bucket->empty()) {
                current_node_data.l1_bucket = nullptr;
            }

            break;
        }

        current_node = current_node->get_parent_node();
    }
}

void
bucketing_tree::downgrade_bucketing_state(lpm_node* node, lpm_buckets_bucket* l1_bucket)
{
    dassert_crit(node != nullptr);
    const lpm_key_t& node_key = node->get_key();
    lpm_bucketing_data& node_data = node->data();
    m_changed_keys_to_bucketing_data.push_back({node_key, node_data});
    bool l1_has_l2_below_key = does_l1_has_l2_below_key(l1_bucket, node_key);
    lpm_bucketing_data::node_bucketing_state new_bucketing_state
        = l1_has_l2_below_key ? lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET
                              : lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG;
    node_data.bucketing_state = new_bucketing_state;
}

void
bucketing_tree::fast_remove_node_bottom_up(lpm_buckets_bucket* l1_bucket, lpm_nodes_bucket* l2_bucket, lpm_node* node)
{
    // We are going to remove node from the middle of the bucket. Steps:
    // 1. As bottom of bucket must be valid() node, Clear the ancestors to keep this assumption.
    // 2. If we hit the top_node -> try to pull it down as it might not be the top_node anymore.

    lpm_node* l2_top_node = l2_bucket->get_top_node();
    const lpm_key_t& l2_top_node_key = l2_top_node->get_key();
    const lpm_key_t& node_key = node->get_key();
    dassert_crit(is_contained(l2_top_node_key, node_key));
    dassert_crit(l2_top_node_key != node_key);

    lpm_node* current_node = node;
    while (current_node != l2_top_node) {
        if (current_node->is_valid() && (current_node != node)) {
            // We reached to valid node. No need to remove invalid nodes anymore.
            return;
        }

        const lpm_node* left_child = current_node->get_left_child();
        bool left_node_belongs_to_same_bucket = does_node_belong_to_same_l2_bucket_as_its_parent(left_child);
        if (left_node_belongs_to_same_bucket) {
            return;
        }

        const lpm_node* right_child = current_node->get_right_child();
        bool right_node_belongs_to_same_bucket = does_node_belong_to_same_l2_bucket_as_its_parent(right_child);
        if (right_node_belongs_to_same_bucket) {
            return;
        }

        // Tighten L1/L2 buckets from bellow
        const lpm_key_t& current_node_key = current_node->get_key();
        bool l1_has_l2_below_key = does_l1_has_l2_below_key(l1_bucket, current_node_key);
        lpm_bucketing_data::node_bucketing_state new_bucketing_state
            = l1_has_l2_below_key ? lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET
                                  : lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG;

        lpm_bucketing_data& current_node_data = current_node->data();
        m_changed_keys_to_bucketing_data.push_back({current_node_key, current_node_data});
        current_node_data.bucketing_state = new_bucketing_state;
        current_node = current_node->get_parent_node();
    }

    // current_node is now the L2 top node. If it's HW destined, bucket structure doesn't need to change
    if (current_node->is_valid()) {
        return;
    }

    // At this stage current_node is an invalid node (and a non-group-root).
    // At least one of its children must be with it in the same bucket,
    // because we never start a bucket (from below) with an invalid node.
    const lpm_node* right_child = current_node->get_right_child();
    const lpm_node* left_child = current_node->get_left_child();
    dassert_crit(does_node_belong_to_same_l2_bucket_as_its_parent(left_child)
                 || does_node_belong_to_same_l2_bucket_as_its_parent(right_child));

    compute_top_node(l2_bucket, l2_top_node);
}

la_status
bucketing_tree::unbucket(const lpm_key_t& key)
{
    log_debug(TABLES, "bucketing_tree::%s, key=0x%s, len=%lu", __func__, key.to_string().c_str(), key.get_width());

    vector_alloc<lpm_node*> path_to_unbucket = m_binary_lpm_tree.get_path(key, is_node_group_root);
    unbucket_path(path_to_unbucket);

    return LA_STATUS_SUCCESS;
}

bool
bucketing_tree::does_l1_has_l2_below_key(lpm_buckets_bucket* l1_bucket, const lpm_key_t& key) const
{
    auto& l2_buckets = l1_bucket->get_members();
    for (const auto& l2_bucket : l2_buckets) {
        const lpm_key_t& bucket_key = l2_bucket->get_root();
        bool is_bucket_below_key = is_contained(key, bucket_key);
        if (is_bucket_below_key) {
            return true;
        }
    }

    return false;
}

la_status
bucketing_tree::do_modify(const lpm_key_t& key, lpm_payload_t payload, bool is_modify_group)
{
    log_debug(TABLES,
              "bucketing_tree::%s, key=0x%s/%zu, payload=0x%x is_modify_group=%s",
              __func__,
              key.to_string().c_str(),
              key.get_width(),
              payload,
              is_modify_group ? "Yes" : "No");

    lpm_node* current_node = m_binary_lpm_tree.find_node(key);
    dassert_crit(current_node != nullptr);

    const lpm_key_t& current_node_key = current_node->get_key();
    bool node_exists = (current_node_key == key) && (current_node->is_valid());
    if (!node_exists) {
        dassert_crit(!is_modify_group);
        return LA_STATUS_ENOTFOUND;
    }

    dassert_crit((is_node_group_root(current_node)) || (!is_modify_group));

    if (payload == INVALID_PAYLOAD && !is_modify_group) {
        return LA_STATUS_EINVAL;
    }

    const lpm_bucketing_data& current_node_data = current_node->data();
    if ((!current_node_data.is_user_prefix) && (!is_modify_group)) {
        return LA_STATUS_ENOTFOUND;
    }

    if (current_node_data.is_user_prefix && is_modify_group) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = modify_node(current_node, payload);
    return status;
}

la_status
bucketing_tree::modify_node(lpm_node* node, lpm_payload_t payload)
{
    lpm_bucketing_data& node_data = node->data();
    if (node_data.payload == payload) {
        return LA_STATUS_SUCCESS;
    }

    const lpm_key_t& node_key = node->get_key();
    m_l2_executed_actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::MODIFY, node_key, node_data.payload));

    node_data.payload = payload;

    lpm_bucket* bucket_to_refresh = get_bucket(node, lpm_level_e::L2);
    if (bucket_to_refresh) {
        bucket_changed(bucket_to_refresh, BUCKET_REFRESHED);
    }

    // Make sure to change our children's default if they default back to us
    lpm_node* right_child = node->get_right_child();
    lpm_node* left_child = node->get_left_child();
    mark_changed_default_payload(left_child, payload);
    mark_changed_default_payload(right_child, payload);

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::remove_group_root(const lpm_key_t& key)
{
    log_debug(TABLES, "bucketing_tree::%s key=0x%s/%zu", __func__, key.to_string().c_str(), key.get_width());

    lpm_node* group_root_node = m_binary_lpm_tree.find_node(key);
    dassert_crit(group_root_node != nullptr);
    dassert_crit(is_node_group_root(group_root_node));
    const lpm_key_t& group_root_node_key = group_root_node->get_key();
    dassert_crit(group_root_node_key == key);
    const lpm_bucketing_data& group_root_node_data = group_root_node->data();
    size_t group_id = group_root_node_data.group;

    // Withdraw stack
    lpm_action_desc_internal l2_executed_action(lpm_implementation_action_e::REMOVE_GROUP_ROOT, key, group_root_node_data.payload);
    l2_executed_action.m_group_id = group_id;
    l2_executed_action.m_core_id = m_group_to_core[group_id];
    m_l2_executed_actions.push_back(l2_executed_action);

    // Perform action
    const lpm_key_t& parent_key = key >> 1;
    vector_alloc<lpm_node*> path_to_unbucket = m_binary_lpm_tree.get_path(parent_key, is_node_group_root);
    mark_unbalanced_nodes(path_to_unbucket);
    unbucket_path(path_to_unbucket);
    unbucket_node(group_root_node);

    const lpm_node* group_root_parent = group_root_node->get_parent_node();
    size_t to_group = get_owner_group(group_root_parent);
    size_t to_core = m_group_to_core[to_group];
    move_bucketed_subtree(group_root_node, to_core);

    m_group_to_core[group_id] = CORE_ID_NONE;
    remove_group_root_from_tree(group_root_node);

    lpm_node* parent_group_root = path_to_unbucket[0];
    dassert_crit(is_node_group_root(parent_group_root));
    m_nodes_to_rebucket.insert(parent_group_root);

    return LA_STATUS_SUCCESS;
}

void
bucketing_tree::revert_remove_group_root(lpm_node* node,
                                         const lpm_key_t& key,
                                         lpm_payload_t payload,
                                         size_t group_id,
                                         size_t core_id)
{
    const lpm_key_t& node_key = node->get_key();
    if ((node_key != key) || (!node->is_valid())) {
        lpm_bucketing_data bucketing_data;
        bucketing_data.payload = payload;
        bucketing_data.is_user_prefix = false;
        bucketing_data.group = group_id;
        node = m_binary_lpm_tree.insert_node_to_tree(node, key, bucketing_data);
        dassert_crit(node != nullptr);
    } else {
        lpm_bucketing_data& node_data = node->data();
        node_data.group = group_id;
        node_data.payload = payload;
    }

    m_group_to_core[group_id] = core_id;
}

void
bucketing_tree::cut_l1_l2_buckets(lpm_node* cut_node)
{
    lpm_buckets_bucket* l1_bucket = get_l1_bucket(cut_node);
    if (l1_bucket == nullptr) {
        // We are not in bucket's region at all.
        return;
    }

    lpm_nodes_bucket* l2_bucket = get_l2_bucket(cut_node);

    lpm_l2_buckets_set l2_buckets;

    node_and_l2_bucket_vec wave;
    wave.push_back(std::make_pair(cut_node, l2_bucket));

    while (!wave.empty()) {
        node_and_l2_bucket curr = wave.back();
        wave.pop_back();

        lpm_node* curr_node = curr.first;
        lpm_nodes_bucket* curr_l2_bucket = curr.second;
        const lpm_key_t& curr_node_key = curr_node->get_key();
        lpm_bucketing_data& curr_node_data = curr_node->data();
        m_changed_keys_to_bucketing_data.push_back({curr_node_key, curr_node_data});
        curr_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::UNBUCKETED;

        if (curr_node->is_valid()) {
            curr_l2_bucket->remove(curr_node);
            l2_buckets.insert(curr_l2_bucket);
        }

        lpm_node* left_child = curr_node->get_left_child();
        lpm_node* right_child = curr_node->get_right_child();
        for (lpm_node* child : {left_child, right_child}) {
            const lpm_bucketing_data& child_data = child->data();
            if ((child == nullptr) || (child_data.l1_bucket != nullptr)) {
                continue;
            }

            lpm_nodes_bucket* bucketing_data_l2_bucket = child_data.l2_bucket.get();
            if (bucketing_data_l2_bucket == nullptr) {
                bucketing_data_l2_bucket = curr_l2_bucket;
            }
            wave.push_back(std::make_pair(child, bucketing_data_l2_bucket));
        }
    }

    mark_changed_buckets(l1_bucket, l2_buckets);
    fix_bucketing_data_after_cut_l1_l2_buckets(l1_bucket, l2_bucket, cut_node);
}

void
bucketing_tree::mark_changed_buckets(lpm_buckets_bucket* l1_bucket, const lpm_l2_buckets_set& l2_buckets)
{
    bool change_l1 = false;
    for (lpm_nodes_bucket* l2_changed_bucket : l2_buckets) {
        bucketing_tree::lpm_change_e change;
        if (l2_changed_bucket->empty()) {
            change_l1 = true;
            auto l2_changed_bucket_sptr = typed_shared_from_this(l2_changed_bucket);
            l1_bucket->remove(l2_changed_bucket_sptr);
            change = BUCKET_CHANGED;
        } else {
            change = BUCKET_REFRESHED;
        }

        bucket_changed(l2_changed_bucket, change);
    }

    if (change_l1) {
        bucketing_tree::lpm_change_e change = l1_bucket->empty() ? BUCKET_CHANGED : BUCKET_REFRESHED;
        bucket_changed(l1_bucket, change);
    }
}

void
bucketing_tree::fix_bucketing_data_after_cut_l1_l2_buckets(lpm_buckets_bucket* l1_bucket,
                                                           lpm_nodes_bucket* l2_bucket,
                                                           lpm_node* cut_node)
{
    if (l2_bucket != nullptr) {
        // This node was L2 bucketed.
        if (l2_bucket->empty()) {
            clear_bucketing_data_after_release_l2_bucket(l1_bucket, l2_bucket, cut_node);
        } else {
            fast_remove_node_bottom_up(l1_bucket, l2_bucket, cut_node);
        }
    } else if (l1_bucket != nullptr) {
        lpm_bucketing_data& cut_node_data = cut_node->data();
        cut_node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET;
        lpm_node* current_node = cut_node;
        lpm_bucketing_data::node_bucketing_state current_node_bucketing_state = current_node->data().bucketing_state;
        while (current_node_bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET) {
            lpm_bucketing_data& current_node_data = current_node->data();
            downgrade_bucketing_state(current_node, l1_bucket);
            if (current_node_data.l1_bucket != nullptr) {
                dassert_crit(current_node_data.l1_bucket.get() == l1_bucket);
                if (l1_bucket->empty()) {
                    current_node_data.l1_bucket = nullptr;
                }

                break;
            }

            current_node = current_node->get_parent_node();
            current_node_bucketing_state = current_node->data().bucketing_state;
        }
    }
}

void
bucketing_tree::move_bucketed_subtree(lpm_node* group_root_node, size_t to_core)
{
    vector_alloc<lpm_node*> wave;
    wave.push_back(group_root_node);

    while (!wave.empty()) {
        lpm_node* curr = wave.back();
        wave.pop_back();

        auto left = curr->get_left_child();
        auto right = curr->get_right_child();

        if (left && (!is_node_group_root(left))) {
            wave.push_back(left);
        }

        if (right && (!is_node_group_root(right))) {
            wave.push_back(right);
        }

        const lpm_bucketing_data& curr_data = curr->data();
        lpm_nodes_bucket* l2_bucket = curr_data.l2_bucket.get();
        if (l2_bucket != nullptr) {
            bucket_changed(l2_bucket, BUCKET_CHANGED);
            l2_bucket->set_core(to_core);
        }

        lpm_buckets_bucket* l1_bucket = curr_data.l1_bucket.get();
        if (l1_bucket != nullptr) {
            bucket_changed(l1_bucket, BUCKET_CHANGED);
            l1_bucket->set_core(to_core);
        }
    }
}

la_status
bucketing_tree::add_group_root(const lpm_key_t& group_root_key, size_t group_id, size_t core_id)
{
    log_debug(TABLES,
              "bucketing_tree::%s core_id=%lu, group_id=%lu, group_root_key=%s",
              __func__,
              core_id,
              group_id,
              group_root_key.to_string().c_str());

    // Unbucket the "from_group"
    lpm_node* insertion_point = m_binary_lpm_tree.find_node(group_root_key);
    dassert_crit(insertion_point != nullptr);
    const lpm_key_t& insertion_point_key = insertion_point->get_key();
    bool insertion_point_below_key = is_contained(group_root_key, insertion_point_key);
    bool is_insertion_point_group_root = is_node_group_root(insertion_point);
    dassert_crit((!is_insertion_point_group_root) || (insertion_point_key != group_root_key));

    bool new_group_root_in_the_middle_of_group = (insertion_point_below_key && (!is_insertion_point_group_root));
    if (new_group_root_in_the_middle_of_group) {
        cut_l1_l2_buckets(insertion_point);
        unbucket_node(insertion_point);
        move_bucketed_subtree(insertion_point, core_id);
    }

    // Insert the group root
    lpm_node* group_root_node = insert_group_root_to_tree(insertion_point, group_root_key, core_id, group_id);

    m_nodes_to_rebucket.insert(group_root_node);
    m_group_to_core[group_id] = core_id;

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::modify_group_to_core(const lpm_key_t& group_root_key, size_t group_id, size_t core_id)
{
    log_debug(TABLES,
              "bucketing_tree::%s core_id=%lu, group_id=%lu, group_root_key=%s",
              __func__,
              core_id,
              group_id,
              group_root_key.to_string().c_str());

    lpm_node* group_root_node = m_binary_lpm_tree.find_node(group_root_key);
    dassert_crit(group_root_node != nullptr);
    dassert_crit(is_node_group_root(group_root_node));
    const lpm_key_t& group_root_node_key = group_root_node->get_key();
    dassert_crit(group_root_node_key == group_root_key);
    const lpm_bucketing_data& group_root_node_data = group_root_node->data();
    dassert_crit(group_root_node_data.group == group_id);

    // Withdraw stack
    lpm_action_desc_internal l2_executed_action(lpm_implementation_action_e::MODIFY_GROUP_TO_CORE, group_root_key);
    l2_executed_action.m_group_id = group_id;
    l2_executed_action.m_core_id = m_group_to_core[group_id];
    m_l2_executed_actions.push_back(l2_executed_action);

    move_bucketed_subtree(group_root_node, core_id);

    m_group_to_core[group_id] = core_id;

    return LA_STATUS_SUCCESS;
}

lpm_payload_t
bucketing_tree::get_node_ancestor_payload(const lpm_node* current_node) const
{
    const lpm_node* ancestor = current_node->ancestor();
    if (ancestor == nullptr) {
        return m_binary_lpm_tree.get_root()->data().payload;
    }

    const lpm_bucketing_data& ancestor_data = ancestor->data();
    return ancestor_data.payload;
}

lpm_nodes_bucket*
bucketing_tree::split_l2_bucket_at_node(lpm_nodes_bucket* l2_bucket, lpm_node* start_node)
{
    size_t core_id = l2_bucket->get_core();
    lpm_bucket* l2_new_bucket = allocate_bucket(core_id, lpm_level_e::L2);
    dassert_crit(l2_new_bucket != nullptr);

    lpm_nodes_bucket* l2_new_nodes_bucket = static_cast<lpm_nodes_bucket*>(l2_new_bucket);

    move_bucket_nodes(l2_new_nodes_bucket, l2_bucket, start_node);

    return l2_new_nodes_bucket;
}

lpm_buckets_bucket*
bucketing_tree::split_l1_bucket_at_node(lpm_buckets_bucket* from_bucket, lpm_node* node)
{
    size_t core_id = from_bucket->get_core();
    lpm_bucket* l1_new_bucket = allocate_bucket(core_id, lpm_level_e::L1);
    dassert_crit(l1_new_bucket != nullptr);

    lpm_buckets_bucket* l1_new_buckets_bucket = static_cast<lpm_buckets_bucket*>(l1_new_bucket);

    const lpm_key_t& split_key = node->get_key();

    auto l2_buckets = from_bucket->get_members();
    for (auto l2_bucket : l2_buckets) {
        const lpm_key_t& bucket_key = l2_bucket->get_top_node()->get_key();
        bool is_sub_bucket = is_contained(split_key, bucket_key);
        if (is_sub_bucket) {
            from_bucket->remove(l2_bucket);
            l1_new_buckets_bucket->insert(l2_bucket);
        }
    }

    return l1_new_buckets_bucket;
}

void
bucketing_tree::copy_bucketing_data_before_removing(lpm_node* node)
{
    dassert_crit(node->is_valid());
    lpm_node* right = node->get_right_child();
    lpm_node* left = node->get_left_child();

    const lpm_bucketing_data& node_data = node->data();
    dassert_crit(node_data.group == GROUP_ID_NONE);
    if (((right != nullptr) && (left != nullptr)) || node == m_binary_lpm_tree.get_root()) {
        return;
    }

    lpm_node* child = right ? right : left;
    copy_node_attributes_to_child(node, child);
    const lpm_key_t& node_key = node->get_key();
    m_changed_keys_to_bucketing_data.push_back({node_key, node_data});
    lpm_node* parent = node->get_parent_node();
    if ((child != nullptr) || parent->is_valid() || parent == m_binary_lpm_tree.get_root()) {
        return;
    }

    lpm_node* parent_right = parent->get_right_child();
    lpm_node* parent_left = parent->get_left_child();
    bool node_is_right = (parent_right == node);
    lpm_node* parent_child = (!node_is_right) ? parent_right : parent_left;
    copy_node_attributes_to_child(parent, parent_child);
    const lpm_key_t& parent_key = parent->get_key();
    const lpm_bucketing_data& parent_data = parent->data();
    m_changed_keys_to_bucketing_data.push_back({parent_key, parent_data});
}

void
bucketing_tree::copy_node_attributes_to_child(lpm_node* parent, lpm_node* child)
{
    if (!child) {
        return;
    }

    const lpm_key_t& child_key = child->get_key();
    const lpm_bucketing_data& parent_data = parent->data();
    lpm_bucketing_data& child_data = child->data();
    m_changed_keys_to_bucketing_data.push_back({child_key, child_data});

    if (parent_data.l2_bucket != nullptr) {
        child_data.l2_bucket = parent_data.l2_bucket;
    }

    if (parent_data.l1_bucket != nullptr) {
        child_data.l1_bucket = parent_data.l1_bucket;
    }
}

void
bucketing_tree::unbucket_node(lpm_node* node)
{
    dassert_crit(node != nullptr);
    lpm_node* left_child = node->get_left_child();
    lpm_node* right_child = node->get_right_child();
    const lpm_bucketing_data& left_child_data = left_child->data();
    lpm_node* next_node = (left_child && (!left_child_data.is_balanced)) ? left_child : right_child;
    unbucket_node(node, next_node);
}

void
bucketing_tree::unbucket_node(lpm_node* node, lpm_node* next)
{
    lpm_bucketing_data& node_data = node->data();
    if (node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::UNBUCKETED) {
        return;
    }

    log_xdebug(TABLES, "%s: Unbucketing node=%s", __func__, node->to_string().c_str());

    // For withdraw
    const lpm_key_t& node_key = node->get_key();
    m_changed_keys_to_bucketing_data.push_back({node_key, node_data});
    lpm_node* left_child = node->get_left_child();
    lpm_node* right_child = node->get_right_child();
    if (left_child != nullptr) {
        const lpm_key_t& left_child_key = left_child->get_key();
        const lpm_bucketing_data& left_child_data = left_child->data();
        m_changed_keys_to_bucketing_data.push_back({left_child_key, left_child_data});
    }

    if (right_child != nullptr) {
        const lpm_key_t& right_child_key = right_child->get_key();
        const lpm_bucketing_data& right_child_data = right_child->data();
        m_changed_keys_to_bucketing_data.push_back({right_child_key, right_child_data});
    }

    // next node - node along the path
    // sibling node - node aside the path
    lpm_node* next_node = left_child;
    lpm_node* sibling_node = right_child;
    if (next == sibling_node) {
        swap(next_node, sibling_node);
    }

    unbucket_l2(node, next_node, sibling_node);
    unbucket_l1(node, next_node, sibling_node);

    node_data.bucketing_state = lpm_bucketing_data::node_bucketing_state::UNBUCKETED;
    dassert_crit(node_data.l2_bucket == nullptr);
    dassert_crit(node_data.l1_bucket == nullptr);
}

void
bucketing_tree::unbucket_l2(lpm_node* node, lpm_node* next_node, lpm_node* sibling_node)
{
    // Remove from L2 then remove from L1
    lpm_bucketing_data& node_data = node->data();
    lpm_nodes_bucket* l2_bucket = node_data.l2_bucket.get();
    lpm_buckets_bucket* l1_bucket = node_data.l1_bucket.get();
    if (!l2_bucket) {
        dassert_crit(node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS);
        return;
    }

    dassert_crit(l1_bucket != nullptr);

    log_xdebug(TABLES, "Removing node %s from L2 bucket (sw index = %d)", node->to_string().c_str(), l2_bucket->get_sw_index());

    lpm_nodes_bucket* next_l2_bucket = get_l2_bucket(next_node);
    lpm_nodes_bucket* sibling_l2_bucket = get_l2_bucket(sibling_node);

    bool next_belongs_to_my_bucket = (l2_bucket == next_l2_bucket);
    bool sibling_belongs_to_my_bucket = (l2_bucket == sibling_l2_bucket);
    bool l2_split = (next_belongs_to_my_bucket && sibling_belongs_to_my_bucket);
    lpm_bucketing_data& next_node_data = next_node->data();
    lpm_bucketing_data& sibling_node_data = sibling_node->data();
    if (l2_split) {
        dassert_crit(next_node_data.l1_bucket == nullptr);
        dassert_crit(sibling_node_data.l1_bucket == nullptr);
        bucket_changed(l2_bucket, BUCKET_CHANGED);

        sibling_l2_bucket = split_l2_bucket_at_node(l2_bucket, sibling_node);
        auto sibling_l2_bucket_sptr = typed_shared_from_this(sibling_l2_bucket);
        l1_bucket->insert(sibling_l2_bucket_sptr);

        compute_top_node(sibling_l2_bucket, sibling_node);
        compute_top_node(l2_bucket, next_node);

        next_node_data.l2_bucket = typed_shared_from_this(l2_bucket);
        sibling_node_data.l2_bucket = sibling_l2_bucket_sptr;

    } else {
        bucket_changed(l2_bucket, BUCKET_CHANGED);
        bucket_changed(l1_bucket, BUCKET_REFRESHED);

        if (next_belongs_to_my_bucket) {
            next_node_data.l2_bucket = typed_shared_from_this(l2_bucket);
            if (node == l2_bucket->get_top_node()) {
                compute_top_node(l2_bucket, next_node);
            }
        }

        if (sibling_belongs_to_my_bucket) {
            sibling_node_data.l2_bucket = typed_shared_from_this(l2_bucket);
            if (node == l2_bucket->get_top_node()) {
                compute_top_node(l2_bucket, sibling_node);
            }
        }
    }

    l2_bucket->set_root(lpm_key_t());
    node_data.l2_bucket = nullptr;

    if (node->is_valid()) {
        l2_bucket->remove(node);
        if (l2_bucket->empty()) {
            bucket_changed(l1_bucket, BUCKET_CHANGED);
            l2_bucket->set_top_node(nullptr);
            auto l2_bucket_sptr = typed_shared_from_this(l2_bucket);
            l1_bucket->remove(l2_bucket_sptr);
        }
    }
}

void
bucketing_tree::unbucket_l1(lpm_node* node, lpm_node* next_node, lpm_node* sibling_node)
{
    lpm_bucketing_data& node_data = node->data();
    lpm_buckets_bucket* l1_bucket = node_data.l1_bucket.get();
    if (!l1_bucket) {
        dassert_crit(node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG);
        return;
    }

    // L1 split
    lpm_buckets_bucket* next_l1_bucket = static_cast<lpm_buckets_bucket*>(get_l1_bucket(next_node));
    lpm_buckets_bucket* sibling_l1_bucket = static_cast<lpm_buckets_bucket*>(get_l1_bucket(sibling_node));

    bool next_belongs_to_my_bucket = (l1_bucket == next_l1_bucket);
    bool sibling_belongs_to_my_bucket = (l1_bucket == sibling_l1_bucket);
    bool l1_split = (next_belongs_to_my_bucket && sibling_belongs_to_my_bucket);
    lpm_bucketing_data& next_node_data = next_node->data();
    lpm_bucketing_data& sibling_node_data = sibling_node->data();
    if (l1_split) {
        bucket_changed(l1_bucket, BUCKET_CHANGED);
        sibling_l1_bucket = split_l1_bucket_at_node(l1_bucket, sibling_node);

        next_node_data.l1_bucket = typed_shared_from_this(l1_bucket);
        sibling_node_data.l1_bucket = typed_shared_from_this(sibling_l1_bucket);
    } else {
        bucket_changed(l1_bucket, BUCKET_CHANGED);

        if (next_belongs_to_my_bucket) {
            next_node_data.l1_bucket = typed_shared_from_this(l1_bucket);
        }

        if (sibling_belongs_to_my_bucket) {
            sibling_node_data.l1_bucket = typed_shared_from_this(l1_bucket);
        }
    }

    l1_bucket->set_root(lpm_key_t());
    node_data.l1_bucket = nullptr;
}

void
bucketing_tree::compute_top_node(lpm_nodes_bucket* bucket, lpm_node* node)
{
    while (node) {
        if (node->is_valid()) {
            break;
        }

        lpm_node* left_child = node->get_left_child();
        lpm_node* right_child = node->get_right_child();
        bool left_node_belongs_to_same_bucket = does_node_belong_to_same_l2_bucket_as_its_parent(left_child);
        bool right_node_belongs_to_same_bucket = does_node_belong_to_same_l2_bucket_as_its_parent(right_child);

        const lpm_bucketing_data& left_child_data = left_child->data();
        const lpm_bucketing_data& right_child_data = right_child->data();
        if (left_node_belongs_to_same_bucket && right_node_belongs_to_same_bucket) {
            dassert_crit(left_child_data.l2_bucket == nullptr);
            dassert_crit(right_child_data.l2_bucket == nullptr);
            break;
        }

        if (left_node_belongs_to_same_bucket) {
            dassert_crit(left_child_data.l2_bucket == nullptr);
            node = left_child;
        } else {
            dassert_crit(right_child_data.l2_bucket == nullptr);
            node = right_child;
        }
    }

    auto node_sptr = node->shared_from_this();

    bucket->set_top_node(node_sptr);
}

void
bucketing_tree::release_empty_buckets()
{
    for (lpm_level_e level : {lpm_level_e::L1, lpm_level_e::L2}) {
        for (changed_bucket_data& changed_bucket : m_iteration_members[size_t(level)].affected_buckets_data) {
            lpm_bucket_index_t index = changed_bucket.bucket_index;
            lpm_bucket* bucket = get_bucket_by_sw_index(level, index);
            dassert_crit(bucket != nullptr);

            if (!bucket->empty()) {
                continue;
            }

            log_xdebug(TABLES, "level=%s  bucket: SW=%d  was reset", to_string(level).c_str(), bucket->get_sw_index());
            reset_bucket(bucket);
        }
    }
}

// Algorithm: go over every unbucketed node (starting from bottom),
// choose which bucket to add it to and add it.
la_status
bucketing_tree::rebucket(size_t core_id, lpm_node* node)
{
    dassert_crit(node != nullptr);
    const lpm_bucketing_data& node_data = node->data();
    if (node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::UNBUCKETED) {
        return LA_STATUS_SUCCESS;
    }

    la_status status = LA_STATUS_SUCCESS;

    lpm_node* left_child = node->get_left_child();
    lpm_node* right_child = node->get_right_child();
    for (lpm_node* child : {left_child, right_child}) {
        if (child == nullptr) {
            continue;
        }

        if (is_node_group_root(child)) {
            continue;
        }

        status = rebucket(core_id, child);
        return_on_error(status);
    }

    return rebucket_node(core_id, node);
}

la_status
bucketing_tree::rebucket_node(size_t core_id, lpm_node* node)
{
    // Try actions in this order:
    //
    //      1. Merge L2 buckets, and merge L1 buckets.
    //      2. Add node to left/right L2 bucket, and merge L1 buckets.
    //      3. Add node to left/right L2 bucket and do nothing for L1 bucket.
    //      4. Create new L2 bucket, and merge L1 buckets.
    //      5. Create new L2 bucket, and add L2 bucket (not node) to left/right L1 bucket
    //      6. Create new L2 bucket, and create new L1 bucket.

    // For withdraw
    const lpm_key_t& node_key = node->get_key();
    lpm_node* left_child = node->get_left_child();
    lpm_node* right_child = node->get_right_child();
    lpm_bucketing_data& node_data = node->data();
    m_changed_keys_to_bucketing_data.push_back({node_key, node_data});

    for (lpm_node* child : {left_child, right_child}) {
        if (child != nullptr) {
            const lpm_bucketing_data& child_data = child->data();
            const lpm_key_t& child_key = child->get_key();
            m_changed_keys_to_bucketing_data.push_back({child_key, child_data});
        }
    }

    merge_decision_e l2_merge_info = choose_between_childrens_l2_buckets(node);
    lpm_nodes_bucket* current_l2_bucket;
    la_status status = rebucket_l2(core_id, node, l2_merge_info, current_l2_bucket);
    return_on_error(status);

    dassert_crit((node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS)
                 ^ (node_data.l2_bucket == nullptr));

    merge_decision_e l1_merge_info = choose_between_childrens_l1_buckets(node, l2_merge_info);
    bool add_new_l2_bucket = (l2_merge_info == merge_decision_e::NEW);
    status = rebucket_l1(core_id, node, l1_merge_info, add_new_l2_bucket);
    return_on_error(status);

    dassert_crit((node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG)
                 ^ (node_data.l1_bucket == nullptr));

    bool left_is_balanced = true;
    if (left_child != nullptr) {
        const lpm_bucketing_data& left_child_data = left_child->data();
        left_is_balanced = left_child_data.is_balanced;
    }

    bool right_is_balanced = true;
    if (right_child != nullptr) {
        const lpm_bucketing_data& right_child_data = right_child->data();
        right_is_balanced = right_child_data.is_balanced;
    }

    node_data.is_balanced = left_is_balanced && right_is_balanced;

    bool is_group_root = is_node_group_root(node);
    if (is_group_root) {
        do_pull_l2_root_up(node, node->get_width() - 1);
        do_pull_l1_root_up(node, node->get_width() - 1);
    }

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::rebucket_l1(size_t core_id, lpm_node* node, merge_decision_e merge_decision, bool add_new_l2_bucket)
{
    lpm_buckets_bucket* current_l1_bucket = nullptr;
    lpm_node* left = node->get_left_child();
    lpm_node* right = node->get_right_child();
    lpm_bucketing_data& left_data = left->data();
    lpm_bucketing_data& right_data = right->data();
    lpm_bucketing_data& node_data = node->data();
    lpm_buckets_bucket* l1_lbucket = left ? left_data.l1_bucket.get() : nullptr;
    lpm_buckets_bucket* l1_rbucket = right ? right_data.l1_bucket.get() : nullptr;

    switch (merge_decision) {
    case merge_decision_e::MERGE: {
        current_l1_bucket = merge_l1_buckets(l1_lbucket, l1_rbucket);
        left_data.l1_bucket = nullptr;
        right_data.l1_bucket = nullptr;
        break;
    }

    case merge_decision_e::PULL_LEFT: {
        current_l1_bucket = l1_lbucket;
        left_data.l1_bucket = nullptr;
        pull_l1_root_up(right, node->get_width());
        break;
    }

    case merge_decision_e::PULL_RIGHT: {
        current_l1_bucket = l1_rbucket;
        right_data.l1_bucket = nullptr;
        pull_l1_root_up(left, node->get_width());
        break;
    }

    case merge_decision_e::NEW: {
        current_l1_bucket = static_cast<lpm_buckets_bucket*>(allocate_bucket(core_id, lpm_level_e::L1));
        if (!current_l1_bucket) {
            return LA_STATUS_ERESOURCE;
        }

        pull_l1_root_up(left, node->get_width());
        pull_l1_root_up(right, node->get_width());
        break;
    }

    case merge_decision_e::NONE: {
        pull_l1_root_up(left, node->get_width());
        pull_l1_root_up(right, node->get_width());
    }
    }

    if (node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS) {
        node_data.bucketing_state = (merge_decision != merge_decision_e::NONE)
                                        ? lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET
                                        : lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG;
    }

    node_data.l1_bucket = typed_shared_from_this(current_l1_bucket);

    if (add_new_l2_bucket) {
        dassert_crit(current_l1_bucket && node_data.l2_bucket);
        bucket_changed(current_l1_bucket, BUCKET_CHANGED);
        current_l1_bucket->set_root(lpm_key_t());
        current_l1_bucket->insert(node_data.l2_bucket.lock());
    }

    // If the L2 bucket has grown above L1 root, we need to update L1's root.
    if (node->is_valid() && (node->get_width() < current_l1_bucket->get_root_width())) {
        bucket_changed(current_l1_bucket, BUCKET_CHANGED);
        current_l1_bucket->set_root(lpm_key_t());
    }

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::rebucket_l2(size_t core_id, lpm_node* node, merge_decision_e merge_decision, lpm_nodes_bucket*& out_l2_bucket)
{
    out_l2_bucket = nullptr;
    lpm_node* left = node->get_left_child();
    lpm_node* right = node->get_right_child();
    lpm_bucketing_data& left_data = left->data();
    lpm_bucketing_data& right_data = right->data();
    auto lbucket = left ? left_data.l2_bucket : nullptr;
    auto rbucket = right ? right_data.l2_bucket : nullptr;

    switch (merge_decision) {
    case merge_decision_e::MERGE: {
        const auto& from_l2_bucket = rbucket;
        const auto& from_l1_bucket = right_data.l1_bucket;
        dassert_crit(from_l1_bucket);
        out_l2_bucket = merge_l2_buckets(lbucket.get(), rbucket.get());
        from_l1_bucket->remove(from_l2_bucket);

        left_data.l2_bucket = nullptr;
        right_data.l2_bucket = nullptr;
        break;
    }

    case merge_decision_e::PULL_LEFT: {
        out_l2_bucket = lbucket.get();
        left_data.l2_bucket = nullptr;
        pull_l2_root_up(right, node->get_width());
        break;
    }

    case merge_decision_e::PULL_RIGHT: {
        out_l2_bucket = rbucket.get();
        right_data.l2_bucket = nullptr;
        pull_l2_root_up(left, node->get_width());
        break;
    }

    case merge_decision_e::NEW: {
        out_l2_bucket = static_cast<lpm_nodes_bucket*>(allocate_bucket(core_id, lpm_level_e::L2));
        if (!out_l2_bucket) {
            return LA_STATUS_ERESOURCE;
        }

        pull_l2_root_up(left, node->get_width());
        pull_l2_root_up(right, node->get_width());

        break;
    }
    case merge_decision_e::NONE: {
        pull_l2_root_up(left, node->get_width());
        pull_l2_root_up(right, node->get_width());
        break;
    }
    }

    lpm_bucketing_data& node_data = node->data();
    node_data.bucketing_state = (merge_decision != merge_decision_e::NONE)
                                    ? lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS
                                    : lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG;
    node_data.l2_bucket = typed_shared_from_this(out_l2_bucket);

    if (node->is_valid()) {
        add_node_to_bucket(node, out_l2_bucket);
    }

    if (node->is_valid() || (merge_decision == merge_decision_e::MERGE)) {
        out_l2_bucket->set_top_node(node->shared_from_this());
    }

    return LA_STATUS_SUCCESS;
}

void
bucketing_tree::pull_l2_root_up(lpm_node* start_node, size_t illegal_width)
{
    const lpm_bucketing_data& start_node_data = start_node->data();
    if ((start_node == nullptr) || (is_node_group_root(start_node))
        || (start_node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS)) {
        return;
    }

    do_pull_l2_root_up(start_node, illegal_width);
}

void
bucketing_tree::do_pull_l2_root_up(lpm_node* start_node, size_t illegal_width)
{
    dassert_crit(start_node != nullptr);
    const lpm_bucketing_data& start_node_data = start_node->data();
    lpm_nodes_bucket* l2_bucket = start_node_data.l2_bucket.get();
    dassert_crit(l2_bucket != nullptr);
    const lpm_key_t& l2_prev_root = l2_bucket->get_root();
    size_t prev_width = l2_prev_root.get_width();
    if ((illegal_width < prev_width) && (prev_width <= start_node->get_width())) {
        return;
    }

    lpm_buckets_bucket* l1_bucket = start_node_data.l1_bucket.get();
    dassert_crit(l1_bucket != nullptr);

    bucket_changed(l2_bucket, BUCKET_CHANGED);
    bucket_changed(l1_bucket, BUCKET_REFRESHED);

    int l1_bucket_highest_possible_root = (int)l1_bucket->get_max_width() - (int)m_bucket_depth;
    int stop_width = std::max((int)illegal_width + 1, l1_bucket_highest_possible_root);

    int max_depth = (m_tree_parameters[(size_t)lpm_level_e::L2].support_double_entries) ? m_bucket_depth * 2 : m_bucket_depth;
    int l2_bucket_max_root = (int)l2_bucket->get_max_width() - max_depth;
    stop_width = std::max(stop_width, l2_bucket_max_root);

    int current_root_width = l2_bucket->get_top_node()->get_width();
    while (stop_width < current_root_width) {
        bool support_double_entries = m_tree_parameters[LEVEL2].support_double_entries;
        lpm_bucket::occupancy_data occupancy = lpm_bucket_occupancy_utils::get_bucket_hw_occupancy(
            m_ll_device, l2_bucket, stop_width + m_bucket_depth, support_double_entries);
        bool fits = does_bucket_fit_space(lpm_level_e::L2, occupancy.single_entries, occupancy.double_entries);
        if (fits) {
            break;
        }

        stop_width++;
    }

    dassert_crit(stop_width <= current_root_width);
    const lpm_key_t& l2_top_node_key = l2_bucket->get_top_node()->get_key();
    lpm_key_t key = l2_top_node_key.bits_from_msb(0, stop_width);
    l2_bucket->set_root(key);
}

void
bucketing_tree::pull_l1_root_up(lpm_node* start_node, size_t illegal_width)
{
    const lpm_bucketing_data& start_node_data = start_node->data();
    if ((start_node == nullptr) || (is_node_group_root(start_node))
        || (start_node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG)) {
        return;
    }

    do_pull_l1_root_up(start_node, illegal_width);
}

void
bucketing_tree::do_pull_l1_root_up(lpm_node* start_node, size_t illegal_width)
{
    dassert_crit(start_node != nullptr);
    const lpm_bucketing_data& start_node_data = start_node->data();
    lpm_buckets_bucket* l1_bucket = start_node_data.l1_bucket.get();
    const lpm_key_t& l1_prev_root = l1_bucket->get_root();
    size_t prev_width = l1_prev_root.get_width();
    if ((illegal_width < prev_width) && (prev_width <= start_node->get_width())) {
        return;
    }

    bucket_changed(l1_bucket, BUCKET_CHANGED);

    int stop_width = illegal_width + 1;

    const auto& l2_buckets = l1_bucket->get_members();
    lpm_key_t l1_key = l2_buckets.front()->get_root();

    size_t max_depth = (m_tree_parameters[(size_t)lpm_level_e::L1].support_double_entries) ? m_bucket_depth * 2 : m_bucket_depth;
    int max_depth_limit = (int(l1_bucket->get_max_width()) - (int)max_depth);
    size_t desired_width = std::max(max_depth_limit, stop_width);
    l1_key = l1_key.bits_from_msb(0, desired_width);
    l1_bucket->set_root(l1_key);
}

void
bucketing_tree::calculate_default_entries()
{
    start_profiling("Defaults calculations");
    for (lpm_level_e level : {lpm_level_e::L1, lpm_level_e::L2}) {
        for (changed_bucket_data& changed_bucket : m_iteration_members[size_t(level)].affected_buckets_data) {
            lpm_bucket_index_t index = changed_bucket.bucket_index;

            lpm_bucket* bucket = get_bucket_by_sw_index(level, index);
            dassert_crit(bucket != nullptr);
            if (bucket->empty()) {
                // Bucket was removed.
                continue;
            }

            update_bucket_default_entry(bucket);
        }
    }
}

void
bucketing_tree::update_bucket_default_entry(lpm_bucket* bucket)
{
    lpm_level_e level = bucket->get_level();
    const lpm_key_t& bucket_root = bucket->get_root();
    lpm_key_payload default_entry = {.key = {}, .payload = m_trap_destination};
    if (level == lpm_level_e::L2 || is_pacific_revision(m_ll_device)) {
        default_entry.payload = get_l2_default_payload(bucket_root);
    } else if (level == lpm_level_e::L1 && (is_gibraltar_revision(m_ll_device) || is_akpg_revision(m_ll_device))) {
        const lpm_bucket* l2_bucket = get_l1_default_bucket(bucket_root);
        dassert_crit(l2_bucket != nullptr);
        lpm_bucket_index_t l2_hw_index = l2_bucket->get_hw_index();
        dassert_crit(l2_hw_index != LPM_NULL_INDEX);
        default_entry.key = l2_bucket->get_root();
        default_entry.payload = l2_hw_index;
    } else {
        dassert_crit(false, "Unsupported device!!!");
    }

    bucket->set_default_entry(default_entry);
}

lpm_payload_t
bucketing_tree::get_l2_default_payload(const lpm_key_t& key) const
{
    const lpm_node* current_node = m_binary_lpm_tree.get_root();
    lpm_payload_t last_payload = m_trap_destination;

    while (current_node && is_contained(current_node->get_key(), key)) {
        if (current_node->is_valid()) {
            const lpm_bucketing_data& current_node_data = current_node->data();
            last_payload = current_node_data.payload;
        }

        const lpm_key_t& current_node_key = current_node->get_key();
        size_t current_width = current_node_key.get_width();
        bool go_right = key.bit_from_msb(current_width);
        const lpm_node* right_child = current_node->get_right_child();
        const lpm_node* left_child = current_node->get_left_child();
        const lpm_node* next_node = go_right ? right_child : left_child;
        current_node = next_node;
    }

    return last_payload;
}

const lpm_bucket*
bucketing_tree::get_l1_default_bucket(const lpm_key_t& key) const
{
    const lpm_node* current_node = m_binary_lpm_tree.get_root();
    const lpm_bucket* last_l2_bucket = nullptr;

    while (current_node && is_contained(current_node->get_key(), key)) {
        const lpm_bucketing_data& current_node_data = current_node->data();
        const lpm_bucket* current_l2_bucket = current_node_data.l2_bucket.get();
        if (current_l2_bucket != nullptr) {
            dassert_crit(is_contained(current_l2_bucket->get_root(), key));
            last_l2_bucket = current_l2_bucket;
        }

        const lpm_key_t& current_node_key = current_node->get_key();
        size_t current_width = current_node_key.get_width();
        bool go_right = key.bit_from_msb(current_width);
        const lpm_node* right_child = current_node->get_right_child();
        const lpm_node* left_child = current_node->get_left_child();
        const lpm_node* next_node = go_right ? right_child : left_child;
        current_node = next_node;
    }

    // During the above traversal we might not reach the node that contains the bucketing data of the L1 bucket with root 'key',
    // Therefore we check here if this node's bucketing data points to L2 bucket with the same root which will be the default.
    const lpm_bucketing_data& current_node_data = current_node->data();
    if (current_node && current_node_data.l2_bucket && current_node_data.l2_bucket->get_root() == key) {
        dassert_crit(current_node_data.l1_bucket && current_node_data.l1_bucket->get_root() == key);
        last_l2_bucket = current_node_data.l2_bucket.get();
    }

    // L1 should always have default L2 bucket.
    dassert_crit(last_l2_bucket);

    return last_l2_bucket;
}

size_t
bucketing_tree::get_owner_group(const lpm_node* current_node) const
{
    while (current_node != nullptr) {
        if (is_node_group_root(current_node)) {
            const lpm_bucketing_data& current_node_data = current_node->data();
            return current_node_data.group;
        }

        current_node = current_node->get_parent_node();
    }

    return GROUP_ID_NONE;
}

lpm_nodes_bucket*
bucketing_tree::merge_l2_buckets(lpm_nodes_bucket* to_bucket, lpm_nodes_bucket* from_bucket)
{
    dassert_crit(to_bucket != nullptr);
    dassert_crit(from_bucket != nullptr);
    dassert_crit(to_bucket != from_bucket);

    bucket_changed(to_bucket, BUCKET_CHANGED);
    bucket_changed(from_bucket, BUCKET_CHANGED);

    to_bucket->merge_bucket_members(from_bucket);
    to_bucket->set_root(lpm_key_t());

    dassert_crit(from_bucket->empty());

    return to_bucket;
}

lpm_buckets_bucket*
bucketing_tree::merge_l1_buckets(lpm_buckets_bucket* to_bucket, lpm_buckets_bucket* from_bucket)
{
    start_profiling("l1_merge");
    dassert_crit(to_bucket != from_bucket);
    bucket_changed(to_bucket, BUCKET_CHANGED);
    bucket_changed(from_bucket, BUCKET_CHANGED);
    to_bucket->set_root(lpm_key_t());

    to_bucket->merge_bucket_members(from_bucket);

    dassert_crit(from_bucket->empty());
    dassert_slow(!has_empty_bucket(to_bucket));

    return to_bucket;
}

bool
bucketing_tree::has_empty_bucket(const lpm_buckets_bucket* l1_bucket) const
{
    const auto& l2_buckets = l1_bucket->get_members();
    for (const auto& l2_bucket : l2_buckets) {
        if (l2_bucket->empty()) {
            return true;
        }
    }

    return false;
}

size_t
bucketing_tree::count_downstream_buckets(const lpm_node* node) const
{
    std::vector<const lpm_node*> front;
    std::set<const lpm_bucket*> downstream_buckets;
    front.push_back(node);
    while (!front.empty()) {
        const lpm_node* curr = front.back();
        front.pop_back();
        const lpm_bucketing_data& curr_data = curr->data();
        if (curr_data.l2_bucket != nullptr) {
            downstream_buckets.insert(curr_data.l2_bucket.get());
        }

        auto left = curr->get_left_child();
        auto right = curr->get_right_child();

        if (left != nullptr) {
            front.push_back(left);
        }

        if (right != nullptr) {
            front.push_back(right);
        }
    }

    return downstream_buckets.size();
}

bucketing_tree::merge_decision_e
bucketing_tree::choose_between_childrens_l2_buckets(const lpm_node* node) const
{
    merge_decision_e res;
    const lpm_node* left_child = node->get_left_child();
    const lpm_node* right_child = node->get_right_child();

    lpm_bucket* lbucket = nullptr;
    if (left_child != nullptr) {
        const lpm_bucketing_data& left_child_data = left_child->data();
        bool left_bucket = (left_child_data.group == GROUP_ID_NONE);
        lbucket = left_bucket ? left_child_data.l2_bucket.get() : nullptr;
    }

    lpm_bucket* rbucket = nullptr;
    if (right_child != nullptr) {
        const lpm_bucketing_data& right_child_data = right_child->data();
        bool right_bucket = (right_child_data.group == GROUP_ID_NONE);
        rbucket = right_bucket ? right_child_data.l2_bucket.get() : nullptr;
    }

    bool is_valid_node = node->is_valid();

    bool can_be_added_left = can_add_node_to_l2_bucket(node, left_child);
    bool can_be_added_right = can_add_node_to_l2_bucket(node, right_child);

    // Check if this node is a leaf
    if ((lbucket == nullptr) && (rbucket == nullptr)) {
        res = is_valid_node ? merge_decision_e::NEW : merge_decision_e::NONE;
        return res;
    }

    // Check case of only 1 child bucket.
    if (lbucket == nullptr) {
        if (can_be_added_right) {
            res = merge_decision_e::PULL_RIGHT;
        } else {
            res = is_valid_node ? merge_decision_e::NEW : merge_decision_e::NONE;
        }

        return res;
    }

    if (rbucket == nullptr) {
        if (can_be_added_left) {
            res = merge_decision_e::PULL_LEFT;
        } else {
            res = is_valid_node ? merge_decision_e::NEW : merge_decision_e::NONE;
        }

        return res;
    }

    // Check merging buckets.
    if (can_be_added_left && can_be_added_right) {
        size_t entries_to_add = is_valid_node ? 1 : 0; // add one more entry if the node is valid
        bool can_merge = can_merge_l2_buckets(node, entries_to_add);
        if (can_merge) {
            res = merge_decision_e::MERGE;
            return res;
        }

        if (lbucket->size() > rbucket->size()) {
            res = merge_decision_e::PULL_RIGHT;
        } else {
            res = merge_decision_e::PULL_LEFT;
        }

        return res;
    }

    // Check pulling one of the buckets.
    if (can_be_added_left) {
        res = merge_decision_e::PULL_LEFT;
        return res;
    }

    if (can_be_added_right) {
        res = merge_decision_e::PULL_RIGHT;
        return res;
    }

    if (is_valid_node) {
        res = merge_decision_e::NEW;
        return res;
    }

    // Can't pull any of them
    res = merge_decision_e::NONE;
    return res;
}

bucketing_tree::merge_decision_e
bucketing_tree::choose_between_childrens_l1_buckets(const lpm_node* node, const merge_decision_e& l2_choice) const
{
    merge_decision_e res;
    size_t common_root_width = node->get_width();
    const lpm_node* left_child = node->get_left_child();
    const lpm_node* right_child = node->get_right_child();
    const lpm_bucketing_data& left_child_data = left_child->data();
    const lpm_bucketing_data& right_child_data = right_child->data();

    bool left_bucket = (left_child != nullptr) && (left_child_data.group == GROUP_ID_NONE);
    lpm_bucket* lbucket = left_bucket ? left_child_data.l1_bucket.get() : nullptr;
    bool right_bucket = (right_child != nullptr) && (right_child_data.group == GROUP_ID_NONE);
    lpm_bucket* rbucket = right_bucket ? right_child_data.l1_bucket.get() : nullptr;

    // Check if this node is a leaf
    if ((lbucket == nullptr) && (rbucket == nullptr)) {
        res = node->is_valid() ? merge_decision_e::NEW : merge_decision_e::NONE;
        return res;
    }

    switch (l2_choice) {
    case merge_decision_e::MERGE:
        res = merge_decision_e::MERGE;
        return res;

    case merge_decision_e::NONE:
    case merge_decision_e::PULL_LEFT:
    case merge_decision_e::PULL_RIGHT: {
        if ((lbucket != nullptr) && (rbucket != nullptr)) {
            bool can_merge = can_merge_l1_buckets(common_root_width, lbucket, rbucket, 0);
            if (can_merge) {
                res = merge_decision_e::MERGE;
                return res;
            }
        }

        res = l2_choice;
        return res;
    }

    case merge_decision_e::NEW: {
        if (lbucket && rbucket) {
            bool can_merge = can_merge_l1_buckets(common_root_width, lbucket, rbucket, 1);
            if (can_merge) {
                res = silicon_one::bucketing_tree::merge_decision_e::MERGE;
                return res;
            }
        }

        bool can_pull_left = false;
        if (lbucket != nullptr) {
            can_pull_left = can_add_l2_bucket_to_l1_bucket(lbucket, node);
        }

        bool can_pull_right = false;
        if (rbucket != nullptr) {
            can_pull_right = can_add_l2_bucket_to_l1_bucket(rbucket, node);
        }

        if (can_pull_left || can_pull_right) {
            if (!can_pull_left) {
                res = merge_decision_e::PULL_RIGHT;
                return res;
            }

            if (!can_pull_right) {
                res = merge_decision_e::PULL_LEFT;
                return res;
            }
            size_t left_size = lbucket->size();
            size_t right_size = rbucket->size();

            res = (left_size > right_size) ? merge_decision_e::PULL_RIGHT : merge_decision_e::PULL_LEFT;
            return res;
        }

        res = merge_decision_e::NEW;
        return res;
    }
    }

    res = merge_decision_e::NEW;
    return res;
}

bool
bucketing_tree::does_entry_fit_in_bucket_depth(const lpm_bucket* bucket, size_t width) const
{
    size_t bucket_max_width = bucket->get_max_width();
    size_t max_depth
        = (m_tree_parameters[(size_t)bucket->get_level()].support_double_entries) ? m_bucket_depth * 2 : m_bucket_depth;
    size_t diff = bucket_max_width - width;
    return (bucket_max_width == 0) || (diff <= max_depth);
}

bool
bucketing_tree::can_add_node_to_l2_bucket(const lpm_node* node, const lpm_node* child_node) const
{
    if (child_node == nullptr) {
        return false;
    }

    const lpm_bucketing_data& child_node_data = child_node->data();
    lpm_nodes_bucket* l2_bucket = child_node_data.l2_bucket.get();
    if (l2_bucket == nullptr) {
        return false;
    }

    lpm_buckets_bucket* l1_bucket = child_node_data.l1_bucket.get();
    dassert_crit(l1_bucket != nullptr);

    size_t width = node->get_width();
    bool is_l2_depth_ok = does_entry_fit_in_bucket_depth(l2_bucket, width);
    if (!is_l2_depth_ok) {
        return false;
    }

    // Check if it upper the L1 bucket
    bool is_l1_depth_ok = does_entry_fit_in_bucket_depth(l1_bucket, width);
    if (!is_l1_depth_ok) {
        return false;
    }

    size_t nodes_to_add = node->is_valid() ? 1 : 0;
    bool support_double_entries = m_tree_parameters[LEVEL2].support_double_entries;
    lpm_bucket::occupancy_data occupancy
        = lpm_bucket_occupancy_utils::get_bucket_occupancy(l2_bucket, width + m_bucket_depth, support_double_entries);
    // Newly added node will be essentially single entry as it's added as a top node
    bool fits = does_bucket_fit_space(lpm_level_e::L2, occupancy.single_entries + nodes_to_add, occupancy.double_entries);
    if (!fits) {
        return false;
    }

    return true;
}

bool
bucketing_tree::is_node_group_root(const lpm_node* node)
{
    dassert_crit(node != nullptr);
    const lpm_bucketing_data& node_data = node->data();
    return (node_data.group != GROUP_ID_NONE);
}

bool
bucketing_tree::is_node_in_bucket_region(const lpm_node* node) const
{
    dassert_crit(node != nullptr);
    const lpm_bucketing_data& node_data = node->data();
    bool is_bucketed = (static_cast<size_t>(node_data.bucketing_state)
                        < static_cast<size_t>(lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG));
    return is_bucketed;
}

bool
bucketing_tree::does_node_belong_to_same_l2_bucket_as_its_parent(const lpm_node* node) const
{
    if (!node) {
        return false;
    }

    const lpm_bucketing_data& node_data = node->data();
    return (node_data.l2_bucket == nullptr)
           && (node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS);
}

bool
bucketing_tree::can_merge_l2_buckets(const lpm_node* merge_node, size_t entries_to_add) const
{
    size_t root_width = merge_node->get_width();
    const lpm_node* merge_node_left_child = merge_node->get_left_child();
    const lpm_node* merge_node_right_child = merge_node->get_right_child();
    const lpm_bucketing_data& merge_node_left_child_data = merge_node_left_child->data();
    const lpm_bucketing_data& merge_node_right_child_data = merge_node_right_child->data();
    const lpm_nodes_bucket* bucket0 = merge_node_left_child_data.l2_bucket.get();
    const lpm_nodes_bucket* bucket1 = merge_node_right_child_data.l2_bucket.get();

    dassert_crit(bucket0 != nullptr);
    dassert_crit(bucket1 != nullptr);

    bool support_double_entries = m_tree_parameters[LEVEL2].support_double_entries;
    lpm_bucket::occupancy_data bucket0_stats
        = lpm_bucket_occupancy_utils::get_bucket_occupancy(bucket0, root_width + m_bucket_depth, support_double_entries);
    lpm_bucket::occupancy_data bucket1_stats
        = lpm_bucket_occupancy_utils::get_bucket_occupancy(bucket1, root_width + m_bucket_depth, support_double_entries);

    bool can_merge = does_bucket_fit_space(bucket0->get_level(),
                                           bucket0_stats.single_entries + bucket1_stats.single_entries + entries_to_add,
                                           bucket0_stats.double_entries + bucket1_stats.double_entries);

    if (!can_merge) {
        return false;
    }

    // Checking length
    bool is_l2_depth_ok = does_entry_fit_in_bucket_depth(bucket0, root_width);
    if (!is_l2_depth_ok) {
        return false;
    }

    is_l2_depth_ok = does_entry_fit_in_bucket_depth(bucket1, root_width);
    if (!is_l2_depth_ok) {
        return false;
    }

    // Checking affect on L1
    lpm_buckets_bucket* l1_bucket0 = merge_node_left_child_data.l1_bucket.get();
    lpm_buckets_bucket* l1_bucket1 = merge_node_right_child_data.l1_bucket.get();

    dassert_crit(l1_bucket0 != nullptr);
    dassert_crit(l1_bucket1 != nullptr);
    dassert_crit(l1_bucket0 != l1_bucket1);

    can_merge = can_merge_l1_buckets(root_width, l1_bucket0, l1_bucket1, -1);

    return can_merge;
}

bool
bucketing_tree::can_add_l2_bucket_to_l1_bucket(const lpm_bucket* l1_bucket, const lpm_node* l2_root_node) const
{
    size_t bucket_size = l1_bucket->size();
    if (bucket_size == m_tree_parameters[LEVEL1].bucket_num_fixed_entries + m_tree_parameters[LEVEL1].bucket_num_shared_entries) {
        return false;
    }

    size_t l2_root_width = l2_root_node->get_width();
    bool is_l1_depth_ok = does_entry_fit_in_bucket_depth(l1_bucket, l2_root_width);

    return is_l1_depth_ok;
}

bool
bucketing_tree::can_merge_l1_buckets(size_t root_width, const lpm_bucket* bucket0, const lpm_bucket* bucket1, int l2_change) const
{
    // depth
    bool is_l1_depth_ok = does_entry_fit_in_bucket_depth(bucket0, root_width);
    if (!is_l1_depth_ok) {
        return false;
    }

    is_l1_depth_ok = does_entry_fit_in_bucket_depth(bucket1, root_width);
    if (!is_l1_depth_ok) {
        return false;
    }

    // entries
    size_t size0 = bucket0->size();
    size_t size1 = bucket1->size();

    size_t max_allowed_size = m_tree_parameters[(size_t)lpm_level_e::L1].bucket_num_fixed_entries
                              + m_tree_parameters[(size_t)lpm_level_e::L1].bucket_num_shared_entries;
    if (max_allowed_size < size0 + size1 + l2_change) {
        return false;
    }

    return true;
}

bool
bucketing_tree::does_bucket_fit_space(lpm_level_e level, size_t num_singles, size_t num_doubles) const
{

    bool fits = does_double_bucket_fit_space(level, num_singles, num_doubles, 0 /* num_singles1 */, 0 /* num_doubles1 */);
    return fits;
}

bucketing_tree::key_depth_class
bucketing_tree::get_key_depth_class(const lpm_bucket* bucket, const lpm_key_t& key) const
{
    const lpm_key_t& bucket_root = bucket->get_root();
    size_t bucket_root_width = bucket_root.get_width();
    size_t key_width = key.get_width();
    if (!is_contained(bucket->get_root(), key)) {
        return key_depth_class::NOT_IN_RANGE;
    }

    if (bucket_root_width + m_bucket_depth >= key_width) {
        return key_depth_class::SINGLE_ENTRY;
    }

    size_t max_depth
        = (m_tree_parameters[(size_t)bucket->get_level()].support_double_entries) ? m_bucket_depth * 2 : m_bucket_depth;
    if (bucket_root_width + max_depth >= key_width) {
        dassert_crit(is_contained(bucket->get_root(), key));
        return key_depth_class::DOUBLE_ENTRY;
    }

    return key_depth_class::NOT_IN_RANGE;
}

bool
bucketing_tree::does_double_bucket_fit_space(lpm_level_e level,
                                             size_t num_singles0,
                                             size_t num_doubles0,
                                             size_t num_singles1,
                                             size_t num_doubles1) const
{
    bool fit = false;

    if (level == lpm_level_e::L2
        && (is_gibraltar_revision(m_ll_device) || is_asic4_revision(m_ll_device) || is_asic3_revision(m_ll_device)
            || is_asic5_revision(m_ll_device))) {
        size_t num_groups0 = num_doubles0 + div_round_up(num_singles0, 2);
        size_t num_groups1 = num_doubles1 + div_round_up(num_singles1, 2);
        size_t max_bucket_group_size = m_tree_parameters[(size_t)level].bucket_num_shared_entries / 2
                                       + m_tree_parameters[(size_t)level].bucket_num_fixed_entries / 2;
        size_t max_groups_in_double_bucket
            = m_tree_parameters[(size_t)level]
                  .bucket_num_fixed_entries /* it should be /2 for groups and *2 for number of buckets */
              + m_tree_parameters[(size_t)level].bucket_num_shared_entries / 2;
        fit = num_groups0 + num_groups1 <= max_groups_in_double_bucket && num_groups0 <= max_bucket_group_size
              && num_groups1 <= max_bucket_group_size;
    } else {
        bool has_doubles = (num_doubles0 > 0) || (num_doubles1 > 0);
        size_t max_single_entries_per_bucket;
        size_t max_single_entries_both_buckets;
        size_t max_double_entries_both_buckets;

        if (has_doubles) {
            max_single_entries_per_bucket = m_tree_parameters[(size_t)level].bucket_num_fixed_entries;
            max_single_entries_both_buckets = m_tree_parameters[(size_t)level].bucket_num_fixed_entries * 2;
            max_double_entries_both_buckets = m_tree_parameters[(size_t)level].bucket_num_shared_entries / 2;
        } else {
            max_single_entries_per_bucket = m_tree_parameters[(size_t)level].bucket_num_fixed_entries
                                            + m_tree_parameters[(size_t)level].bucket_num_shared_entries;
            max_single_entries_both_buckets = m_tree_parameters[(size_t)level].bucket_num_fixed_entries * 2
                                              + m_tree_parameters[(size_t)level].bucket_num_shared_entries;
            max_double_entries_both_buckets = 0;
        }

        bool single_entries_bucket0_fits = (num_singles0 <= max_single_entries_per_bucket);
        bool single_entries_bucket1_fits = (num_singles1 <= max_single_entries_per_bucket);
        bool single_entries_both_fit = (num_singles0 + num_singles1 <= max_single_entries_both_buckets);
        bool double_entries_both_fit = (num_doubles0 + num_doubles1 <= max_double_entries_both_buckets);
        fit = (single_entries_bucket0_fits && single_entries_bucket1_fits && single_entries_both_fit && double_entries_both_fit);
    }

    return fit;
}

void
bucketing_tree::mark_changed_default_payload(lpm_node* node, lpm_payload_t payload)
{
    if (!node) {
        return;
    }

    lpm_bucketing_data& node_data = node->data();
    if (!node_data.is_user_prefix) {
        if (is_node_group_root(node)) {
            const lpm_key_t& node_key = node->get_key();
            m_l2_executed_actions.push_back(
                lpm_action_desc_internal(lpm_implementation_action_e::MODIFY, node_key, node_data.payload));
            node_data.payload = payload;
        }

        lpm_node* left_child = node->get_left_child();
        lpm_node* right_child = node->get_right_child();
        mark_changed_default_payload(left_child, payload);
        mark_changed_default_payload(right_child, payload);
    }

    if (is_pacific_revision(m_ll_device) && node_data.l1_bucket) {
        bucket_changed(node_data.l1_bucket.get(), BUCKET_REFRESHED);
    }

    if (node_data.l2_bucket) {
        bucket_changed(node_data.l2_bucket.get(), BUCKET_REFRESHED);
    }
}

lpm_bucket_raw_ptr_vec
bucketing_tree::get_l1_buckets_default_changed(const lpm_bucket* l2_bucket)
{
    // When we move an L2 bucket to another location, we want to update the defaults of all L1 buckets which have this L2 bucket as
    // their default.
    // These L1 buckets are:
    // 1. An L1 bucket which has the same key length as the L2 bucket. In this case both L1 and L2 are on same node.
    // 2. An L1 bucket which has a key length longer than the L2 bucket, As long as it doesn't have another L2 bucket between it and
    // the L1 bucket. They can be on the same node or on different nodes.
    //
    // start_node can hit only case(1), that's why it's out of the loop.
    // From there, we traverse the tree and collect L1 buckets that satisfy condition[2], but not condition[1] (if it satisfy
    // condition[1] it has other L2 default).

    lpm_bucket_raw_ptr_vec ret_buckets_vector;
    vector_alloc<const lpm_node*> wave;

    const lpm_key_t& bucket_root = l2_bucket->get_root();
    dassert_crit(bucket_root != lpm_key_t());
    lpm_node* start_node = m_binary_lpm_tree.find_node(bucket_root);
    dassert_crit(start_node != nullptr);

    const lpm_bucketing_data& start_node_data = start_node->data();
    lpm_bucket* l1_bucket = start_node_data.l1_bucket.get();
    if ((l1_bucket != nullptr) && (l1_bucket->get_root() == bucket_root)) {
        ret_buckets_vector.push_back(l1_bucket);
    }

    wave.push_back(start_node->get_left_child());
    wave.push_back(start_node->get_right_child());

    while (!wave.empty()) {
        const lpm_node* curr_node = wave.back();
        wave.pop_back();
        if (curr_node == nullptr) {
            continue;
        }

        const lpm_bucketing_data& curr_node_data = curr_node->data();
        lpm_bucket* l1_bucket = curr_node_data.l1_bucket.get();
        if (l1_bucket != nullptr) {
            lpm_bucket* current_l2_bucket = curr_node_data.l2_bucket.get();
            bool reached_l2_bucket = ((current_l2_bucket != nullptr) && (l1_bucket->get_root() == current_l2_bucket->get_root()));
            if (!reached_l2_bucket) {
                ret_buckets_vector.push_back(l1_bucket);
            }
        }

        if (curr_node_data.l2_bucket != nullptr && curr_node_data.l2_bucket.get() != l2_bucket) {
            continue;
        }

        for (const lpm_node* child : {curr_node->get_left_child(), curr_node->get_right_child()}) {
            wave.push_back(child);
        }
    }

    return ret_buckets_vector;
}

bucketing_tree::lpm_changed_bucket_data
bucketing_tree::init_changed_bucket_struct(const lpm_bucket* bucket)
{
    lpm_key_t root = bucket->get_root();
    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    size_t core_id = bucket->get_core();
    size_t hotness_level = 0;
    if ((hw_index != LPM_NULL_INDEX) && (bucket->get_level() == lpm_level_e::L2)) {
        hotness_level = m_hbm_cache_managers[core_id].get_hotness_of_bucket(hw_index);
    }

    return {root, hw_index, core_id, hotness_level};
}

void
bucketing_tree::bucket_changed(lpm_bucket* bucket, lpm_change_e change)
{
    if (bucket == nullptr) {
        return;
    }

    lpm_bucket_index_t sw_index = bucket->get_sw_index();
    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    lpm_level_e level = bucket->get_level();

    log_xdebug(TABLES,
               "%s (%s bucket SW=%d core=%lu HW=%d change=%s",
               __func__,
               to_string(level).c_str(),
               sw_index,
               bucket->get_core(),
               hw_index,
               (change == BUCKET_REFRESHED) ? "REFRESH" : "CHANGE");

    bucketing_tree_level_iteration_members& iteration_members = m_iteration_members[size_t(level)];
    size_t current_index = iteration_members.affected_buckets_data.size();
    if (!iteration_members.affected_buckets_bitmap.bit(sw_index)) {
        iteration_members.bucket_sw_idx_to_changed_data[sw_index] = current_index;
        changed_bucket_data change_data;
        change_data.change_type = change;
        change_data.bucket_index = sw_index;
        change_data.bucket_data = init_changed_bucket_struct(bucket);
        iteration_members.affected_buckets_data.push_back(change_data);
        iteration_members.affected_buckets_bitmap.set_bit(sw_index, true);
    }

    if (change == lpm_change_e::BUCKET_CHANGED) {
        size_t changed_data_location = iteration_members.bucket_sw_idx_to_changed_data[sw_index];
        iteration_members.affected_buckets_data[changed_data_location].change_type = change;
        if (bucket->get_hw_index() != LPM_NULL_INDEX) {
            size_t core_id = bucket->get_core();
            release_hw_index(core_id, level, hw_index);
            bucket->set_hw_index(LPM_NULL_INDEX);
        }

        const lpm_key_t& bucket_root = bucket->get_root();
        if ((is_gibraltar_revision(m_ll_device) || is_asic4_revision(m_ll_device) || is_asic3_revision(m_ll_device)
             || is_asic5_revision(m_ll_device))
            && (level == lpm_level_e::L2)
            && (bucket_root != lpm_key_t())) {
            // Find all L1 buckets that are affected by this L2 bucket location change
            lpm_bucket_raw_ptr_vec l1_buckets_vector = get_l1_buckets_default_changed(bucket);
            for (auto& l1_bucket : l1_buckets_vector) {
                bucket_changed(l1_bucket, BUCKET_REFRESHED);
            }
        }
    } else {
        notify_hw_index_occupancy_changed(bucket);
    }
}

void
bucketing_tree::reset_bucket(lpm_bucket* bucket)
{
    dassert_crit(bucket != nullptr);
    dassert_crit(bucket->empty());

    lpm_level_e level = bucket->get_level();

    ranged_index_generator& free_indices = m_sw_bucket_allocator_handler[(size_t)level].free_indices;
    lpm_bucket_index_t sw_index = bucket->get_sw_index();
    if (!free_indices.is_available(sw_index)) {
        free_indices.release(sw_index);
    }

    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    if (hw_index != LPM_NULL_INDEX) {
        size_t core_id = bucket->get_core();
        release_hw_index(core_id, level, hw_index);
    }

    bucket->reset();
}

lpm_bucket*
bucketing_tree::allocate_bucket(size_t core_id, lpm_level_e level)
{
    size_t index = 0;

    ranged_index_generator& indices_vector = m_sw_bucket_allocator_handler[(size_t)level].free_indices;
    bool status = indices_vector.allocate(index);
    if (!status) {
        log_err(TABLES, "Number of buckets exceeds reasonable limit %lu", indices_vector.max_size());

        return nullptr;
    }

    lpm_bucket* new_bucket = get_bucket_by_sw_index(level, index);
    bucket_changed(new_bucket, BUCKET_CHANGED);
    new_bucket->set_core(core_id);

    return new_bucket;
}

bool
bucketing_tree::is_hw_index_free(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index) const
{
    return m_hw_index_allocators[core_id][(size_t)level].hw_index_allocator->is_hw_index_free(hw_index);
}

la_status
bucketing_tree::allocate_hw_index_for_l2_bucket(size_t core_id, lpm_bucket* bucket, lpm_bucket_index_t& hw_index)
{
    dassert_crit(bucket->size()
                 <= m_tree_parameters[LEVEL2].bucket_num_fixed_entries + m_tree_parameters[LEVEL2].bucket_num_shared_entries);

    size_t root_width = bucket->get_root_width();
    bool support_double_entries = m_tree_parameters[LEVEL2].support_double_entries;
    const lpm_bucket::occupancy_data occupancy
        = lpm_bucket_occupancy_utils::get_bucket_occupancy(bucket, root_width + m_bucket_depth, support_double_entries);
    la_status status = m_hw_index_allocators[core_id][LEVEL2].hw_index_allocator->allocate_hw_index_for_bucket(occupancy, hw_index);
    return_on_error(status);

    allocate_hw_index_for_bucket_common(core_id, bucket, hw_index);

    return LA_STATUS_SUCCESS;
}

la_status
bucketing_tree::allocate_hw_index_for_l1_bucket(size_t core_id, lpm_bucket* bucket, lpm_bucket_index_t& hw_index)
{
    dassert_crit(bucket->size()
                 <= m_tree_parameters[LEVEL1].bucket_num_fixed_entries + m_tree_parameters[LEVEL1].bucket_num_shared_entries);

    la_status status;
    size_t root_width = bucket->get_root_width();
    bool support_double_entries = m_tree_parameters[LEVEL1].support_double_entries;
    const lpm_bucket::occupancy_data occupancy
        = lpm_bucket_occupancy_utils::get_bucket_occupancy(bucket, root_width + m_bucket_depth, support_double_entries);
    status = m_hw_index_allocators[core_id][LEVEL1].hw_index_allocator->allocate_hw_index_for_bucket(occupancy, hw_index);
    return_on_error(status);

    allocate_hw_index_for_bucket_common(core_id, bucket, hw_index);

    return LA_STATUS_SUCCESS;
}

void
bucketing_tree::allocate_hw_index_for_bucket_common(size_t core_id, lpm_bucket* bucket, lpm_bucket_index_t hw_index)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);

    lpm_bucket_index_t sw_index = bucket->get_sw_index();
    lpm_level_e level = bucket->get_level();
    m_hw_index_allocators[core_id][(size_t)level].hw_index_to_sw_index[hw_index] = sw_index;
    bucket->set_hw_index(hw_index);
}

la_status
bucketing_tree::move_l2_bucket_between_sram_and_hbm(size_t core_id,
                                                    lpm_bucket_index_t src_hw_index,
                                                    l2_bucket_location_e destination,
                                                    lpm_bucket*& out_l2_bucket,
                                                    lpm_bucket_raw_ptr_vec& out_l1_changed_buckets)
{
    if (src_hw_index < 0) {
        log_err(TABLES, "core %lu  bucketing_tree::%s  bucket HW index < 0", core_id, __func__);
        return LA_STATUS_EINVAL;
    }

    size_t hbm_address_offset = m_tree_parameters[LEVEL2].num_of_sram_buckets;
    bool src_is_hbm = is_location_in_hbm(lpm_level_e::L2, src_hw_index, hbm_address_offset);
    bool dst_is_hbm = (destination == l2_bucket_location_e::HBM);
    if (src_is_hbm == dst_is_hbm) {
        log_err(TABLES, "core_id=%lu, Bucket %d already in %s", core_id, src_hw_index, src_is_hbm ? "HBM" : "SRAM");
        return LA_STATUS_EINVAL;
    }

    lpm_bucket_index_t new_hw_index;
    lpm_hw_index_allocator_adapter_hbm* l2_allocator
        = static_cast<lpm_hw_index_allocator_adapter_hbm*>(m_hw_index_allocators[core_id][LEVEL2].hw_index_allocator.get());
    la_status status = l2_allocator->allocate_hw_index_for_bucket(destination, new_hw_index);
    return_on_error(status,
                    TABLES,
                    ERROR,
                    "core_id=%lu, Failed to allocate HW index for bucket %d in %s",
                    core_id,
                    src_hw_index,
                    dst_is_hbm ? "HBM" : "SRAM");
    dassert_crit(dst_is_hbm == is_location_in_hbm(lpm_level_e::L2, new_hw_index, hbm_address_offset));

    out_l2_bucket = get_bucket_by_hw_index(core_id, lpm_level_e::L2, src_hw_index);
    allocate_hw_index_for_bucket_common(core_id, out_l2_bucket, new_hw_index);
    m_hbm_cache_managers[core_id].notify_bucket_moved(src_hw_index, new_hw_index);
    release_hw_index(core_id, lpm_level_e::L2, src_hw_index);

    update_l1_buckets_after_moving_l2_bucket(out_l2_bucket, out_l1_changed_buckets);

    return LA_STATUS_SUCCESS;
}

void
bucketing_tree::update_l1_buckets_after_moving_l2_bucket(lpm_bucket* l2_bucket, lpm_bucket_raw_ptr_vec& out_l1_changed_buckets)
{
    const lpm_key_t& l2_root = l2_bucket->get_root();

    // Handling the containing L1 bucket
    lpm_bucket* l1_bucket = get_bucket(l2_root, lpm_level_e::L1);
    out_l1_changed_buckets.push_back(l1_bucket);
    if (is_pacific_revision(m_ll_device)) {
        return;
    }

    // Handling L1 defaults
    lpm_bucket_index_t l2_hw_index = l2_bucket->get_hw_index();
    dassert_crit(l2_hw_index != LPM_NULL_INDEX);
    lpm_key_payload default_entry = {.key = l2_bucket->get_root(), .payload = static_cast<lpm_payload_t>(l2_hw_index)};
    lpm_bucket_raw_ptr_vec l1_buckets_vector = get_l1_buckets_default_changed(l2_bucket);
    for (auto& affected_l1_bucket : l1_buckets_vector) {
        affected_l1_bucket->set_default_entry(default_entry);
        out_l1_changed_buckets.push_back(affected_l1_bucket);
    }
}

la_status
bucketing_tree::move_l2_bucket_to_row(size_t core_id,
                                      lpm_bucket_index_t src_hw_index,
                                      lpm_bucket_index_t new_hw_index,
                                      lpm_bucket*& out_l2_bucket,
                                      lpm_bucket_raw_ptr_vec& out_l1_changed_buckets)
{
    if (src_hw_index < 0) {
        log_err(TABLES, "core %lu  %s: bucket index < 0", core_id, __func__);
        return LA_STATUS_EINVAL;
    }

    if (src_hw_index == new_hw_index) {
        return LA_STATUS_SUCCESS;
    }

    bool is_available = is_hw_index_free(core_id, lpm_level_e::L2, new_hw_index);
    if (!is_available) {
        return LA_STATUS_EBUSY;
    }

    out_l2_bucket = get_bucket_by_hw_index(core_id, lpm_level_e::L2, src_hw_index);
    size_t root_width = out_l2_bucket->get_root_width();
    bool support_double_entries = m_tree_parameters[LEVEL2].support_double_entries;
    const lpm_bucket::occupancy_data occupancy = lpm_bucket_occupancy_utils::get_bucket_hw_occupancy(
        m_ll_device, out_l2_bucket, root_width + m_bucket_depth, support_double_entries);

    la_status status
        = m_hw_index_allocators[core_id][LEVEL2].hw_index_allocator->allocate_specific_hw_index_for_bucket(occupancy, new_hw_index);
    return_on_error(
        status, TABLES, ERROR, "core_id=%lu, Failed to move bucket from HW index %d to %d", core_id, src_hw_index, new_hw_index);

    allocate_hw_index_for_bucket_common(core_id, out_l2_bucket, new_hw_index);
    m_hbm_cache_managers[core_id].notify_bucket_moved(src_hw_index, new_hw_index);
    release_hw_index(core_id, lpm_level_e::L2, src_hw_index);

    update_l1_buckets_after_moving_l2_bucket(out_l2_bucket, out_l1_changed_buckets);

    return LA_STATUS_SUCCESS;
}

void
bucketing_tree::release_hw_index(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index)
{
    log_xdebug(TABLES, "core_id=%lu, tree releasing HW index %d", core_id, hw_index);

    lpm_bucket_index_vec& hw_index_to_sw_index = m_hw_index_allocators[core_id][(size_t)level].hw_index_to_sw_index;
    hw_index_to_sw_index[hw_index] = LPM_NULL_INDEX;

    m_hw_index_allocators[core_id][(size_t)level].hw_index_allocator->release_hw_index(hw_index);

    m_hw_index_allocators[core_id][(size_t)level].bucket_release_time[hw_index] = std::chrono::steady_clock::now();
}

void
bucketing_tree::notify_hw_index_occupancy_changed(const lpm_bucket* bucket)
{
    lpm_bucket_index_t hw_index = bucket->get_hw_index();
    if (hw_index == LPM_NULL_INDEX) {
        return;
    }

    size_t root_width = bucket->get_root_width();
    size_t core_id = bucket->get_core();
    lpm_level_e level = bucket->get_level();
    size_t level_idx = static_cast<size_t>(level);
    bool support_double_entries = m_tree_parameters[level_idx].support_double_entries;

    lpm_bucket::occupancy_data bucket_occupancy = lpm_bucket_occupancy_utils::get_bucket_hw_occupancy(
        m_ll_device, bucket, root_width + m_bucket_depth, support_double_entries);
    m_hw_index_allocators[core_id][level_idx].hw_index_allocator->notify_hw_index_occupancy_changed(hw_index, bucket_occupancy);
}

void
bucketing_tree::add_node_to_bucket(lpm_node* node, lpm_nodes_bucket* bucket)
{
    log_xdebug(TABLES,
               "tree adding node %s to bucket (sw index %d  hw index %d)",
               node->to_string().c_str(),
               bucket->get_sw_index(),
               bucket->get_hw_index());

    bucket_changed(bucket, BUCKET_CHANGED);
    bucket->set_root(lpm_key_t());

    bucket->insert(node);
}

void
bucketing_tree::move_bucket_nodes(lpm_nodes_bucket* dest_bucket, lpm_nodes_bucket* src_bucket, lpm_node* src_bucket_start_node)
{
    const lpm_key_t& key = src_bucket_start_node->get_key();
    for (lpm_node* node : src_bucket->get_nodes()) {
        const lpm_key_t& node_key = node->get_key();
        if (!is_contained(key, node_key)) {
            continue;
        }

        log_xdebug(TABLES,
                   "tree moving node %s from bucket %d (sw index) to bucket %d",
                   node->to_string().c_str(),
                   src_bucket->get_sw_index(),
                   dest_bucket->get_sw_index());

        src_bucket->remove(node);
        dest_bucket->insert(node);
    }
}

lpm_bucket*
bucketing_tree::get_bucket(const lpm_node* node, lpm_level_e level) const
{
    lpm_bucket* bucket;
    if (level == lpm_level_e::L1) {
        bucket = get_l1_bucket(node);
    } else {
        bucket = get_l2_bucket(node);
    }

    return bucket;
}

lpm_nodes_bucket*
bucketing_tree::get_containing_l2_bucket(const lpm_node* node, const lpm_key_t& key) const
{
    const lpm_node* current_node = node;
    while (current_node != nullptr) {
        const lpm_bucketing_data& current_node_data = current_node->data();
        if (current_node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS) {
            return nullptr;
        }

        if ((current_node_data.l2_bucket != nullptr) && (is_contained(current_node_data.l2_bucket->get_root(), key))) {
            return current_node_data.l2_bucket.get();
        }

        current_node = current_node->get_parent_node();
    }

    return nullptr;
}

lpm_nodes_bucket*
bucketing_tree::get_l2_bucket(const lpm_node* node) const
{
    const lpm_node* current_node = node;
    while (current_node != nullptr) {
        const lpm_bucketing_data& current_node_data = current_node->data();
        if (current_node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS) {
            return nullptr;
        }

        if (current_node_data.l2_bucket != nullptr) {
            return current_node_data.l2_bucket.get();
        }

        current_node = current_node->get_parent_node();
    }

    return nullptr;
}

lpm_buckets_bucket*
bucketing_tree::get_l1_bucket(const lpm_node* node) const
{
    const lpm_node* current_node = node;
    while (current_node != nullptr) {
        const lpm_bucketing_data& current_node_data = current_node->data();
        if (current_node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG) {
            return nullptr;
        }

        if (current_node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::UNBUCKETED) {
            return nullptr;
        }

        if (current_node_data.l1_bucket != nullptr) {
            return current_node_data.l1_bucket.get();
        }

        current_node = current_node->get_parent_node();
    }

    return nullptr;
}

lpm_bucket*
bucketing_tree::get_bucket(const lpm_key_t& key, lpm_level_e level) const
{
    const lpm_node* node = m_binary_lpm_tree.find_node(key);
    dassert_crit(node != nullptr);

    lpm_bucket* bucket = get_bucket(node, level);

    return bucket;
}

void
bucketing_tree::mark_unbalanced_nodes(const vector_alloc<lpm_node*>& path_to_mark)
{
    for (lpm_node* node : path_to_mark) {
        const lpm_key_t& node_key = node->get_key();
        lpm_bucketing_data& node_data = node->data();
        m_changed_keys_to_bucketing_data.push_back({node_key, node_data});
        node_data.is_balanced = false;
    }
}

void
bucketing_tree::unbucket_path(const vector_alloc<lpm_node*>& path_to_unbucket)
{
    for (lpm_node_vec::const_iterator it = path_to_unbucket.begin(); it != path_to_unbucket.end(); it++) {
        auto node = *it;

        lpm_node_vec::const_iterator next_it = it + 1;
        auto next = (next_it != path_to_unbucket.end()) ? *next_it : nullptr;

        dassert_crit(node != next);
        unbucket_node(node, next);
    }
}

void
bucketing_tree::unbucket_nodes_rec(lpm_node* node)
{
    lpm_bucketing_data& node_data = node->data();
    if (node_data.is_balanced) {
        return;
    }

    const lpm_key_t& node_key = node->get_key();
    m_changed_keys_to_bucketing_data.push_back({node_key, node_data});
    node_data.is_balanced = true;
    unbucket_node(node);

    lpm_node* left_child = node->get_left_child();
    lpm_node* right_child = node->get_right_child();
    for (lpm_node* child : {left_child, right_child}) {
        const lpm_bucketing_data& child_data = child->data();
        bool unbucket_child = ((child != nullptr) && (!child_data.is_balanced) && (!is_node_group_root(child)));
        if (unbucket_child) {
            unbucket_nodes_rec(child);
        }
    }
}

lpm_bucket_sptr
bucketing_tree::create_sw_bucket(lpm_level_e level, lpm_bucket_index_t sw_index) const
{
    dassert_crit(sw_index != LPM_NULL_INDEX);

    if (level == lpm_level_e::L1) {
        return std::make_shared<lpm_buckets_bucket>(sw_index);
    } else {
        return std::make_shared<lpm_nodes_bucket>(sw_index);
    }
}

lpm_bucket*
bucketing_tree::get_bucket_by_sw_index(lpm_level_e level, lpm_bucket_index_t index)
{
    const bucketing_tree* const_tree = this;
    const lpm_bucket* const_bucket = const_tree->get_bucket_by_sw_index(level, index);

    return const_cast<lpm_bucket*>(const_bucket);
}

const lpm_bucket*
bucketing_tree::get_bucket_by_sw_index(lpm_level_e level, lpm_bucket_index_t index) const
{
    if (index == LPM_NULL_INDEX) {
        return nullptr;
    }

    lpm_bucket_ptr_vec& bucket_vector = m_sw_bucket_allocator_handler[(size_t)level].bucket_vector;
    if ((size_t)index >= bucket_vector.size()) {
        return nullptr;
    }

    if (bucket_vector[index] == nullptr) {
        bucket_vector[index] = create_sw_bucket(level, index);
    }

    return bucket_vector[index].get();
}

const lpm_bucket*
bucketing_tree::get_bucket_by_hw_index(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index) const
{
    const lpm_bucket_index_vec& hw_to_sw = m_hw_index_allocators[core_id][(size_t)level].hw_index_to_sw_index;

    dassert_crit(static_cast<size_t>(hw_index) < hw_to_sw.size());

    lpm_bucket_index_t sw_index = hw_to_sw[hw_index];
    const lpm_bucket* bucket = get_bucket_by_sw_index(level, sw_index);
    return bucket;
}

lpm_bucket*
bucketing_tree::get_bucket_by_hw_index(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index)
{
    lpm_bucket_index_vec& hw_to_sw = m_hw_index_allocators[core_id][(size_t)level].hw_index_to_sw_index;

    dassert_crit(static_cast<size_t>(hw_index) < hw_to_sw.size());

    lpm_bucket_index_t sw_index = hw_to_sw[hw_index];
    lpm_bucket* bucket = get_bucket_by_sw_index(level, sw_index);
    return bucket;
}

const lpm_bucket*
bucketing_tree::get_neighbor_bucket(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index) const
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    size_t hbm_address_offset = m_tree_parameters[(size_t)level].num_of_sram_buckets;
    if (is_location_in_hbm(level, hw_index, hbm_address_offset)) {
        return nullptr;
    }
    return get_bucket_by_hw_index(core_id, level, hw_index ^ 1);
}

lpm_bucket*
bucketing_tree::get_neighbor_bucket(size_t core_id, lpm_level_e level, lpm_bucket_index_t hw_index)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    size_t hbm_address_offset = m_tree_parameters[(size_t)level].num_of_sram_buckets;
    if (is_location_in_hbm(level, hw_index, hbm_address_offset)) {
        return nullptr;
    }
    return get_bucket_by_hw_index(core_id, level, hw_index ^ 1);
}

lpm_bucket_const_ptr_vec
bucketing_tree::get_buckets(lpm_level_e level) const
{
    lpm_bucket_const_ptr_vec ret;
    for (const auto& curr : m_sw_bucket_allocator_handler[(size_t)level].bucket_vector) {
        if ((!curr) || (curr->empty())) {
            continue;
        }
        ret.push_back(curr);
    }

    return ret;
}

const vector_alloc<size_t>&
bucketing_tree::get_group_to_core() const
{
    return m_group_to_core;
}

const lpm_node*
bucketing_tree::get_root_node() const
{
    return m_binary_lpm_tree.get_root();
}

const lpm_node*
bucketing_tree::find_node(const lpm_key_t& key) const
{
    return m_binary_lpm_tree.find_node(key);
}

bool
bucketing_tree::empty() const
{
    std::vector<const lpm_node*> wave;
    const lpm_node* current_node = m_binary_lpm_tree.get_root();
    wave.push_back(current_node);

    while (!wave.empty()) {
        const lpm_node* current_node = wave.back();
        wave.pop_back();
        const lpm_bucketing_data& current_node_data = current_node->data();
        if (current_node_data.is_user_prefix) {
            return false;
        }

        const lpm_node* current_left_child = current_node->get_left_child();
        const lpm_node* current_right_child = current_node->get_right_child();
        for (const lpm_node* child : {current_left_child, current_right_child}) {
            if (child != nullptr) {
                wave.push_back(child);
            }
        }
    }

    return true;
}

la_status
bucketing_tree::lookup(const lpm_key_t& key,
                       size_t core_id,
                       lpm_level_e level,
                       lpm_payload_t hw_bucket_index,
                       lpm_key_t& out_hit_key,
                       lpm_payload_t& out_hit_payload,
                       bool& out_is_default) const
{
    lpm_bucket_index_t hw_index = hw_bucket_index;
    const lpm_bucket* bucket = get_bucket_by_hw_index(core_id, level, hw_index);
    if (!bucket) {
        log_err(TABLES, "requested %s bucket HW index=%d doesn't exist.", to_string(level).c_str(), hw_index);
        out_hit_key = lpm_key_t();
        out_hit_payload = INVALID_PAYLOAD;
        return LA_STATUS_EINVAL;
    }

    la_status status = bucket->lookup(key, out_hit_key, out_hit_payload, out_is_default);

    return status;
}

void
bucketing_tree::clear_iteration_members()
{
    for (lpm_level_e level : {lpm_level_e::L1, lpm_level_e::L2}) {
        bucketing_tree_level_iteration_members& iteration_members = m_iteration_members[(size_t)level];
        iteration_members.affected_buckets_bitmap = bit_vector();
        iteration_members.affected_buckets_data.resize(0);
    }

    m_changed_keys_to_bucketing_data.clear();
    m_l2_executed_actions.clear();
    m_nodes_to_rebucket.clear();

    m_total_stats.insertions += m_stats.insertions;
    m_total_stats.removals += m_stats.removals;
    m_total_stats.modifications += m_stats.modifications;
    m_total_stats.refreshes += m_stats.refreshes;
    m_total_stats.unbuckets += m_stats.unbuckets;

    m_stats.reset();

    dassert_slow(sanity());
}

void
bucketing_tree::commit()
{
    if (m_is_hbm_enabled) {
        update_hbm_cache_manager();
    }

    for (size_t core_id = 0; core_id < m_num_of_cores; core_id++) {
        for (lpm_level_e level : {lpm_level_e::L1, lpm_level_e::L2}) {
            m_hw_index_allocators[core_id][static_cast<size_t>(level)].hw_index_allocator->commit();
        }
    }

    clear_iteration_members();
}

void
bucketing_tree::update_hbm_cache_manager()
{
    for (changed_bucket_data& changed_bucket : m_iteration_members[LEVEL2].affected_buckets_data) {
        lpm_bucket_index_t sw_index = changed_bucket.bucket_index;
        lpm_bucket* bucket = get_bucket_by_sw_index(lpm_level_e::L2, sw_index);
        const lpm_changed_bucket_data& old_data = changed_bucket.bucket_data;
        dassert_crit(bucket != nullptr);
        lpm_bucket_index_t hw_index = bucket->get_hw_index();
        size_t core_id = bucket->get_core();

        bool is_refresh = (changed_bucket.change_type == lpm_change_e::BUCKET_REFRESHED);
        if (is_refresh) {
            dassert_crit(core_id != CORE_ID_NONE);
            lpm_nodes_bucket* l2_bucket = static_cast<lpm_nodes_bucket*>(bucket);
            bool is_evictable = !l2_bucket->is_pinned();
            m_hbm_cache_managers[core_id].set_bucket_eviction_enable(hw_index, is_evictable);
            continue;
        }

        bool is_write_to_hw = (hw_index != LPM_NULL_INDEX);
        if (is_write_to_hw) {
            dassert_crit(core_id != CORE_ID_NONE);

            if (old_data.hw_index == LPM_NULL_INDEX) {
                m_hbm_cache_managers[core_id].notify_bucket_created(hw_index);

                lpm_nodes_bucket* l2_bucket = static_cast<lpm_nodes_bucket*>(bucket);
                bool is_evictable = !l2_bucket->is_pinned();
                m_hbm_cache_managers[core_id].set_bucket_eviction_enable(hw_index, is_evictable);
            } else {
                m_hbm_cache_managers[core_id].notify_bucket_created(hw_index, old_data.hotness_level);
            }
        }

        if (old_data.hw_index != LPM_NULL_INDEX) {
            size_t core_id = old_data.core_id;
            dassert_crit(core_id != CORE_ID_NONE);
            m_hbm_cache_managers[core_id].notify_bucket_removed(old_data.hw_index);
        }
    }
}

void
bucketing_tree::withdraw()
{
    start_profiling("Withdraw");
    log_debug(TABLES, "bucketing_tree::%s", __func__);

    withdraw_reset_bucketing();
    withdraw_regenerate_tree_topology();
    withdraw_bucketing_data(); // has to be before withdraw_repopulate_l2_buckets() because otherwise group roots will appear as
                               // invalid
                               // nodes and cannot be inserted to L2 buckets.
    withdraw_regenerate_buckets_properties();
    withdraw_repopulate_l2_buckets();
    withdraw_repopulate_l1_buckets();
    calculate_default_entries();
    withdraw_hw_indexes();

    m_stats.reset();

    // Clear to prevent re-doing the withdraw.
    clear_iteration_members();
}

void
bucketing_tree::withdraw_reset_bucketing()
{
    for (changed_bucket_data& changed_bucket : m_iteration_members[LEVEL1].affected_buckets_data) {
        lpm_bucket_index_t index = changed_bucket.bucket_index;
        lpm_bucket* bucket = get_bucket_by_sw_index(lpm_level_e::L1, index);
        dassert_crit(bucket != nullptr);

        lpm_buckets_bucket* buckets_bucket = static_cast<lpm_buckets_bucket*>(bucket);
        buckets_bucket->clear_sub_buckets();

        if (changed_bucket.change_type == lpm_change_e::BUCKET_CHANGED) {
            reset_bucket(bucket);
        }
    }

    for (changed_bucket_data& changed_bucket : m_iteration_members[LEVEL2].affected_buckets_data) {
        lpm_bucket_index_t index = changed_bucket.bucket_index;
        lpm_bucket* bucket = get_bucket_by_sw_index(lpm_level_e::L2, index);
        dassert_crit(bucket != nullptr);

        lpm_nodes_bucket* nodes_bucket = static_cast<lpm_nodes_bucket*>(bucket);

        nodes_bucket->clear_members();

        if (changed_bucket.change_type == lpm_change_e::BUCKET_CHANGED) {
            reset_bucket(bucket);
        }
    }
}

void
bucketing_tree::withdraw_regenerate_tree_topology()
{
    // Regenerate tree structure.
    for (lpm_implementation_desc_vec::reverse_iterator it = m_l2_executed_actions.rbegin(); it != m_l2_executed_actions.rend();
         ++it) {
        const auto& action_desc = *it;
        lpm_implementation_action_e action = action_desc.m_action;
        const lpm_key_t& key(action_desc.m_key);
        lpm_node* node = m_binary_lpm_tree.find_node(key);
        const lpm_key_t& node_key = node->get_key();
        lpm_bucketing_data& node_data = node->data();

        switch (action) {
        case lpm_implementation_action_e::INSERT: {

            dassert_crit(node_key == key);
            if (is_node_group_root(node)) {
                node_data.is_user_prefix = false;
                node_data.payload = action_desc.m_payload;
            } else {
                remove_node_from_tree(node);
            }
            break;
        }
        case lpm_implementation_action_e::REMOVE: {
            bool exist = ((node_key == key) && (node->is_valid()));
            if (exist) {
                dassert_crit(!node_data.is_user_prefix);
                node_data.payload = action_desc.m_payload;
                node_data.is_user_prefix = true;
            } else {
                lpm_bucketing_data bucketing_data;
                bucketing_data.payload = action_desc.m_payload;
                bucketing_data.is_user_prefix = true;
                const lpm_node* new_node = m_binary_lpm_tree.insert_node_to_tree(node, key, bucketing_data);
                dassert_crit(new_node != nullptr);
            }
        } break;
        case lpm_implementation_action_e::MODIFY:
            node_data.payload = action_desc.m_payload;
            break;
        case lpm_implementation_action_e::ADD_GROUP_ROOT:
            dassert_crit(node_key == key);
            revert_insert_group_root(node);
            break;
        case lpm_implementation_action_e::REMOVE_GROUP_ROOT:
            revert_remove_group_root(node, key, action_desc.m_payload, action_desc.m_group_id, action_desc.m_core_id);
            break;
        case lpm_implementation_action_e::MODIFY_GROUP_TO_CORE:
            m_group_to_core[action_desc.m_group_id] = action_desc.m_core_id;
            break;

        default:
            dassert_crit(false);
        }
    }
}

void
bucketing_tree::withdraw_regenerate_buckets_properties()
{
    for (lpm_level_e level : {lpm_level_e::L1, lpm_level_e::L2}) {
        for (changed_bucket_data& changed_bucket : m_iteration_members[size_t(level)].affected_buckets_data) {
            if (changed_bucket.change_type == lpm_change_e::BUCKET_REFRESHED) {
                continue;
            }

            lpm_bucket_index_t index = changed_bucket.bucket_index;
            const lpm_changed_bucket_data& data = changed_bucket.bucket_data;

            // This bucket was generated in the last iteration
            if (data.hw_index == LPM_NULL_INDEX) {
                continue;
            }

            lpm_bucket* bucket = get_bucket_by_sw_index(level, index);

            bucket->set_root(data.root);

            uint64_t dummy_index;
            m_sw_bucket_allocator_handler[(size_t)level].free_indices.allocate(index, dummy_index);

            bucket->set_hw_index(data.hw_index);
            bucket->set_core(data.core_id);

            m_hw_index_allocators[data.core_id][(size_t)level].hw_index_to_sw_index[data.hw_index] = index;
        }
    }
}

void
bucketing_tree::withdraw_repopulate_l2_buckets()
{
    for (changed_bucket_data& changed_bucket : m_iteration_members[LEVEL2].affected_buckets_data) {
        const lpm_changed_bucket_data& data = changed_bucket.bucket_data;
        if (data.hw_index == LPM_NULL_INDEX) {
            continue;
        }

        lpm_bucket_index_t index = changed_bucket.bucket_index;
        lpm_nodes_bucket* l2_bucket = static_cast<lpm_nodes_bucket*>(get_bucket_by_sw_index(lpm_level_e::L2, index));

        const lpm_key_t& l2_root = l2_bucket->get_root();
        const lpm_node* node = m_binary_lpm_tree.find_node(l2_root);
        dassert_crit(node != nullptr);

        // Insert nodes to bucket
        std::vector<const lpm_node*> wave;
        wave.push_back(node);

        while (!wave.empty()) {
            const lpm_node* curr_node = wave.back();
            wave.pop_back();

            const lpm_bucketing_data& curr_node_data = curr_node->data();
            const lpm_nodes_bucket* node_l2_bucket = curr_node_data.l2_bucket.get();
            if (node_l2_bucket && (node_l2_bucket != l2_bucket)) {
                continue;
            }

            if (curr_node->is_valid()) {
                l2_bucket->insert(const_cast<lpm_node*>(curr_node));
            }

            const lpm_node* current_left_child = curr_node->get_left_child();
            const lpm_node* current_right_child = curr_node->get_right_child();
            for (const lpm_node* child : {current_left_child, current_right_child}) {
                if (child != nullptr) {
                    wave.push_back(child);
                }
            }
        }

        dassert_crit(!l2_bucket->empty());

        // Fix top_node
        dassert_slow(l2_bucket == static_cast<lpm_nodes_bucket*>(get_bucket(node, lpm_level_e::L2)));
        compute_top_node(l2_bucket, const_cast<lpm_node*>(node));
    }
}

void
bucketing_tree::withdraw_repopulate_l1_buckets()
{
    for (changed_bucket_data& changed_bucket : m_iteration_members[LEVEL1].affected_buckets_data) {
        const lpm_changed_bucket_data& data = changed_bucket.bucket_data;
        if (data.hw_index == LPM_NULL_INDEX) {
            continue;
        }

        lpm_bucket_index_t index = changed_bucket.bucket_index;
        lpm_buckets_bucket* l1_bucket = static_cast<lpm_buckets_bucket*>(get_bucket_by_sw_index(lpm_level_e::L1, index));
        dassert_crit(l1_bucket != nullptr);

        const lpm_key_t& l1_root = l1_bucket->get_root();

        const lpm_node* l1_bucketing_data_node = m_binary_lpm_tree.get_root();
        while (is_contained(l1_bucketing_data_node->get_key(), l1_root)) {
            const lpm_bucketing_data& l1_bucketing_data_node_data = l1_bucketing_data_node->data();
            if (l1_bucketing_data_node_data.l1_bucket.get() == l1_bucket) {
                break;
            }

            const lpm_key_t& l1_bucketing_data_node_key = l1_bucketing_data_node->get_key();
            size_t current_width = l1_bucketing_data_node_key.get_width();
            bool go_right = l1_root.bit_from_msb(current_width);
            const lpm_node* l1_bucketing_data_left_child = l1_bucketing_data_node->get_left_child();
            const lpm_node* l1_bucketing_data_right_child = l1_bucketing_data_node->get_right_child();
            l1_bucketing_data_node = go_right ? l1_bucketing_data_right_child : l1_bucketing_data_left_child;
        }

        // Find all L2 bucket within the region of this l1_bucket
        vector_alloc<const lpm_node*> wave;
        wave.push_back(l1_bucketing_data_node);

        while (!wave.empty()) {
            const lpm_node* curr_node = wave.back();
            wave.pop_back();

            const lpm_bucketing_data& curr_node_data = curr_node->data();
            const lpm_buckets_bucket* node_l1_bucket = curr_node_data.l1_bucket.get();
            if (node_l1_bucket && (node_l1_bucket != l1_bucket)) {
                continue;
            }

            const lpm_node* curr_left_child = curr_node->get_left_child();
            const lpm_node* curr_right_child = curr_node->get_right_child();
            for (const lpm_node* child : {curr_left_child, curr_right_child}) {
                if (child != nullptr) {
                    wave.push_back(child);
                }
            }

            const auto& l2_bucket = curr_node_data.l2_bucket;
            if (l2_bucket) {
                l1_bucket->insert(l2_bucket.lock());
            }
        }
    }
}

void
bucketing_tree::withdraw_hw_indexes()
{
    for (size_t core_id = 0; core_id < m_num_of_cores; core_id++) {
        for (lpm_level_e level : {lpm_level_e::L1, lpm_level_e::L2}) {
            m_hw_index_allocators[core_id][static_cast<size_t>(level)].hw_index_allocator->withdraw();
        }
    }
}

void
bucketing_tree::withdraw_bucketing_data()
{
    lpm_key_set keys_already_assigned;
    for (auto& modified_key : m_changed_keys_to_bucketing_data) {
        const lpm_key_t& key = modified_key.first;
        if (keys_already_assigned.count(key) > 0) {
            continue;
        }

        keys_already_assigned.insert(key);

        lpm_node* node = m_binary_lpm_tree.find_node(key);
        if (node == nullptr || node->get_key() != key) {
            continue;
        }

        node->set_data(modified_key.second);
    }
}

bucketing_tree::bucketing_tree_level_parameters
bucketing_tree::get_parameters(lpm_level_e level) const
{
    return m_tree_parameters[(size_t)level];
}

size_t
bucketing_tree::get_max_bucket_depth() const
{
    return m_bucket_depth;
}

core_buckets_occupancy_vec
bucketing_tree::get_occupancy(lpm_level_e level) const
{
    core_buckets_occupancy_vec occupancy(m_num_of_cores);

    for (const auto& bucket : m_sw_bucket_allocator_handler[(size_t)level].bucket_vector) {
        if ((!bucket) || (bucket->empty())) {
            continue;
        }
        size_t core_id = bucket->get_core();
        core_buckets_occupancy& core_buckets_occupancy = occupancy[core_id];
        size_t root_width = bucket->get_root_width();
        bool support_double_entries = m_tree_parameters[static_cast<size_t>(bucket->get_level())].support_double_entries;
        lpm_bucket::occupancy_data data = lpm_bucket_occupancy_utils::get_bucket_hw_occupancy(
            m_ll_device, bucket.get(), root_width + m_bucket_depth, support_double_entries);

        size_t hbm_address_offset = m_tree_parameters[(size_t)level].num_of_sram_buckets;
        bool is_hbm = is_location_in_hbm(level, bucket->get_hw_index(), hbm_address_offset);
        bool is_ipv6 = bucket->get_root().bit_from_msb(0);
        if (is_hbm) {
            core_buckets_occupancy.hbm_buckets++;
            core_buckets_occupancy.hbm_entries += data.total_entries;
            if (is_ipv6) {
                core_buckets_occupancy.hbm_ipv6_entries += data.total_entries;
            } else {
                core_buckets_occupancy.hbm_ipv4_entries += data.total_entries;
            }
        } else {
            core_buckets_occupancy.sram_single_entries += (data.total_entries - data.double_entries);
            core_buckets_occupancy.sram_double_entries += data.double_entries;
            core_buckets_occupancy.sram_buckets++;
            if (get_neighbor_bucket(bucket->get_core(), bucket->get_level(), bucket->get_hw_index()) == nullptr) {
                core_buckets_occupancy.sram_unpaired_buckets++;
            }
            if (is_ipv6) {
                core_buckets_occupancy.sram_ipv6_entries += data.total_entries;
            } else {
                core_buckets_occupancy.sram_ipv4_entries += data.total_entries;
            }
        }
    }

    for (size_t core_id = 0; core_id < m_num_of_cores; core_id++) {
        core_buckets_occupancy& core_buckets_occupancy = occupancy[core_id];
        core_buckets_occupancy.sram_rows = (core_buckets_occupancy.sram_buckets - core_buckets_occupancy.sram_unpaired_buckets) / 2
                                           + core_buckets_occupancy.sram_unpaired_buckets;
    }

    return occupancy;
}

lpm_action_statistics
bucketing_tree::get_action_distribution_stats() const
{
    return m_stats;
}

lpm_action_statistics
bucketing_tree::get_total_action_distribution_stats() const
{
    return m_total_stats;
}

void
bucketing_tree::calculate_prefixes_load_per_core(lpm_ip_protocol_e protocol, vector_alloc<size_t>& out_load_per_core) const
{
    out_load_per_core.assign(m_num_of_cores, 0);

    const lpm_node* left_root_child = m_binary_lpm_tree.get_root()->get_left_child();
    const lpm_node* right_root_child = m_binary_lpm_tree.get_root()->get_right_child();
    const auto& start_node = (protocol == lpm_ip_protocol_e::IPV4) ? left_root_child : right_root_child;
    const lpm_bucketing_data& start_node_data = start_node->data();
    size_t group_id = start_node_data.group;
    dassert_crit(group_id != GROUP_ID_NONE);
    size_t core_id = m_group_to_core[group_id];
    dassert_crit(core_id != CORE_ID_NONE);

    calculate_prefixes_load_per_core_rec(core_id, start_node, out_load_per_core);
    log_debug(TABLES, "%s: Ended successfully", __func__);
}

void
bucketing_tree::calculate_prefixes_load_per_core_rec(size_t core,
                                                     const lpm_node* node,
                                                     vector_alloc<size_t>& out_load_per_core) const
{
    if (node == nullptr) {
        return;
    }

    const lpm_bucketing_data& node_data = node->data();
    if (is_node_group_root(node)) {
        size_t group_id = node_data.group;
        dassert_crit(group_id != GROUP_ID_NONE);
        core = m_group_to_core[group_id];
        dassert_crit(core != CORE_ID_NONE);
    }

    if (node_data.is_user_prefix) {
        out_load_per_core[core]++;
    }

    const lpm_node* left_child = node->get_left_child();
    const lpm_node* right_child = node->get_right_child();
    for (const lpm_node* child : {left_child, right_child}) {
        calculate_prefixes_load_per_core_rec(core, child, out_load_per_core);
    }
}

lpm_key_t
bucketing_tree::get_shortest_key_to_separate_from_parent(const lpm_node* node) const
{
    dassert_crit(node != nullptr);
    const lpm_key_t& node_key = node->get_key();
    dassert_crit(node_key.get_width() > 0);

    bool is_group_root = is_node_group_root(node);
    if (is_group_root) {
        return node_key; /* we must not go outside the group */
    }

    const auto& parent = node->get_parent_node();

    dassert_ncrit(parent);
    if (!parent) {
        return lpm_key_t();
    }

    const lpm_key_t& parent_key = parent->get_key();
    size_t parent_key_width = parent_key.get_width();
    dassert_crit(node_key.get_width() > parent_key_width);

    lpm_key_t result = node_key.bits_from_msb(0, parent_key_width + 1);

    return result;
}

void
bucketing_tree::find_subtree_with_given_weighted_size(const resource_descriptor& requested_weighted_size,
                                                      const lpm_key_vec& from_core_group_roots_keys,
                                                      size_t max_width,
                                                      size_t& out_from_group,
                                                      lpm_key_t& out_subtree_key,
                                                      size_t& out_achieved_weighted_size) const
{
    find_subtree_ret_data best_result;
    size_t best_diff = requested_weighted_size.count;

    for (const lpm_key_t& group_root_key : from_core_group_roots_keys) {
        const lpm_node* group_root_node = m_binary_lpm_tree.find_node(group_root_key);
        dassert_crit(group_root_node != nullptr);
        dassert_crit(group_root_node->get_key() == group_root_key);
        dassert_crit(is_node_group_root(group_root_node));

        find_subtree_ret_data current_result
            = find_subtree_with_given_weighted_size_rec(group_root_node, requested_weighted_size, max_width);
        size_t current_diff = (abs((int)current_result.ret_weighted_size - (int)requested_weighted_size.count));
        if (current_diff < best_diff) {
            const lpm_bucketing_data& group_root_node_data = group_root_node->data();
            out_from_group = group_root_node_data.group;
            best_result = current_result;
            best_diff = current_diff;
        }
    }

    if (best_result.ret_node == nullptr) {
        out_subtree_key = lpm_key_t();
        out_achieved_weighted_size = 0;
        out_from_group = GROUP_ID_NONE;
    } else {
        out_subtree_key = get_shortest_key_to_separate_from_parent(best_result.ret_node);
        out_achieved_weighted_size = best_result.ret_weighted_size;

        log_debug(TABLES,
                  "%s: ret_node key %s/%zu   returned key %s/%zu",
                  __func__,
                  best_result.ret_node->get_key().to_string().c_str(),
                  best_result.ret_node->get_key().get_width(),
                  out_subtree_key.to_string().c_str(),
                  out_subtree_key.get_width());
    }
}

bucketing_tree::find_subtree_ret_data
bucketing_tree::find_subtree_with_given_weighted_size_rec(const lpm_node* node,
                                                          const resource_descriptor& requested_weighted_size,
                                                          size_t max_width) const
{
    dassert_crit(node != nullptr);

    const lpm_node* left_child = node->get_left_child();
    const lpm_node* right_child = node->get_right_child();
    bool check_left = ((left_child != nullptr) && (!is_node_group_root(left_child)));
    find_subtree_ret_data left_ret = check_left
                                         ? find_subtree_with_given_weighted_size_rec(left_child, requested_weighted_size, max_width)
                                         : find_subtree_ret_data();

    bool check_right = ((right_child != nullptr) && (!is_node_group_root(right_child)));
    find_subtree_ret_data right_ret
        = check_right ? find_subtree_with_given_weighted_size_rec(right_child, requested_weighted_size, max_width)
                      : find_subtree_ret_data();

    auto ret = choose_subtree_closest_to_given_weighted_size(left_ret, right_ret, requested_weighted_size, node, max_width);

    return ret;
}

size_t
bucketing_tree::get_tcam_load_of_l1_bucket(const lpm_buckets_bucket* l1_bucket) const
{
    if (l1_bucket == nullptr) {
        return 0;
    }

    const lpm_key_t& key = l1_bucket->get_root();
    logical_tcam_type_e key_type = m_core_tcam_utils->get_logical_tcam_type_of_key(key);
    if (key_type == logical_tcam_type_e::SINGLE) {
        return m_tcam_single_width_key_weight;
    }

    if (key_type == logical_tcam_type_e::DOUBLE) {
        return m_tcam_double_width_key_weight;
    }

    return m_tcam_quad_width_key_weight;
}

bucketing_tree::find_subtree_ret_data
bucketing_tree::choose_subtree_closest_to_given_weighted_size(const find_subtree_ret_data& left_ret,
                                                              const find_subtree_ret_data& right_ret,
                                                              const resource_descriptor& requested_weighted_size,
                                                              const lpm_node* node,
                                                              size_t max_width) const
{
    dassert_crit(node != nullptr);
    size_t node_weight = get_node_weight(node, requested_weighted_size.type);
    size_t subtree_weighted_size = left_ret.subtree_weighted_size + right_ret.subtree_weighted_size + node_weight;

    size_t my_width = node->get_width();
    bool children_width_ok = my_width + 1 <= max_width;

    // parent's delta from requested size
    find_subtree_ret_data ret;
    ret.ret_node = node;
    ret.ret_weighted_size = subtree_weighted_size;
    ret.subtree_weighted_size = subtree_weighted_size;
    size_t diff = (abs((int)subtree_weighted_size - (int)requested_weighted_size.count));
    log_xdebug(TABLES,
               "%s: requested_weighted_size.count %zu  my diff %zu  my_group %zu  my_key %s/%zu",
               __func__,
               requested_weighted_size.count,
               diff,
               get_owner_group(node),
               node->get_key().to_string().c_str(),
               node->get_key().get_width());

    // check if a child has the smallest delta from requested size
    for (const auto& child_ret : {left_ret, right_ret}) {
        if (!children_width_ok) {
            continue;
        }

        if (child_ret.ret_node == nullptr) {
            continue;
        }

        size_t child_diff = abs((int)child_ret.ret_weighted_size - (int)requested_weighted_size.count);
        const lpm_node* ret_node = child_ret.ret_node;
        log_xdebug(TABLES,
                   "%s: requested_weighted_size.count %zu  child's diff %zu  child's group %zu  child's key %s/%zu",
                   __func__,
                   requested_weighted_size.count,
                   child_diff,
                   get_owner_group(ret_node),
                   child_ret.ret_node->get_key().to_string().c_str(),
                   child_ret.ret_node->get_key().get_width());

        // we'll try to avoid returning a tree of size zero. A tree of size zero cannot help rebalance.
        bool choose_child = ((child_diff < diff) && (child_ret.ret_weighted_size != 0)) || (ret.ret_weighted_size == 0);

        if (choose_child) {
            ret.ret_weighted_size = child_ret.ret_weighted_size;
            ret.ret_node = child_ret.ret_node;
            diff = child_diff;
        }
    }

    dassert_crit(ret.ret_node != nullptr);

    return ret;
}

size_t
bucketing_tree::get_node_weight(const lpm_node* node, resource_type resource) const
{
    const lpm_bucketing_data& node_data = node->data();
    switch (resource) {
    case resource_type::PREFIXES: {
        size_t node_weight = node_data.is_user_prefix ? 1 : 0;
        return node_weight;
    }

    case resource_type::TCAM_LINES: {
        lpm_bucket* l1_bucket = node_data.l1_bucket.get();
        size_t node_weight = get_tcam_load_of_l1_bucket(static_cast<lpm_buckets_bucket*>(l1_bucket));
        return node_weight;
    }

    default:
        dassert_crit(false);
    }

    return 0;
}

size_t
bucketing_tree::get_load_of_group(size_t group_id, const lpm_key_t group_root_key, resource_type resource) const
{
    lpm_node* group_root_node = m_binary_lpm_tree.find_node(group_root_key);
    dassert_crit(group_root_node != nullptr);
    const lpm_key_t& group_root_node_key = group_root_node->get_key();
    dassert_crit(group_root_node_key == group_root_key);
    const lpm_bucketing_data& group_root_node_data = group_root_node->data();
    dassert_crit(group_root_node_data.group == group_id);

    size_t total_load = 0;

    std::vector<const lpm_node*> wave;
    wave.push_back(group_root_node);

    while (!wave.empty()) {
        const lpm_node* curr = wave.back();
        wave.pop_back();
        const lpm_node* left_child = curr->get_left_child();
        const lpm_node* right_child = curr->get_right_child();
        for (const lpm_node* child : {left_child, right_child}) {
            if ((child != nullptr) && (!is_node_group_root(child))) {
                wave.push_back(child);
            }
        }

        size_t current_load = get_node_weight(curr, resource);
        total_load += current_load;
    }

    return total_load;
}

bool
bucketing_tree::sanity() const
{
    bool res = true;
    dassert_slow(res = res && sanity_l2_buckets());
    dassert_slow(res = res && sanity_l1_buckets());
    dassert_slow(res = res && sanity_nodes());
    dassert_slow(res = res && sanity_bucketing_data());
    dassert_slow(res = res && sanity_check_is_balanced_integrity(m_binary_lpm_tree.get_root()));
    dassert_slow(res = res && m_binary_lpm_tree.sanity());
    return res;
}

bool
bucketing_tree::sanity_check_is_balanced_integrity(const lpm_node* node) const
{
    bool res = true;
    const lpm_bucketing_data& node_data = node->data();
    const lpm_node* left_child = node->get_left_child();
    const lpm_node* right_child = node->get_right_child();
    const lpm_bucketing_data& left_child_data = left_child->data();
    const lpm_bucketing_data& right_child_data = right_child->data();
    if (left_child) {
        res = sanity_check_is_balanced_integrity(left_child);
        if (!is_node_group_root(left_child)) {
            if ((node_data.is_balanced) && (!left_child_data.is_balanced)) {
                log_err(TABLES, "node=%s is not balanced", left_child->to_string().c_str());
                dassert_crit(false);
                res = false;
            }
        }
    }
    if (right_child) {
        res = sanity_check_is_balanced_integrity(right_child);
        if (!is_node_group_root(right_child)) {
            if ((node_data.is_balanced) && (!right_child_data.is_balanced)) {
                log_err(TABLES, "node=%s is not balanced", right_child->to_string().c_str());
                dassert_crit(false);
                res = false;
            }
        }
    }

    return res;
}

bool
bucketing_tree::sanity_bucketing_data() const
{
    lpm_bucket_index_set l1_buckets;
    lpm_bucket_index_set l2_buckets;
    std::vector<const lpm_node*> wave;
    wave.push_back(m_binary_lpm_tree.get_root());

    while (!wave.empty()) {
        const lpm_node* curr = wave.back();
        wave.pop_back();

        if (!curr) {
            continue;
        }

        const lpm_node* left_child = curr->get_left_child();
        const lpm_node* right_child = curr->get_right_child();
        wave.push_back(left_child);
        wave.push_back(right_child);

        const lpm_bucketing_data& curr_data = curr->data();
        bool current_belongs_to_l2_bucket
            = (curr_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS);

        // Check that all the path from current node to the bucketing data node is marked as L2 bucketed.
        const lpm_node* parent_node = curr->get_parent_node();
        const lpm_bucketing_data& parent_node_data = parent_node->data();
        if (current_belongs_to_l2_bucket) {
            if (curr_data.l2_bucket == nullptr) {
                if (parent_node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS) {
                    log_err(TABLES, "node=%s belongs to L2 bucket that doesn't end with bucketing_data", curr->to_string().c_str());
                    dassert_crit(false);
                    return false;
                }
            }
        }

        // Check that all the path from current node to the bucketing data node is marked as L1 bucketed.
        if (curr_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET) {
            if (curr_data.l1_bucket == nullptr) {
                if ((parent_node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS)
                    && (parent_node_data.bucketing_state != lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET)) {
                    log_err(TABLES, "node=%s belongs to L1 bucket that doesn't end with bucketing_data", curr->to_string().c_str());
                    dassert_crit(false);
                    return false;
                }
            }

            // Check that L1 bucketing data ends with L2 bucket
            vector_alloc<const lpm_node*> children;
            children.push_back(left_child);
            children.push_back(right_child);
            bool child_is_legal = false;
            for (const lpm_node* child : children) {
                if (!child) {
                    continue;
                }
                const lpm_bucketing_data& child_data = child->data();
                const lpm_bucketing_data& bd = child_data;
                if ((bd.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET)
                    || (bd.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS)) {
                    if (bd.l1_bucket == nullptr) {
                        child_is_legal = true;
                        break;
                    }
                }
            }
            if (!child_is_legal) {
                log_err(TABLES, "node=%s belongs to L1 bucket that doesn't start with bucketing_data", curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }
        }
    }

    return true;
}

bool
bucketing_tree::sanity_nodes() const
{
    lpm_bucket_index_set l1_buckets;
    lpm_bucket_index_set l2_buckets;
    std::vector<const lpm_node*> wave;
    wave.push_back(m_binary_lpm_tree.get_root());

    while (!wave.empty()) {
        const lpm_node* curr = wave.back();
        wave.pop_back();

        if (!curr) {
            continue;
        }

        const lpm_node* left_child = curr->get_left_child();
        const lpm_node* right_child = curr->get_right_child();
        wave.push_back(left_child);
        wave.push_back(right_child);

        if (curr == m_binary_lpm_tree.get_root()) {
            continue;
        }

        const lpm_bucketing_data& curr_data = curr->data();
        if (curr_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::UNBUCKETED) {
            log_err(TABLES, "node=%s is not bucketed", curr->to_string().c_str());
            dassert_crit(false);
            return false;
        }

        const auto& l2_bucket = curr_data.l2_bucket;
        const auto& l1_bucket = curr_data.l1_bucket;
        bool current_belongs_to_l2_bucket
            = (curr_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS);
        bool current_belongs_to_l1_bucket
            = ((curr_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS)
               || (curr_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET));

        const lpm_key_t& curr_key = curr->get_key();
        const lpm_node* curr_parent = curr->get_parent_node();
        const lpm_key_t& parent_key = curr_parent->get_key();
        if (l2_bucket != nullptr) {
            if (!current_belongs_to_l2_bucket) {
                log_err(
                    TABLES, "L2 bucket=%d bucketing data corrupted, node=%s", l2_bucket->get_sw_index(), curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }

            // Check that either this node or its parent belongs to L1 bucket
            const lpm_bucketing_data& parent_node_data = curr_parent->data();
            if (l1_bucket == nullptr) {
                bool current_parent_belongs_to_l1_bucket
                    = ((parent_node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS)
                       || (parent_node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_BUCKET));
                if (!current_parent_belongs_to_l1_bucket) {
                    dassert_crit(false);
                    return false;
                }
            }

            // Check that this bucket didn't appear on different node
            if (l2_buckets.count(l2_bucket->get_sw_index()) > 0) {
                log_err(TABLES, "L2 bucket=%d appears twice, node=%s", l2_bucket->get_sw_index(), curr->to_string().c_str());
                dassert_crit(false);
                return false;
            } else {
                l2_buckets.insert(l2_bucket->get_sw_index());
            }

            // Fail if this node is below top node
            if (l2_bucket->get_top_node()->get_width() < curr->get_width()) {
                log_err(TABLES,
                        "L2 bucket=%d top_node=%s above its bucketing_data node=%s",
                        l2_bucket->get_sw_index(),
                        l2_bucket->get_top_node()->to_string().c_str(),
                        curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }

            // Check this node is the last node before the root
            const lpm_key_t& l2_root = l2_bucket->get_root();
            if ((!(is_contained(l2_root, curr_key))) || is_contained(l2_root, parent_key)) {
                log_err(TABLES,
                        "L2 bucket=%d, root=%s is not between the node=%s and its parent",
                        l2_bucket->get_sw_index(),
                        l2_root.to_string().c_str(),
                        curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }

            // Check this L2 belongs to the correct L1 bucket
            const lpm_node* l1_bucket_node = curr;
            while (l1_bucket_node->data().l1_bucket == nullptr) {
                l1_bucket_node = l1_bucket_node->get_parent_node();
            }

            bool found = false;
            const lpm_bucketing_data& l1_bucket_node_data = l1_bucket_node->data();
            const auto& l1_bucket = l1_bucket_node_data.l1_bucket;
            for (const auto& l2_member : l1_bucket->get_members()) {
                if (l2_bucket == l2_member) {
                    found = true;
                    break;
                }
            }

            if (!found) {
                log_err(TABLES,
                        "node=%s, L2 bucket=%d is not a member of L1 bucket=%d",
                        curr->to_string().c_str(),
                        l2_bucket->get_sw_index(),
                        l1_bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }
        }

        if (l1_bucket != nullptr) {
            if (!current_belongs_to_l1_bucket) {
                log_err(
                    TABLES, "L1 bucket=%d bucketing data corrupted, node=%s", l1_bucket->get_sw_index(), curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }

            // Check this node is the last node before the root
            const lpm_key_t& l1_root = l1_bucket->get_root();
            if ((!(is_contained(l1_root, curr_key))) || is_contained(l1_root, parent_key)) {
                log_err(TABLES,
                        "L1 bucket=%d, root=%s is not between the node=%s and its parent",
                        l1_bucket->get_sw_index(),
                        l1_root.to_string().c_str(),
                        curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }

            // Check that this bucket didn't appear on different node
            if (l1_buckets.count(l1_bucket->get_sw_index()) > 0) {
                log_err(TABLES, "L1 bucket=%d appears twice, node=%s", l1_bucket->get_sw_index(), curr->to_string().c_str());
                dassert_crit(false);
                return false;
            } else {
                l1_buckets.insert(l1_bucket->get_sw_index());
            }
        }

        if (is_node_group_root(curr) && (!curr_data.is_user_prefix)) {
            lpm_payload_t expected_payload = get_node_ancestor_payload(curr);
            if (expected_payload != curr_data.payload) {
                log_err(TABLES, "Group_root=%s has wrong payload", curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }
        }

        if (!curr->is_valid()) {
            dassert_crit(!curr_data.is_user_prefix && !is_node_group_root(curr));
            if (curr_data.payload != INVALID_PAYLOAD) {
                log_err(TABLES, "Invalid node=%s has wrong payload", curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }
        } else {
            if (!(curr_data.is_user_prefix || is_node_group_root(curr))) {
                log_err(TABLES, "Valid node=%s is not user prefix or group node", curr->to_string().c_str());
                dassert_crit(false);
                return false;
            }
        }

        bool ok = true;
        dassert_crit(ok = ok && sanity_node_belong_to_bucket(curr));
        if (!ok) {
            dassert_crit(false);
            return false;
        }
    }

    // Make sure all non empty buckets are written in the tree
    for (const auto& bucket : m_sw_bucket_allocator_handler[(size_t)lpm_level_e::L2].bucket_vector) {
        if ((!bucket) || (bucket->empty())) {
            continue;
        }

        if (l2_buckets.count(bucket->get_sw_index()) == 0) {
            log_err(TABLES, "L2 bucket=%d is missing", bucket->get_sw_index());
            dassert_crit(false);
            return false;
        }
    }

    return true;
}

bool
bucketing_tree::sanity_node_belong_to_bucket(const lpm_node* node) const
{
    const lpm_bucketing_data& node_data = node->data();
    if (node->is_valid()) {
        bool belongs_to_l2_bucket
            = (node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS);
        if (!belongs_to_l2_bucket) {
            log_err(TABLES, "node=%s valid node must belong to a bucket", node->to_string().c_str());
            dassert_crit(false);
            return false;
        }

        bool is_group_root = is_node_group_root(node);
        if (is_group_root) {
            if (node_data.l2_bucket == nullptr) {
                log_err(TABLES, "node=%s Group root must start L2 bucket", node->to_string().c_str());
                dassert_crit(false);
                return false;
            }
            if (node_data.l1_bucket == nullptr) {
                log_err(TABLES, "node=%s Group root must start L1 bucket", node->to_string().c_str());
                dassert_crit(false);
                return false;
            }
        }

        // Check that this node belongs to the correct bucket
        const lpm_nodes_bucket* l2_bucket = get_l2_bucket(node);
        bool found = false;
        for (const auto member : l2_bucket->get_nodes()) {
            if (node == member) {
                found = true;
                break;
            }
        }

        if (!found) {
            log_err(TABLES,
                    "L2 bucket=%d, node=%s Node doesn't belong to the bucket",
                    l2_bucket->get_sw_index(),
                    node->to_string().c_str());
            dassert_crit(false);
            return false;
        }
    } else {
        // Check that there is valid node below that belongs to the bucket as bucket can't start with invalid node.
        if (node_data.bucketing_state == lpm_bucketing_data::node_bucketing_state::BELONGS_TO_L1_L2_BUCKETS) {
            const lpm_node* left_child = node->get_left_child();
            const lpm_node* right_child = node->get_right_child();
            bool left_belongs = does_node_belong_to_same_l2_bucket_as_its_parent(left_child);
            bool right_belongs = does_node_belong_to_same_l2_bucket_as_its_parent(right_child);
            if ((!left_belongs) && (!right_belongs)) {
                dassert_crit(false);
                return false;
            }
        }
    }
    return true;
}

bool
bucketing_tree::sanity_l1_buckets() const
{
    size_t l1_sw_buckets_used = 0;
    vector_alloc<size_t> buckets_per_core(m_num_of_cores, 0);
    for (const auto& bucket : m_sw_bucket_allocator_handler[(size_t)lpm_level_e::L1].bucket_vector) {
        if (!bucket) {
            continue;
        }
        bool empty = (bucket->empty());
        const auto& buckets_bucket = std::static_pointer_cast<const lpm_buckets_bucket>(bucket);
        if (empty) {
            // HW index
            if (bucket->get_hw_index() != LPM_NULL_INDEX) {
                log_err(TABLES, "L1 bucket=%d is empty and have HW index", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }
        } else {
            // Counting HW indexes to make sure there is no leak.
            l1_sw_buckets_used++;

            // Check that all L2 buckets are below the L1's root.
            const lpm_key_t& bucket_root = buckets_bucket->get_root();
            if (bucket_root.get_width() == 0) {
                log_err(TABLES, "L1 bucket=%d is not empty and doesn't have root", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }

            size_t core_id = buckets_bucket->get_core();
            if (core_id == CORE_ID_NONE) {
                log_err(TABLES, "L2 bucket=%d is not empty and isn't assigned to any core", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }

            buckets_per_core[core_id]++;

            bool has_zero_length_prefix = false;
            for (const auto& entry : bucket->get_entries()) {
                if (entry.key.get_width() == bucket_root.get_width()) {
                    has_zero_length_prefix = true;
                    break;
                }
            }

            if (!has_zero_length_prefix) {
                if (is_pacific_revision(m_ll_device)) {
                    const lpm_payload_t& expected_default_payload = get_l2_default_payload(bucket_root);
                    const lpm_payload_t& actual_default_payload = bucket->get_default_entry().payload;
                    if (expected_default_payload != actual_default_payload) {
                        log_err(TABLES, "L1 bucket=%d default mismatch", bucket->get_sw_index());
                        dassert_crit(false);
                        return false;
                    }
                } else {
                    const lpm_bucket* default_l2_bucket = get_l1_default_bucket(bucket_root);
                    if (!default_l2_bucket) {
                        log_err(TABLES, "L1 bucket=%d doesn't have L2 default bucket.", bucket->get_sw_index());
                        dassert_crit(false);
                        return false;
                    }
                    const lpm_bucket_index_t& expected_default_bucket_index = default_l2_bucket->get_hw_index();
                    const lpm_bucket_index_t& actual_default_bucket_index = bucket->get_default_entry().payload;
                    if (expected_default_bucket_index != actual_default_bucket_index) {
                        log_err(TABLES, "L1 bucket=%d default mismatch", bucket->get_sw_index());
                        dassert_crit(false);
                        return false;
                    }
                }
            }

            const lpm_bucket_ptr_list& l2_buckets = buckets_bucket->get_members();
            for (const auto& l2_bucket : l2_buckets) {
                if (!is_contained(bucket_root, l2_bucket->get_root())) {
                    log_err(TABLES,
                            "L1 bucket=%d root is shorter than L2 bucket=%d",
                            bucket->get_sw_index(),
                            l2_bucket->get_sw_index());
                    dassert_crit(false);
                    return false;
                }
            }
        }
    }

    size_t used_free_sw_indexes = m_tree_parameters[(size_t)lpm_level_e::L1].num_of_sw_buckets
                                  - m_sw_bucket_allocator_handler[(size_t)lpm_level_e::L1].free_indices.available();
    if (used_free_sw_indexes != l1_sw_buckets_used) {
        log_err(TABLES,
                "L1 SW bucket number mismatch. free_indices used=%lu, l1_sw_buckets_used=%lu\n",
                used_free_sw_indexes,
                l1_sw_buckets_used);
        dassert_crit(false);
        return false;
    }

    size_t usable_hw_buckets = (m_tree_parameters[(size_t)lpm_level_e::L1].buckets_per_sram_line == 1)
                                   ? m_tree_parameters[(size_t)lpm_level_e::L1].num_of_sram_buckets / 2
                                   : m_tree_parameters[(size_t)lpm_level_e::L1].num_of_sram_buckets;
    usable_hw_buckets -= m_tree_parameters[(size_t)lpm_level_e::L1].buckets_per_sram_line; // Remove line 0 which is TCAM catch-all.

    for (size_t core_id = 0; core_id < m_num_of_cores; core_id++) {
        size_t core_free_indexes = m_hw_index_allocators[core_id][LEVEL1].hw_index_allocator->get_number_of_free_indices();
        if (usable_hw_buckets != core_free_indexes + buckets_per_core[core_id]) {
            log_err(TABLES,
                    "core_id=%lu, L1 HW indexes buckets mismatch. Total buckets=%lu, core_free_indexes=%lu core_free_indexes=%lu",
                    core_id,
                    usable_hw_buckets,
                    core_free_indexes,
                    buckets_per_core[core_id]);
            dassert_crit(false);
            return false;
        }
    }

    return true;
}

bool
bucketing_tree::sanity_l2_buckets() const
{
    size_t l2_sw_buckets_used = 0;
    vector_alloc<size_t> sram_buckets_per_core(m_num_of_cores, 0);
    vector_alloc<size_t> hbm_buckets_per_core(m_num_of_cores, 0);
    for (const auto& bucket : m_sw_bucket_allocator_handler[(size_t)lpm_level_e::L2].bucket_vector) {
        if (!bucket) {
            continue;
        }
        const auto nodes_bucket = std::static_pointer_cast<const lpm_nodes_bucket>(bucket);
        bool empty = (nodes_bucket->empty());
        lpm_node* top_node = nodes_bucket->get_top_node();
        const lpm_key_t& top_node_key = top_node->get_key();
        if (empty) {
            // Top node
            if (top_node != nullptr) {
                log_err(TABLES, "L2 bucket=%d is empty and have top_node", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }

            // HW index
            if (nodes_bucket->get_hw_index() != LPM_NULL_INDEX) {
                log_err(TABLES, "L2 bucket=%d is empty and have HW index", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }
        } else {
            // Top node is not null and below root.
            if (top_node == nullptr) {
                log_err(TABLES, "L2 bucket=%d is not empty and doesn't have top_node", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }

            const lpm_key_t& bucket_root = nodes_bucket->get_root();
            if (top_node_key.get_width() < bucket_root.get_width()) {
                log_err(TABLES, "L2 bucket=%d top_node is below root", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }

            size_t core_id = nodes_bucket->get_core();
            if (core_id == CORE_ID_NONE) {
                log_err(TABLES, "L2 bucket=%d is not empty and isn't assigned to any core", bucket->get_sw_index());
                dassert_crit(false);
                return false;
            }

            // Counting HW indexes to make sure there is no leak.
            size_t hbm_address_offset = m_tree_parameters[LEVEL2].num_of_sram_buckets;
            if (is_location_in_hbm(lpm_level_e::L2, nodes_bucket->get_hw_index(), hbm_address_offset)) {
                hbm_buckets_per_core[core_id]++;
            } else {
                sram_buckets_per_core[core_id]++;
            }

            lpm_payload_t expected_default_payload = get_l2_default_payload(bucket_root);
            lpm_payload_t actual_default_payload = bucket->get_default_entry().payload;
            if (expected_default_payload != actual_default_payload) {
                bool has_zero_length_prefix = false;
                for (const auto& entry : bucket->get_entries()) {
                    if (entry.key.get_width() == bucket_root.get_width()) {
                        has_zero_length_prefix = true;
                        break;
                    }
                }

                if (!has_zero_length_prefix) {
                    log_err(TABLES, "L2 bucket=%d default mismatch", bucket->get_sw_index());
                    dassert_crit(false);
                    return false;
                }
            }

            // Check that all nodes are below top_node.
            for (const auto& node : nodes_bucket->get_nodes()) {
                const lpm_key_t& node_key = node->get_key();
                bool node_below_top = is_contained(top_node_key, node_key);
                if (!node_below_top) {
                    log_err(TABLES,
                            "L2 bucket=%d top_node=%s, node=%s node is not below top_node",
                            bucket->get_sw_index(),
                            top_node->to_string().c_str(),
                            node->to_string().c_str());
                    dassert_crit(false);
                    return false;
                }
            }

            l2_sw_buckets_used++;
        }
    }

    size_t used_free_sw_indexes = m_tree_parameters[(size_t)lpm_level_e::L2].num_of_sw_buckets
                                  - m_sw_bucket_allocator_handler[(size_t)lpm_level_e::L2].free_indices.available();
    if (used_free_sw_indexes != l2_sw_buckets_used) {
        log_err(TABLES,
                "L2 SW bucket number mismatch. free_indices used=%lu, l2_sw_buckets_used=%lu\n",
                used_free_sw_indexes,
                l2_sw_buckets_used);
        dassert_crit(false);
        return false;
    }

    // usable_sram_hw_buckets -= m_tree_parameters[(size_t)lpm_level_e::L2].buckets_per_sram_line; // Remove line 0 which is TCAM
    // catch-all.
    size_t usable_sram_hw_buckets = (m_tree_parameters[LEVEL2].buckets_per_sram_line == 1)
                                        ? m_tree_parameters[LEVEL2].num_of_sram_buckets / 2
                                        : m_tree_parameters[LEVEL2].num_of_sram_buckets;

    size_t usable_hbm_hw_buckets = m_tree_parameters[LEVEL2].num_of_hbm_buckets;
    size_t usable_hw_buckets = usable_sram_hw_buckets + usable_hbm_hw_buckets;

    for (size_t core_id = 0; core_id < m_num_of_cores; core_id++) {
        size_t core_total_free_indexes = m_hw_index_allocators[core_id][LEVEL2].hw_index_allocator->get_number_of_free_indices();
        size_t total_used_hw_index = sram_buckets_per_core[core_id] + hbm_buckets_per_core[core_id];
        if (usable_hw_buckets != total_used_hw_index + core_total_free_indexes) {
            log_err(TABLES,
                    "core_id=%lu, L2 HW indexes buckets mismatch. usable_hw_buckets=%lu, total_used_hw_index=%lu "
                    "core_total_free_indexes=%lu",
                    core_id,
                    usable_hw_buckets,
                    total_used_hw_index,
                    core_total_free_indexes);
            dassert_crit(false);
            return false;
        }
    }

    return true;
}

size_t
bucketing_tree::get_free_space_in_sram(size_t core_id) const
{
    const lpm_hw_index_allocator_adapter_hbm* l2_hbm_adapter
        = static_cast<const lpm_hw_index_allocator_adapter_hbm*>(m_hw_index_allocators[core_id][LEVEL2].hw_index_allocator.get());
    size_t free_space_in_sram = l2_hbm_adapter->get_number_of_free_indices_in_sram();
    return free_space_in_sram;
}

lpm_hbm_cache_manager&
bucketing_tree::get_hbm_cache_manager(size_t core_id)
{
    return m_hbm_cache_managers[core_id];
}

lpm_hw_index_allocator_adapter_sptr
bucketing_tree::get_hw_index_allocator(size_t core_id, lpm_level_e level) const
{
    if (core_id >= m_num_of_cores) {
        return nullptr;
    }

    size_t level_idx = static_cast<size_t>(level);
    return m_hw_index_allocators[core_id][level_idx].hw_index_allocator;
}

size_t
bucketing_tree::get_subtree_size(const json_t* root) const
{
    if (root == nullptr) {
        return 0;
    }

    json_t* json_size = json_object_get(root, TREE_SIZE_KEY);
    return json_integer_value(json_size);
}

json_t*
bucketing_tree::bucket_to_json(const lpm_bucket_scptr& bucket) const
{
    json_t* json_bucket = json_object();

    json_t* json_root = json_object();

    const lpm_key_t& root_key = bucket->get_root();
    json_object_set_new(json_root, KEY_VALUE_KEY, json_string(root_key.to_string().c_str()));
    json_object_set_new(json_root, KEY_WIDTH_KEY, json_integer(root_key.get_width()));

    json_object_set_new(json_bucket, ROOT_KEY, json_root);

    json_object_set_new(json_bucket, SW_INDEX_KEY, json_integer(bucket->get_sw_index()));
    json_object_set_new(json_bucket, HW_INDEX_KEY, json_integer(bucket->get_hw_index()));
    json_object_set_new(json_bucket, DEFAULT_PAYLOAD_KEY, json_integer(bucket->get_default_entry().payload));
    json_object_set_new(json_bucket, CORE_KEY, json_integer(bucket->get_core()));

    return json_bucket;
}

json_t*
bucketing_tree::buckets_to_json(lpm_level_e level) const
{
    lpm_bucket_const_ptr_vec buckets = get_buckets(level);
    json_t* json_repr = json_object();
    for (const auto& bucket : buckets) {
        json_t* json_bucket = bucket_to_json(bucket);

        // Adds the json_bucket to the json object representing the buckets
        char bucket_key[11]; // sw_index doesn't exceed 10^10
        sprintf(bucket_key, "%d", bucket->get_sw_index());
        json_object_set_new(json_repr, bucket_key, json_bucket);
    }
    return json_repr;
}

json_t*
bucketing_tree::subtree_to_json(const lpm_node* node) const
{
    if (node == nullptr) {
        return nullptr;
    }

    json_t* json_repr = json_object();

    const lpm_key_t& key = node->get_key();
    const lpm_bucketing_data& node_data = node->data();
    json_object_set_new(json_repr, KEY_VALUE_KEY, json_string(key.to_string().c_str()));
    json_object_set_new(json_repr, KEY_WIDTH_KEY, json_integer(key.get_width()));
    json_object_set_new(json_repr, IS_VALID_KEY, node_data.is_user_prefix ? json_true() : json_false());
    json_object_set_new(json_repr, PAYLOAD_KEY, json_integer(node_data.payload));

    // Writes the bucketing data
    json_t* json_bucketing_data = json_object();

    const auto& l2_bucket = node_data.l2_bucket;
    lpm_bucket_index_t l2_index = (l2_bucket != nullptr) ? l2_bucket->get_sw_index() : LPM_NULL_INDEX;
    json_object_set_new(json_bucketing_data, L2_SW_INDEX_KEY, json_integer(l2_index));

    const auto& l1_bucket = node_data.l1_bucket;
    lpm_bucket_index_t l1_index = (l1_bucket != nullptr) ? l1_bucket->get_sw_index() : LPM_NULL_INDEX;
    json_object_set_new(json_bucketing_data, L1_SW_INDEX_KEY, json_integer(l1_index));

    json_object_set_new(json_bucketing_data, GROUP_ID_KEY, json_integer(node_data.group));

    json_object_set_new(json_bucketing_data, BUCKETING_STATE_KEY, json_integer((size_t)node_data.bucketing_state));
    json_object_set_new(json_bucketing_data, IS_BALANCED_KEY, node_data.is_balanced ? json_true() : json_false());
    json_object_set_new(json_bucketing_data, IS_SRAM_ONLY_KEY, node_data.is_sram_only ? json_true() : json_false());
    json_object_set_new(json_repr, BUCKETING_DATA_KEY, json_bucketing_data);

    json_t* left = subtree_to_json(node->get_left_child());
    json_t* right = subtree_to_json(node->get_right_child());

    json_object_set_new(json_repr, LEFT_KEY, left);
    json_object_set_new(json_repr, RIGHT_KEY, right);

    // Calculates the tree_size
    size_t left_tree_size = get_subtree_size(left);
    size_t right_tree_size = get_subtree_size(right);
    size_t count_root = node_data.is_user_prefix ? 1 : 0;
    json_object_set_new(json_repr, TREE_SIZE_KEY, json_integer(left_tree_size + right_tree_size + count_root));

    return json_repr;
}

json_t*
bucketing_tree::tree_to_json() const
{
    json_t* json_repr = json_object();

    // Converting the nodes to JSON
    json_t* root = subtree_to_json(m_binary_lpm_tree.get_root());
    json_object_set_new(json_repr, ROOT_KEY, root);

    // Converting the buckets to JSON
    json_t* json_l1_buckets = buckets_to_json(lpm_level_e::L1);
    json_t* json_l2_buckets = buckets_to_json(lpm_level_e::L2);

    json_t* buckets = json_object();
    json_object_set_new(buckets, L1_BUCKETS_KEY, json_l1_buckets);
    json_object_set_new(buckets, L2_BUCKETS_KEY, json_l2_buckets);
    json_object_set_new(json_repr, BUCKETS_KEY, buckets);

    return json_repr;
}

json_t*
bucketing_tree::prefixes_statistics_to_json() const
{
    std::vector<size_t> unique_prefixes_per_length = get_unique_prefixes_per_length();
    json_t* json_unique_prefixes_per_length = json_object();
    for (size_t i = 0; i < unique_prefixes_per_length.size(); i++) {
        int num_unique_prefixes = unique_prefixes_per_length[i];
        char iChar[3]; // Max key length is 3 digits.
        sprintf(iChar, "%lu", i);
        json_object_set_new(json_unique_prefixes_per_length, iChar, json_integer(num_unique_prefixes));
        if (num_unique_prefixes == 0) {
            break;
        }
    }

    std::vector<size_t> num_entries_per_length = get_num_entries_per_length();
    json_t* json_length_of_prefixes = json_object();
    for (size_t i = 0; i < num_entries_per_length.size(); i++) {
        int num_entries = num_entries_per_length[i];
        if (num_entries == 0) {
            continue;
        }
        char iChar[3]; // Max key length is 3 digits.
        sprintf(iChar, "%lu", i);
        json_object_set_new(json_length_of_prefixes, iChar, json_integer(num_entries));
    }

    json_t* json_prefixes_statistics = json_object();
    json_object_set_new(json_prefixes_statistics, JSON_UNIQUE_PREFIXES_PER_LENGTH, json_unique_prefixes_per_length);
    json_object_set_new(json_prefixes_statistics, JSON_ENTRIES_PER_LENGTH, json_length_of_prefixes);
    return json_prefixes_statistics;
}

std::vector<size_t>
bucketing_tree::get_num_entries_per_length() const
{
    std::vector<size_t> num_entries_per_length;
    const lpm_node* current_node = m_binary_lpm_tree.get_root();
    std::vector<const lpm_node*> wave;
    wave.push_back(current_node);

    while (!wave.empty()) {
        const lpm_node* current_node = wave.back();
        size_t node_width = current_node->get_width();
        wave.pop_back();
        const lpm_bucketing_data& current_node_data = current_node->data();
        if (current_node_data.is_user_prefix) {
            if (node_width >= num_entries_per_length.size()) {
                num_entries_per_length.resize(node_width + 1);
            }

            num_entries_per_length[node_width]++;
        }

        const lpm_node* left_child = current_node->get_left_child();
        const lpm_node* right_child = current_node->get_right_child();
        for (const lpm_node* child : {left_child, right_child}) {
            if (child != nullptr) {
                wave.push_back(child);
            }
        }
    }

    return num_entries_per_length;
}

std::vector<size_t>
bucketing_tree::get_unique_prefixes_per_length() const
{
    std::vector<int> delta_vector;
    const lpm_node* current_node = m_binary_lpm_tree.get_root();
    std::vector<const lpm_node*> wave;
    wave.push_back(current_node);

    while (!wave.empty()) {
        const lpm_node* current_node = wave.back();
        size_t node_width = current_node->get_width();
        wave.pop_back();
        int current_node_impact = -1;

        const lpm_node* left_node = current_node->get_left_child();
        const lpm_node* right_node = current_node->get_right_child();
        for (const lpm_node* child : {left_node, right_node}) {
            if (child != nullptr) {
                current_node_impact++;
                wave.push_back(child);
            }
        }

        if (node_width + 1 >= delta_vector.size()) {
            delta_vector.resize(node_width + 2);
        }

        delta_vector[node_width + 1] += current_node_impact;
    }

    std::vector<size_t> unique_prefixes_per_length(delta_vector.size(), 0);
    unique_prefixes_per_length[0] = 1;
    for (size_t i = 1; i < delta_vector.size(); i++) {
        unique_prefixes_per_length[i] = delta_vector[i] + unique_prefixes_per_length[i - 1];
    }

    return unique_prefixes_per_length;
}

} // namespace silicon_one
