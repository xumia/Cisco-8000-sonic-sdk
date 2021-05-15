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

#include "common/file_utils.h"
#include "lpm/bucketing_tree.h"
#include "lpm/lpm_hw_index_allocator_adapter_hbm.h"
#include "test_lpm_types.h"
#include <jansson.h>

/*
    *The tests here are based on the test_data structures defined in lpm_types.
    *The tests flow is: set up a tree with a small amount of data, sanity test it,
    *and then perform functionallity tests on it.
    *Finally, TearDown removes all of the entries.
*/

using namespace silicon_one;

// LPM tree tester.
class LpmTreeTest : public testing::TestWithParam<bool>
{

public:
    static ll_device_sptr s_ll_device;                  // Low level device.
    static lpm_core_tcam_utils_scptr s_core_tcam_utils; // Core tcam utils.
    // Set up test case: load tree with entries.
    static void SetUpTestCase()
    {
        s_ll_device = ll_device::create(0, device_path.c_str());
        s_core_tcam_utils = create_core_tcam_utils(s_ll_device);
    }

    static void TearDownTestCase()
    {
        s_ll_device = nullptr;
    }

    void SetUp()
    {
        std::string filename = "test/hw_tables/lpm/inputs/bgptable.txt.gz";
        srand(random_seed);

        PRINTF("Random seed: %lu\n", random_seed);

        bool has_hbm = GetParam();
        PRINTF("HBM = %d\n", has_hbm);

        s_ll_device = ll_device::create(0, device_path.c_str());
        s_tree = std::make_shared<bucketing_tree>(s_ll_device,
                                                  num_of_cores,
                                                  distributor_size,
                                                  l2_double_bucket_size,
                                                  l2_max_bucket_size,
                                                  NUM_OF_L2_SRAM_BUCKETS,
                                                  has_hbm ? 8 * 1024 : 0 /* max_num_of_hbm_buckets */,
                                                  has_hbm ? 1 : 2 /* buckets per SRAM line */,
                                                  true /* double entries allowed */,
                                                  l1_double_bucket_size /* l1_double_bucket_size */,
                                                  l1_max_bucket_size /* l1_max_bucket_size */,
                                                  NUM_OF_L1_BUCKETS /* l1_max_num_of_sram_buckets */,
                                                  2 /* l1_buckets_per_sram_line */,
                                                  false /* l1_support_double_width_entries */,
                                                  max_bucket_depth,
                                                  1 /* tcam_single_width_key_weight */,
                                                  2 /* tcam_double_width_key_weight */,
                                                  4 /* tcam_quad_width_key_weight */,
                                                  trap_destination,
                                                  s_core_tcam_utils);

        create_tree_group_roots(s_tree, nullptr, s_group_roots_in_tree);

        s_generated_entries = (convert_api_to_imp_actions(read_entries(filename, 500, true /*v4 and v6*/)));
        ASSERT_FALSE(s_generated_entries.empty());
    }

    // Tear down test case: remove all the entries frome tree.
    void TearDown()
    {
        lpm_implementation_desc_vec actions;
        for (const auto& entry : s_entries_in_tree) {
            actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, entry.m_key, INVALID_PAYLOAD));
        }

        run_bulk_update(actions, false);

        lpm_implementation_desc_vec group_roots_actions;
        for (const auto& entry : s_group_roots_in_tree) {
            if (entry.m_key.get_width() == 1) {
                continue;
            }
            group_roots_actions.push_back(
                lpm_action_desc_internal(lpm_implementation_action_e::REMOVE_GROUP_ROOT, entry.m_key, INVALID_PAYLOAD));
        }

        run_bulk_update(group_roots_actions, false);

        lpm_action_statistics statistics = s_tree->get_total_action_distribution_stats();
        ASSERT_EQ(statistics.insertions, statistics.removals);

        s_tree.reset();
        s_ll_device.reset();
    }

protected:
    bool only_sram()
    {
        bool has_hbm = GetParam();
        return !has_hbm;
    }

    void compare_jsons(json_t* json_before, json_t* json_after)
    {
        constexpr const char* ROOT_KEY = "root";
        constexpr const char* BUCKETS_KEY = "buckets";
        constexpr const char* L1_BUCKETS_KEY = "l1_buckets";
        constexpr const char* L2_BUCKETS_KEY = "l2_buckets";

        json_t* root_before = json_object_get(json_before, ROOT_KEY);
        json_t* root_after = json_object_get(json_after, ROOT_KEY);
        bool is_root_equal = (json_equal(root_before, root_after));

        json_t* buckets_before = json_object_get(json_before, BUCKETS_KEY);
        json_t* buckets_after = json_object_get(json_after, BUCKETS_KEY);
        json_t* l1_buckets_before = json_object_get(buckets_before, L1_BUCKETS_KEY);
        json_t* l1_buckets_after = json_object_get(buckets_after, L1_BUCKETS_KEY);
        bool is_l1_equal = (json_equal(l1_buckets_before, l1_buckets_after));

        json_t* l2_buckets_before = json_object_get(buckets_before, L2_BUCKETS_KEY);
        json_t* l2_buckets_after = json_object_get(buckets_after, L2_BUCKETS_KEY);
        bool is_l2_equal = (json_equal(l2_buckets_before, l2_buckets_after));

        bool ok = is_root_equal && is_l1_equal && is_l2_equal;
        if (!ok) {
            file_utils::write_json_to_file(json_before, "before.json");
            file_utils::write_json_to_file(json_after, "after.json");
            run_tree_sanity();
        }
        ASSERT_TRUE(ok);
    }

    void perform_actions_with_withdraw(const lpm_implementation_desc_vec& actions)
    {
        json_t* json_before = s_tree->tree_to_json();
        const vector_alloc<size_t>& group_to_core_before = s_tree->get_group_to_core();

        size_t failed_core;
        lpm_implementation_desc_vec_levels_cores cores_actions_for_withdraw;
        s_tree->update(actions, cores_actions_for_withdraw, failed_core);
        s_tree->withdraw();

        json_t* json_after = s_tree->tree_to_json();
        const vector_alloc<size_t>& group_to_core_after = s_tree->get_group_to_core();

        compare_jsons(json_before, json_after);
        json_decref(json_before);
        json_decref(json_after);

        ASSERT_EQ(group_to_core_before, group_to_core_after);
    }

    void run_tree_sanity()
    {
        dassert::settings old_settings = dassert::instance().get_settings(dassert::level_e::SLOW);
        dassert::settings new_settings = {false /*skip*/, true /*terminate*/, true /* backtrace*/, false /*proc_maps*/};
        dassert::instance().set_settings(dassert::level_e::SLOW, new_settings);
        s_tree->sanity();
        dassert::instance().set_settings(dassert::level_e::SLOW, old_settings);
    }

    // Update and track changes in the tree, using the s_entries_in_tree set.
    la_status run_bulk_update(const lpm_implementation_desc_vec& actions, bool check_withdraw_flow)
    {
        // Checking withdraw flow
        if (check_withdraw_flow) {
            perform_actions_with_withdraw(actions);
        }

        // Performing the actual bulk
        size_t failed_core;
        lpm_implementation_desc_vec_levels_cores cores_actions;
        la_status status = s_tree->update(actions, cores_actions, failed_core);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }

        s_tree->commit();

        for (const auto& action : actions) {
            if (action.m_action == lpm_implementation_action_e::INSERT) {
                s_entries_in_tree.insert(action);
            }

            if (action.m_action == lpm_implementation_action_e::REMOVE) {
                s_entries_in_tree.erase(action);
            }

            if (action.m_action == lpm_implementation_action_e::MODIFY) {
                s_entries_in_tree.erase(action);
                s_entries_in_tree.insert(action);
            }
        }

        return LA_STATUS_SUCCESS;
    }

    // Update and track changes in the tree, using the s_entries_in_tree set.
    void run_bulk_with_error_update(const lpm_implementation_desc_vec& actions)
    {
        // Checking that we get back to the same state after error
        json_t* json_before = s_tree->tree_to_json();

        size_t failed_core;
        lpm_implementation_desc_vec_levels_cores cores_actions;
        la_status status = s_tree->update(actions, cores_actions, failed_core);
        ASSERT_NE(status, LA_STATUS_SUCCESS);

        json_t* json_after = s_tree->tree_to_json();
        compare_jsons(json_before, json_after);

        json_decref(json_after);
        json_decref(json_before);
    }

    // Update and track changes in the tree, using the s_entries_in_tree set.
    la_status run_one_by_one_update(const lpm_implementation_desc_vec& actions)
    {
        for (const auto& action : actions) {
            const lpm_implementation_desc_vec& current_actions{action};
            size_t failed_core;
            lpm_implementation_desc_vec_levels_cores cores_actions;
            la_status status = s_tree->update(current_actions, cores_actions, failed_core);
            if (status != LA_STATUS_SUCCESS) {
                return status;
            }
            s_tree->commit();

            if (action.m_action == lpm_implementation_action_e::INSERT) {
                s_entries_in_tree.insert(action);
            }

            if (action.m_action == lpm_implementation_action_e::REMOVE) {
                s_entries_in_tree.erase(action);
            }

            if (action.m_action == lpm_implementation_action_e::MODIFY) {
                s_entries_in_tree.erase(action);
                s_entries_in_tree.insert(action);
            }
        }

        return LA_STATUS_SUCCESS;
    }

    lpm_key_vec generate_random_keys_from_action_vector(size_t num_keys, lpm_implementation_desc_vec vector)
    {
        random_shuffle(vector.begin(), vector.end());
        lpm_key_vec res(num_keys);
        for (size_t i = 0; i < num_keys; i++) {
            res[i] = vector[i].m_key;
        }

        return res;
    }

    lpm_key_t get_key_between_keys(const lpm_key_t& key0, const lpm_key_t& key1, const lpm_key_t& key2)
    {
        bool all_keys_equal = ((key0 == key1) && (key1 == key2));
        dassert_crit(!all_keys_equal);

        const lpm_key_t& first_common = common_key(key0, key1);
        if (!is_contained(first_common, key2)) {
            return first_common;
        }

        const lpm_key_t& second_common = common_key(key1, key2);
        if (!is_contained(second_common, key0)) {
            return second_common;
        }

        const lpm_key_t& third_common = common_key(key0, key2);
        return third_common;
    }

    la_status add_group_root(const lpm_key_t& key, size_t group_id, size_t core_id, bool check_withdraw_flow)
    {
        lpm_action_desc_internal add_group_action
            = lpm_action_desc_internal(lpm_implementation_action_e::ADD_GROUP_ROOT, key, INVALID_PAYLOAD);
        add_group_action.m_group_id = group_id;
        add_group_action.m_core_id = core_id;
        lpm_implementation_desc_vec actions{add_group_action};

        // Checking withdraw flow
        if (check_withdraw_flow) {
            perform_actions_with_withdraw(actions);
        }

        size_t failed_core;
        lpm_implementation_desc_vec_levels_cores cores_actions;
        la_status status = s_tree->update(actions, cores_actions, failed_core);
        if (status != LA_STATUS_SUCCESS) {
            s_tree->withdraw();
            return status;
        }

        s_tree->commit();
        s_group_roots_in_tree.insert(add_group_action);
        return LA_STATUS_SUCCESS;
    }

    la_status remove_group_root(const lpm_key_t& key, bool check_withdraw_flow)
    {
        lpm_action_desc_internal remove_group_action
            = lpm_action_desc_internal(lpm_implementation_action_e::REMOVE_GROUP_ROOT, key, INVALID_PAYLOAD);
        lpm_implementation_desc_vec actions{remove_group_action};

        // Checking withdraw flow
        if (check_withdraw_flow) {
            perform_actions_with_withdraw(actions);
        }

        size_t failed_core;
        lpm_implementation_desc_vec_levels_cores cores_actions;
        la_status status = s_tree->update(actions, cores_actions, failed_core);
        if (status != LA_STATUS_SUCCESS) {
            s_tree->withdraw();
            return status;
        }

        s_tree->commit();
        s_group_roots_in_tree.erase(remove_group_action);
        return LA_STATUS_SUCCESS;
    }

    la_status modify_group_to_core(const lpm_key_t& key, size_t group_id, size_t core_id, bool check_withdraw_flow)
    {
        lpm_action_desc_internal modify_group_to_core_action
            = lpm_action_desc_internal(lpm_implementation_action_e::MODIFY_GROUP_TO_CORE, key, INVALID_PAYLOAD);
        modify_group_to_core_action.m_group_id = group_id;
        modify_group_to_core_action.m_core_id = core_id;
        lpm_implementation_desc_vec actions{modify_group_to_core_action};

        // Checking withdraw flow
        if (check_withdraw_flow) {
            perform_actions_with_withdraw(actions);
        }

        size_t failed_core;
        lpm_implementation_desc_vec_levels_cores cores_actions;
        la_status status = s_tree->update(actions, cores_actions, failed_core);
        if (status != LA_STATUS_SUCCESS) {
            s_tree->withdraw();
            return status;
        }

        s_tree->commit();
        s_group_roots_in_tree.erase(modify_group_to_core_action);
        s_group_roots_in_tree.insert(modify_group_to_core_action);
        return LA_STATUS_SUCCESS;
    }

    // For now, later on - use the find_node of the lpm::tree.
    const lpm_node* find_node_in_tree(const lpm_key_t& key) const
    {
        const lpm_node* current_node = s_tree->get_root_node();

        while (is_contained(current_node->get_key(), key)) {
            const lpm_key_t& current_node_key = current_node->get_key();
            size_t current_width = current_node_key.get_width();
            bool go_right = key.bit_from_msb(current_width);
            const lpm_node* left_child = current_node->get_left_child();
            const lpm_node* right_child = current_node->get_right_child();
            const lpm_node* next_node = go_right ? right_child : left_child;

            if (!next_node) {
                return current_node;
            }

            current_node = next_node;
        }

        const lpm_node* parent = current_node->get_parent_node();
        if (parent && parent->get_key() == key) {
            return parent;
        }

        return current_node;
    }

    lpm_key_t generate_new_key_inside_group(const lpm_key_t& group_root_key) const
    {
        const lpm_node* group_root_node = find_node_in_tree(group_root_key);

        std::vector<const lpm_node*> wave;
        wave.push_back(group_root_node);
        while (!wave.empty()) {
            const lpm_node* curr = wave.back();
            wave.pop_back();
            const lpm_key_t& curr_key = curr->get_key();
            if (!curr->is_valid()) {
                return curr_key;
            }

            const lpm_node* curr_left_child = curr->get_left_child();
            const lpm_node* curr_right_child = curr->get_right_child();
            for (const lpm_node* child : {curr_left_child, curr_right_child}) {
                if ((child == nullptr) || (curr->get_width() != (child->get_width() - 1))) {
                    lpm_key_t ret = (curr_key) << 1;
                    if (child == curr->get_right_child()) {
                        ret |= bit_vector(1);
                    }
                    return ret;
                }
                if (child->data().group == GROUP_ID_NONE) {
                    wave.push_back(child);
                }
            }
        }

        return lpm_key_t();
    }

    lpm_key_vec find_invalid_triangular()
    {
        // Find 3 keys which represent {node, node->get_left_child(), node->get_right_child()} such that (node->get_width() <
        // node->child - 1).
        const lpm_node* root = s_tree->get_root_node();

        std::vector<const lpm_node*> wave{root};

        const lpm_node* root_left_child = root->get_left_child();
        const lpm_node* root_right_child = root->get_right_child();
        wave.push_back(root_left_child);
        wave.push_back(root_right_child);
        while (!wave.empty()) {
            const lpm_node* curr = wave.back();
            wave.pop_back();

            if (curr == nullptr) {
                continue;
            }

            bool has_null_child = false;
            const lpm_node* curr_left_child = curr->get_left_child();
            const lpm_node* curr_right_child = curr->get_right_child();
            for (const lpm_node* child : {curr_left_child, curr_right_child}) {
                if (child != nullptr) {
                    wave.push_back(child);
                } else {
                    has_null_child = true;
                }
            }

            if ((!has_null_child) && (!curr->is_valid()) && (!curr_left_child->is_valid()) && (!curr_right_child->is_valid())
                && (curr->get_width() < curr_left_child->get_width() - 1)
                && (curr->get_width() < curr_right_child->get_width() - 1)) {
                const lpm_key_t& right_child_key = curr_right_child->get_key();
                const lpm_key_t& left_child_key = curr_left_child->get_key();
                const lpm_key_t& curr_key = curr->get_key();
                lpm_key_vec res = {left_child_key, right_child_key, curr_key};
                return res;
            }
        }

        return lpm_key_vec();
    }

    bool is_prefix_pinned(const lpm_key_t& key)
    {
        const lpm_node* node = find_node_in_tree(key);
        lpm_bucket* l2_bucket = s_tree->get_bucket(node, lpm_level_e::L2);
        lpm_bucket_index_t hw_index = l2_bucket->get_hw_index();
        lpm_hbm_cache_manager& cache_manager = s_tree->get_hbm_cache_manager(0 /* core_id */);
        bool is_evictable = cache_manager.get_is_evictable(hw_index);
        bool is_pinned = !is_evictable;
        return is_pinned;
    }

    lpm_key_vec randomize_unique_key_vec(size_t number_of_entries)
    {
        key_set_t unique_keys_set;
        while (unique_keys_set.size() < number_of_entries) {
            lpm_key_t unique_key = rand_key_not_null();
            unique_keys_set.insert(unique_key);
        }

        lpm_key_vec unique_keys_vec(unique_keys_set.begin(), unique_keys_set.end());
        return unique_keys_vec;
    }

    void validate_unique_prefixes_per_length(const lpm_implementation_desc_vec& actions, json_t* json_unique_prefixes_per_length)
    {
        ASSERT_EQ(json_integer_value(json_object_get(json_unique_prefixes_per_length, "0")), 1);
        ASSERT_EQ(json_integer_value(json_object_get(json_unique_prefixes_per_length, "1")), 2);
        size_t length_of_prefix = 2;
        size_t value = 0;
        do {
            key_set_t unique_prefixes_per_length;
            for (const auto& action : actions) {
                size_t width = action.m_key.get_width();
                if (length_of_prefix > width) {
                    continue;
                }

                lpm_key_t check = action.m_key.bits_from_msb(0, length_of_prefix);
                unique_prefixes_per_length.insert(check);
            }

            char iChar[3]; // Max key length is 3 digits.
            sprintf(iChar, "%lu", length_of_prefix++);
            value = json_integer_value(json_object_get(json_unique_prefixes_per_length, iChar));
            ASSERT_EQ(value, unique_prefixes_per_length.size());
        } while (value > 0);
    }

    void validate_length_of_prefixes(const lpm_implementation_desc_vec& actions, json_t* json_length_of_prefixes)
    {
        std::vector<size_t> length_of_prefixes;
        for (const auto& action : actions) {
            size_t width = action.m_key.get_width();
            if (length_of_prefixes.size() <= width) {
                length_of_prefixes.resize(width + 1);
            }

            length_of_prefixes[width]++;
        }

        for (size_t width = 0; width < length_of_prefixes.size(); width++) {
            char iChar[3]; // Max key length is 3 digits.
            sprintf(iChar, "%lu", width);
            json_t* json_value = json_object_get(json_length_of_prefixes, iChar);
            size_t check_length_value = json_integer_value(json_value);
            ASSERT_EQ(check_length_value, length_of_prefixes[width]);
        }
    }

    void validate_statistics_json_correctness(const lpm_implementation_desc_vec& actions, json_t* json_prefixes_statistics)
    {
        json_t* json_unique_prefixes_per_length
            = json_object_get(json_prefixes_statistics, bucketing_tree::JSON_UNIQUE_PREFIXES_PER_LENGTH);
        validate_unique_prefixes_per_length(actions, json_unique_prefixes_per_length);

        json_t* json_length_of_prefixes = json_object_get(json_prefixes_statistics, bucketing_tree::JSON_ENTRIES_PER_LENGTH);
        validate_length_of_prefixes(actions, json_length_of_prefixes);
    }

    static bucketing_tree_sptr s_tree;                         // LPM tree.
    static lpm_implementation_desc_vec s_l1_level_actions;     // Next level actions
    static lpm_implementation_desc_vec s_l2_level_actions;     // Next level actions
    static lpm_implementation_desc_vec s_generated_entries;    // Pool of entries;
    static lpm_action_desc_internal_set s_entries_in_tree;     // Set of entries in the tree.
    static lpm_action_desc_internal_set s_group_roots_in_tree; // Set of group roots in the tree.
};

ll_device_sptr LpmTreeTest::s_ll_device(nullptr);
lpm_core_tcam_utils_scptr LpmTreeTest::s_core_tcam_utils(nullptr);
bucketing_tree_sptr LpmTreeTest::s_tree;
lpm_implementation_desc_vec LpmTreeTest::s_generated_entries;
lpm_action_desc_internal_set LpmTreeTest::s_entries_in_tree;
lpm_action_desc_internal_set LpmTreeTest::s_group_roots_in_tree;

// ADD/REMOVE actions:
TEST_P(LpmTreeTest, BulkInsertRemove)
{
    run_bulk_update(s_generated_entries, true);
    run_tree_sanity();

    lpm_implementation_desc_vec remove_actions;
    for (const auto& entry : s_entries_in_tree) {
        remove_actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, entry.m_key, INVALID_PAYLOAD));
    }

    run_bulk_update(remove_actions, true);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, OneByOneInsertRemove)
{
    la_status status = run_one_by_one_update(s_generated_entries);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();

    lpm_implementation_desc_vec remove_actions;
    for (const auto& entry : s_entries_in_tree) {
        remove_actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, entry.m_key, INVALID_PAYLOAD));
    }

    status = run_one_by_one_update(remove_actions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, BulkInsertRemoveMultipleGroupsSameCore)
{
    size_t group_id = 100;
    size_t group_core = (*s_group_roots_in_tree.begin()).m_core_id;
    lpm_key_vec key_vec = generate_random_keys_from_action_vector(3, s_generated_entries);
    const lpm_key_t& key = get_key_between_keys(key_vec[0], key_vec[1], key_vec[2]);
    la_status status = add_group_root(key, group_id, group_core, false);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_bulk_update(s_generated_entries, true);
    run_tree_sanity();

    lpm_implementation_desc_vec remove_actions;
    for (const auto& entry : s_entries_in_tree) {
        remove_actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, entry.m_key, INVALID_PAYLOAD));
    }

    run_bulk_update(remove_actions, true);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, BulkInsertRemoveMultipleGroupsDifferentCore)
{
    size_t group_id = 79;
    size_t default_core = (*s_group_roots_in_tree.begin()).m_core_id;
    size_t group_core = (default_core + 5) % num_of_cores;

    lpm_key_vec key_vec = generate_random_keys_from_action_vector(3, s_generated_entries);
    const lpm_key_t& key = get_key_between_keys(key_vec[0], key_vec[1], key_vec[2]);
    la_status status = add_group_root(key, group_id, group_core, false);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_bulk_update(s_generated_entries, true);

    // Check the utilization of all the cores
    core_buckets_occupancy_vec tree_occ = s_tree->get_occupancy(lpm_level_e::L2);
    for (size_t core = 0; core < num_of_cores; core++) {
        if ((core == default_core) || (core == group_core)) {
            ASSERT_NE(tree_occ[core].sram_rows, static_cast<size_t>(0));
        } else {
            ASSERT_EQ(tree_occ[core].sram_rows, static_cast<size_t>(0));
        }
    }

    run_tree_sanity();

    lpm_implementation_desc_vec remove_actions;
    for (const auto& entry : s_entries_in_tree) {
        remove_actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, entry.m_key, INVALID_PAYLOAD));
    }

    run_bulk_update(remove_actions, true);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, BulkErrorSameCores)
{
    size_t total_num_prefixes = s_generated_entries.size();
    size_t first_half = total_num_prefixes / 2;
    lpm_implementation_desc_vec first_bulk(s_generated_entries.begin(), s_generated_entries.begin() + first_half);
    run_bulk_update(first_bulk, true);

    lpm_implementation_desc_vec insert_error_bulk(s_generated_entries.begin() + first_half, s_generated_entries.end());
    insert_error_bulk.push_back(s_generated_entries[0]);

    lpm_implementation_desc_vec remove_error_bulk;
    for (size_t action_idx = 0; action_idx < first_half; action_idx += 2) {
        remove_error_bulk.push_back(
            lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, s_generated_entries[action_idx].m_key, INVALID_PAYLOAD));
    }
    remove_error_bulk.push_back(remove_error_bulk[0]);

    for (const auto& action_vec : {insert_error_bulk, remove_error_bulk}) {
        run_bulk_with_error_update(action_vec);
    }
}

TEST_P(LpmTreeTest, BulkErrorDifferentCores)
{

    size_t total_num_prefixes = s_generated_entries.size();
    size_t first_half = total_num_prefixes / 2;
    lpm_implementation_desc_vec first_bulk(s_generated_entries.begin(), s_generated_entries.begin() + first_half);

    size_t group_id = 7;
    size_t group_core = ((*s_group_roots_in_tree.begin()).m_core_id + 2) % num_of_cores;
    lpm_key_vec key_vec = generate_random_keys_from_action_vector(3, first_bulk);
    const lpm_key_t& group_key = get_key_between_keys(key_vec[0], key_vec[1], key_vec[2]);
    la_status status = add_group_root(group_key, group_id, group_core, false);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_bulk_update(first_bulk, true);

    lpm_implementation_desc_vec insert_error_bulk(s_generated_entries.begin() + first_half, s_generated_entries.end());
    insert_error_bulk.push_back(s_generated_entries[0]);

    lpm_implementation_desc_vec remove_error_bulk;
    for (size_t action_idx = 0; action_idx < first_half; action_idx += 2) {
        remove_error_bulk.push_back(
            lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, s_generated_entries[action_idx].m_key, INVALID_PAYLOAD));
    }
    remove_error_bulk.push_back(remove_error_bulk[0]);

    json_t* json_before = s_tree->tree_to_json();

    for (const auto& action_vec : {insert_error_bulk, remove_error_bulk}) {
        // Checking that we get back to the same state after error
        size_t failed_core;
        lpm_implementation_desc_vec_levels_cores cores_actions;
        la_status status = s_tree->update(action_vec, cores_actions, failed_core);
        ASSERT_NE(status, LA_STATUS_SUCCESS);

        json_t* json_after = s_tree->tree_to_json();
        compare_jsons(json_before, json_after);
        json_decref(json_after);
    }

    json_decref(json_before);
}

TEST_P(LpmTreeTest, AddRemoveOnBulkGroupRoots)
{
    const lpm_action_desc_internal& default_group_root_action = *s_group_roots_in_tree.begin();

    lpm_key_vec key_vec = generate_random_keys_from_action_vector(3, s_generated_entries);
    const lpm_key_t& group_root_key = get_key_between_keys(key_vec[0], key_vec[1], key_vec[2]);

    size_t group_id = 100;
    size_t group_core = default_group_root_action.m_core_id + 1;
    la_status status = add_group_root(group_root_key, group_id, group_core, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();

    lpm_implementation_desc_vec insert_actions(s_generated_entries.begin(), s_generated_entries.end());
    insert_actions.push_back(
        lpm_action_desc_internal(lpm_implementation_action_e::INSERT, default_group_root_action.m_key, rand_payload_not_null()));
    insert_actions.push_back(
        lpm_action_desc_internal(lpm_implementation_action_e::INSERT, group_root_key, rand_payload_not_null()));

    // Check insert error flow
    json_t* insert_json_before = s_tree->tree_to_json();
    insert_actions.push_back(insert_actions[0]); // Same insert twice
    size_t failed_core;
    lpm_implementation_desc_vec_levels_cores cores_actions;
    status = s_tree->update(insert_actions, cores_actions, failed_core);
    ASSERT_NE(status, LA_STATUS_SUCCESS);
    json_t* insert_json_after = s_tree->tree_to_json();
    compare_jsons(insert_json_before, insert_json_after);
    json_decref(insert_json_after);
    json_decref(insert_json_before);
    insert_actions.pop_back();

    // Insert the bulk
    run_bulk_update(insert_actions, true);

    lpm_implementation_desc_vec remove_actions;
    for (const auto& insert_action : insert_actions) {
        remove_actions.push_back(
            lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, insert_action.m_key, INVALID_PAYLOAD));
    }

    // Check remove error flow
    json_t* remove_json_before = s_tree->tree_to_json();
    remove_actions.push_back(remove_actions[0]); // Same remove twice
    status = s_tree->update(remove_actions, cores_actions, failed_core);
    ASSERT_NE(status, LA_STATUS_SUCCESS);
    json_t* remove_json_after = s_tree->tree_to_json();
    compare_jsons(remove_json_before, remove_json_after);
    json_decref(remove_json_after);
    json_decref(remove_json_before);
    remove_actions.pop_back();

    // Remove the bulk
    run_bulk_update(remove_actions, true);
}

// ADD/REMOVE_GROUP_ROOT tests
TEST_P(LpmTreeTest, AddRemoveGroupRootOnInvalidNodesSameCore)
{
    run_bulk_update(s_generated_entries, false);

    size_t group_core = (*s_group_roots_in_tree.begin()).m_core_id;
    vector_alloc<size_t> group_ids{10, 15, 78};
    lpm_key_vec group_roots_keys = find_invalid_triangular();
    size_t num_groups = group_ids.size();

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = add_group_root(group_roots_keys[i], group_ids[i], group_core, true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = remove_group_root(group_roots_keys[num_groups - 1 - i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }
}

TEST_P(LpmTreeTest, AddRemoveGroupRootOnInvalidNodesDifferentCores)
{
    run_bulk_update(s_generated_entries, false);

    size_t group_core0 = ((*s_group_roots_in_tree.begin()).m_core_id + 1) % num_of_cores;
    size_t group_core1 = ((*s_group_roots_in_tree.begin()).m_core_id + 2) % num_of_cores;
    size_t group_core2 = ((*s_group_roots_in_tree.begin()).m_core_id + 3) % num_of_cores;

    vector_alloc<size_t> group_ids{10, 15, 78};
    vector_alloc<size_t> group_cores{group_core0, group_core1, group_core2};
    lpm_key_vec group_roots_keys = find_invalid_triangular();
    size_t num_groups = group_ids.size();

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = add_group_root(group_roots_keys[i], group_ids[i], group_cores[i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = remove_group_root(group_roots_keys[num_groups - 1 - i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }
}

TEST_P(LpmTreeTest, AddRemoveGroupRootOnValidNodesSameCore)
{
    run_bulk_update(s_generated_entries, false);

    size_t group_core = (*s_group_roots_in_tree.begin()).m_core_id;
    vector_alloc<size_t> group_ids{10, 15, 78};
    lpm_key_vec group_roots_keys = find_invalid_triangular();
    size_t num_groups = group_ids.size();

    lpm_implementation_desc_vec actions;
    for (const auto& key : group_roots_keys) {
        actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, rand_payload_not_null()));
    }
    run_bulk_update(actions, true);

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = add_group_root(group_roots_keys[i], group_ids[i], group_core, true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = remove_group_root(group_roots_keys[num_groups - 1 - i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }
}

TEST_P(LpmTreeTest, AddRemoveGroupRootOnValidNodesDifferentCores)
{
    run_bulk_update(s_generated_entries, false);

    size_t group_core0 = ((*s_group_roots_in_tree.begin()).m_core_id + 4) % num_of_cores;
    size_t group_core1 = ((*s_group_roots_in_tree.begin()).m_core_id + 5) % num_of_cores;
    size_t group_core2 = ((*s_group_roots_in_tree.begin()).m_core_id + 6) % num_of_cores;

    vector_alloc<size_t> group_ids{10, 15, 78};
    vector_alloc<size_t> group_cores{group_core0, group_core1, group_core2};
    lpm_key_vec group_roots_keys = find_invalid_triangular();
    size_t num_groups = group_ids.size();

    lpm_implementation_desc_vec actions;
    for (const auto& key : group_roots_keys) {
        actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, rand_payload_not_null()));
    }
    run_bulk_update(actions, false);

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = add_group_root(group_roots_keys[i], group_ids[i], group_cores[i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = remove_group_root(group_roots_keys[num_groups - 1 - i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }
}

TEST_P(LpmTreeTest, AddRemoveGroupRootOnNonExistingNodesDifferentCores)
{
    run_bulk_update(s_generated_entries, false);

    size_t group_core0 = ((*s_group_roots_in_tree.begin()).m_core_id + 1) % num_of_cores;
    size_t group_core1 = ((*s_group_roots_in_tree.begin()).m_core_id + 2) % num_of_cores;

    vector_alloc<size_t> group_ids{30, 31};
    vector_alloc<size_t> group_cores{group_core0, group_core1};
    lpm_key_vec triangular_keys = find_invalid_triangular();
    const lpm_key_t& parent_key = triangular_keys[2];
    lpm_key_t key_on_edge = parent_key << 1;
    lpm_key_t key_not_on_edge = parent_key << 2;
    if (is_contained(key_not_on_edge, triangular_keys[0])) {
        key_not_on_edge.set_bit(0, true);
    }

    size_t num_groups = group_ids.size();
    const lpm_key_vec group_roots_keys{key_on_edge, key_not_on_edge};

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = add_group_root(group_roots_keys[i], group_ids[i], group_cores[i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }

    for (size_t i = 0; i < num_groups; i++) {
        la_status status = remove_group_root(group_roots_keys[num_groups - 1 - i], true);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        run_tree_sanity();
    }
}

// MODIFY_GROUP_TO_CORE tests
TEST_P(LpmTreeTest, ModifyGroup2CoreEmptyGroup)
{
    run_bulk_update(s_generated_entries, false);

    const lpm_node* current_node = s_tree->get_root_node();
    while (current_node->get_left_child()) {
        current_node = current_node->get_left_child();
    }

    const lpm_key_t& current_node_key = current_node->get_key();
    const lpm_key_t empty_group_key = (current_node_key) << 1;
    size_t group_id = 30;
    size_t from_core = 4;
    la_status status = add_group_root(empty_group_key, group_id, from_core, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();

    size_t to_core = 7;
    status = modify_group_to_core(empty_group_key, group_id, to_core, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, ModifyGroup2CoreNonEmptyGroup)
{
    run_bulk_update(s_generated_entries, false);

    lpm_key_vec group_roots_keys = find_invalid_triangular();

    const lpm_key_t non_empty_group_key = group_roots_keys[0];
    size_t group_id = 40;
    size_t from_core = 5;
    la_status status = add_group_root(non_empty_group_key, group_id, from_core, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();

    size_t to_core = 6;
    status = modify_group_to_core(non_empty_group_key, group_id, to_core, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, ModifyGroup2CoreOnValidNode)
{
    run_bulk_update(s_generated_entries, false);

    lpm_key_vec group_roots_keys = find_invalid_triangular();

    const lpm_key_t group_key = group_roots_keys[0];
    lpm_action_desc_internal add_action(lpm_implementation_action_e::INSERT, group_key, rand_payload_not_null());
    lpm_implementation_desc_vec add_actions{add_action};

    la_status status = run_one_by_one_update(add_actions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();

    size_t group_id = 40;
    size_t from_core = 5;
    status = add_group_root(group_key, group_id, from_core, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();

    size_t to_core = 6;
    status = modify_group_to_core(group_key, group_id, to_core, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, ModifyGroupRootPayload)
{
    const lpm_key_t& key1 = lpm_key_t(0x1234, 16);
    bool is_tree_empty = s_tree->empty();
    ASSERT_TRUE(is_tree_empty);
    lpm_payload_t payload1 = 1;
    lpm_action_desc_internal add_action1(lpm_implementation_action_e::INSERT, key1, payload1);
    lpm_implementation_desc_vec add_actions1{add_action1};
    la_status status = run_one_by_one_update(add_actions1);

    size_t group_id = 50;
    size_t core_id = 3;
    const lpm_key_t& group_root_key = key1 << 5;
    status = add_group_root(group_root_key, group_id, core_id, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();

    const lpm_key_t& key2 = key1 << 2;
    lpm_payload_t payload2 = 2;
    lpm_action_desc_internal add_action2(lpm_implementation_action_e::INSERT, key2, payload2);
    lpm_implementation_desc_vec add_actions2{add_action2};
    status = run_bulk_update(add_actions2, true);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    run_tree_sanity();
}

TEST_P(LpmTreeTest, InsertRemoveBulkPinnedPrefix)
{
    if (only_sram()) {
        return;
    }

    const lpm_key_t& key = lpm_key_t(0xc0ffee, 24);
    lpm_action_desc_internal sram_pinned_prefix(lpm_implementation_action_e::INSERT, key, rand_payload_not_null());
    sram_pinned_prefix.m_sram_only = true;
    lpm_implementation_desc_vec insert_actions(s_generated_entries.begin(), s_generated_entries.end());
    insert_actions.push_back(sram_pinned_prefix);
    run_bulk_update(insert_actions, true);
    run_tree_sanity();

    bool is_sram_pinned = is_prefix_pinned(key);
    ASSERT_TRUE(is_sram_pinned);

    for (const auto& prefix : s_generated_entries) {
        bool is_sram_pinned = is_prefix_pinned(prefix.m_key);
        ASSERT_FALSE(is_sram_pinned);
    }

    lpm_implementation_desc_vec remove_actions;
    for (const auto& insert_action : insert_actions) {
        remove_actions.push_back(
            lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, insert_action.m_key, INVALID_PAYLOAD));
    }

    // Remove the bulk
    run_bulk_update(remove_actions, true);
}

// Get distribution and prefixes length of lpm entries:
TEST_P(LpmTreeTest, PrefixesStatistics)
{
    if (only_sram()) {
        return;
    }

    size_t number_of_entries = 1000;
    lpm_key_vec unique_keys_vec = randomize_unique_key_vec(number_of_entries);
    lpm_payload_t payload = 0;
    lpm_implementation_desc_vec actions;
    for (auto const& key : unique_keys_vec) {
        actions.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    run_bulk_update(actions, false);
    json_t* json_prefixes_statistics = s_tree->prefixes_statistics_to_json();
    validate_statistics_json_correctness(actions, json_prefixes_statistics);
}

TEST_P(LpmTreeTest, IsTreeEmpty)
{
    bool is_tree_empty = s_tree->empty();
    ASSERT_TRUE(is_tree_empty);
    size_t group_id = 100;
    size_t group_core = (*s_group_roots_in_tree.begin()).m_core_id;
    const lpm_key_t group_root_key = lpm_key_t(0b11000000, 8);
    add_group_root(group_root_key, group_id, group_core, false);
    is_tree_empty = s_tree->empty();
    ASSERT_TRUE(is_tree_empty);
    lpm_implementation_desc_vec_levels_cores out_actions_per_core;
    lpm_key_t key_to_insert = lpm_key_t(0b110000001111111111, 18);
    lpm_payload_t payload = 0;
    s_tree->insert(key_to_insert, payload, out_actions_per_core);
    is_tree_empty = s_tree->empty();
    ASSERT_FALSE(is_tree_empty);
    s_tree->remove(key_to_insert, out_actions_per_core);
    is_tree_empty = s_tree->empty();
    ASSERT_TRUE(is_tree_empty);
}

INSTANTIATE_TEST_CASE_P(WithHBM, LpmTreeTest, testing::Values(true));

INSTANTIATE_TEST_CASE_P(NoHBM, LpmTreeTest, testing::Values(false));
