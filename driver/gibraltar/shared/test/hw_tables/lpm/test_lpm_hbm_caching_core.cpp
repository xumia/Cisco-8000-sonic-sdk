// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "hw_tables/logical_lpm.h"
#include "lld/device_tree.h"
#include "lld/ll_device.h"
#include "test_lpm_read_entries.h"
#include "test_lpm_types.h"
#include <algorithm>
#include <cmath>
#include <locale>
#include <random>
#include <set>

using namespace silicon_one;

constexpr bool use_colors = true;
constexpr char RED_COLOR[] = "\033[0;31m";
constexpr char BLUE_COLOR[] = "\033[0;34m";
constexpr char YELLOW_COLOR[] = "\033[0;33m";
constexpr char RESET_COLOR[] = "\033[0m";
constexpr char CLEAR_SCREEN[] = "\033[2J\033[1;1H";

constexpr size_t CORE_ID = 6;
constexpr size_t L2_BUCKETS_PER_SRAM_ROW = 1;
constexpr size_t L2_DOUBLE_BUCKET_SIZE = 20 /* (#banks * 109 - (20*2 + 4 + 11*2))/38  - closest even number */;
constexpr size_t L2_MAX_BUCKET_SIZE = 17 /* interleaved + (total - shared)/2 */;
constexpr size_t L2_MAX_NUMBER_OF_SRAM_BUCKETS = 4096 /* 2048 * 2 buckets per line */;
constexpr size_t L2_MAX_NUMBER_OF_HBM_BUCKETS = 8 * 1024;
constexpr bool L2_ALLOW_DOUBLE_ENTRIES = false;
constexpr size_t L1_DOUBLE_BUCKET_SIZE = 8;
constexpr size_t L1_MAX_BUCKET_SIZE = 6;
constexpr size_t L1_MAX_NUMBER_OF_BUCKETS = 4 * 1024;
constexpr size_t L1_BUCKETS_PER_SRAM_ROW = 2;
constexpr bool L1_ALLOW_DOUBLE_ENTRIES = false;
constexpr size_t MAX_BUCKET_DEPTH = 16;
constexpr size_t TCAM_NUM_BANKSETS = 1;
constexpr size_t BANK_SIZE = 512;
constexpr size_t MAX_QUAD_ENTRIES = 240;
constexpr size_t TCAM_SINGLE_WIDTH_KEY_WEIGHT = 1;
constexpr size_t TCAM_DOUBLE_WIDTH_KEY_WEIGHT = 2;
constexpr size_t TCAM_QUAD_WIDTH_KEY_WEIGHT = 4;

static void
print_color(const char color[])
{
    if (!use_colors) {
        return;
    }
    printf("%s", color);
}

class LpmHbmCachingCoreTest : public ::testing::Test
{
protected:
    typedef std::set<lpm_key_t, key_less_operator> lpm_key_set_t;

    static constexpr size_t N_CORES = 16;
    static constexpr size_t VRF_LEN = 11;
    static constexpr size_t IPV4_IP_LEN = 32;
    static constexpr size_t IPV6_IP_LEN = 128;

    bool verbose = false;
    bool show_progress = false;
    bool animated_progress = true;

    static void SetUpTestCase()
    {
        s_ll_device = ll_device::create(0, device_path.c_str());
        printf("CSV:filename, stat polling interval [usec], caching interval [usec], caching threshold, eviction threshold, "
               "cooling interval [usec], total number of prefixes, total number of buckets, inital hot prefixes, initial hot "
               "prefixes in SRAM, initial "
               "hot prefixes in HBM, initial hot buckets, initial hot buckets in SRAM, initial hot buckets in HBM, hot prefixes "
               "fraction, hot traffic "
               "fractions, hot prefixes in HBM in the end, hot buckets in HBM in the end, percent of hot prefixes in "
               "HBM in the end, percent of hot buckets in HBM in the end, convergence time[usec], convergence half time[usec]\n");
        s_core_tcam_utils = create_core_tcam_utils(s_ll_device);
    }

    static void TearDownTestCase()
    {
        s_ll_device.reset();
    }

    void SetUp()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::ERROR;
        logger::instance().set_logging_level(0, silicon_one::la_logger_component_e::TABLES, logger_level);

        s_tree = std::make_shared<bucketing_tree>(s_ll_device,
                                                  num_of_cores,
                                                  distributor_size,
                                                  L2_DOUBLE_BUCKET_SIZE,
                                                  L2_MAX_BUCKET_SIZE,
                                                  L2_MAX_NUMBER_OF_SRAM_BUCKETS,
                                                  L2_MAX_NUMBER_OF_HBM_BUCKETS,
                                                  L2_BUCKETS_PER_SRAM_ROW,
                                                  L2_ALLOW_DOUBLE_ENTRIES,
                                                  L1_DOUBLE_BUCKET_SIZE,
                                                  L1_MAX_BUCKET_SIZE,
                                                  L1_MAX_NUMBER_OF_BUCKETS,
                                                  L1_BUCKETS_PER_SRAM_ROW,
                                                  L1_ALLOW_DOUBLE_ENTRIES,
                                                  MAX_BUCKET_DEPTH,
                                                  TCAM_SINGLE_WIDTH_KEY_WEIGHT,
                                                  TCAM_DOUBLE_WIDTH_KEY_WEIGHT,
                                                  TCAM_QUAD_WIDTH_KEY_WEIGHT,
                                                  trap_destination,
                                                  s_core_tcam_utils);

        s_core = std::make_shared<lpm_core>(s_ll_device,
                                            CORE_ID,
                                            s_tree,
                                            L2_DOUBLE_BUCKET_SIZE,
                                            L2_MAX_NUMBER_OF_SRAM_BUCKETS,
                                            TCAM_NUM_BANKSETS,
                                            BANK_SIZE,
                                            MAX_QUAD_ENTRIES,
                                            trap_destination,
                                            s_core_tcam_utils);

        lpm_action_desc_internal_set group_roots;
        create_tree_group_roots(s_tree, s_core, group_roots);

        s_cache_manager = &s_core->get_hbm_cache_manager();
        s_cache_manager->toggle_simulated_time_mode(true);
        setlocale(LC_NUMERIC, "");
    }

    void TearDown()
    {
        s_core.reset();
        s_tree.reset();

        s_cache_manager = nullptr;
        s_entries.clear();
    }

    static ll_device_sptr s_ll_device;                  // Low level device.
    static lpm_core_tcam_utils_scptr s_core_tcam_utils; // Core TCAM utils.
    lpm_core_sptr s_core;                               // Logical LPM.
    bucketing_tree_sptr s_tree;                         // LPM Tree.
    lpm_hbm_cache_manager* s_cache_manager;             // LPM HBM Cache manager.
    test_data_lpm_entries_set_t s_entries;              // Entries set to track the entries in core.
    size_t simulated_time_usec = 0;                     // Simulated time.

    void loadEntriesFromFile(const std::string filename,
                             size_t max_entries,
                             bool fail_on_error,
                             size_t iterations_to_cool_down,
                             lpm_key_set_t& out_keys_in_system)
    {
        lpm_read_entries r(true /*v4 and v6*/);
        lpm_read_entries::lpm_test_action_desc_vec_t test_actions = r.read_extended_raw_entries(filename, max_entries, false);

        ASSERT_FALSE(test_actions.empty()) << "Empty actions";

        if (shuffle_entries) {
            std::default_random_engine re{random_seed};
            std::shuffle(test_actions.begin(), test_actions.end(), re);
        }

        lpm_hbm_cache_manager::lpm_hbm_caching_params params = s_cache_manager->get_caching_params();

        size_t iteration = 0;
        size_t insertions = 0;
        size_t removes = 0;
        size_t modifies = 0;
        size_t errors = 0;
        size_t skipped = 0;
        printf("\n");
        for (auto& action : test_actions) {
            iteration++;

            if ((iterations_to_cool_down != 0) && (iteration % iterations_to_cool_down == 0)) {
                s_cache_manager->cool_down_buckets(params.usecs_until_hotness_decrease);
            }
            /* 128 IPv6 entries don't go to LPM, but to EM */
            if (action.is_update && (action.update_desc.m_key.get_width() == IPV6_IP_LEN + VRF_LEN + 1)) {
                skipped++;
                continue;
            }

            lpm_implementation_desc_vec_levels_cores cores_actions;
            la_status status;
            if (action.is_update && (action.update_desc.m_action == lpm_action_e::INSERT)) {
                status = s_tree->insert(action.update_desc.m_key, action.update_desc.m_payload, cores_actions);
                if (status == LA_STATUS_SUCCESS) {
                    out_keys_in_system.insert(action.update_desc.m_key);
                    insertions++;
                }
            } else if (action.is_update && (action.update_desc.m_action == lpm_action_e::REMOVE)) {
                status = s_tree->remove(action.update_desc.m_key, cores_actions);
                if (status != LA_STATUS_SUCCESS) {
                    out_keys_in_system.erase(action.update_desc.m_key);
                    removes++;
                }
            } else if (action.is_update && (action.update_desc.m_action == lpm_action_e::MODIFY)) {
                status = s_tree->modify(action.update_desc.m_key, action.update_desc.m_payload, cores_actions);
            } else {
                ASSERT_FALSE(false) << "Wrong action";
            }

            if (status == LA_STATUS_SUCCESS) {
                status = s_core->update_tcam(cores_actions[CORE_ID][LEVEL1]);
                if (status != LA_STATUS_SUCCESS) {
                    s_tree->withdraw();
                    if (action.update_desc.m_action == lpm_action_e::INSERT) {
                        out_keys_in_system.erase(action.update_desc.m_key);
                        insertions--;
                    } else if (action.update_desc.m_action == lpm_action_e::REMOVE) {
                        out_keys_in_system.insert(action.update_desc.m_key);
                        removes--;
                    }
                }

                // Success
                s_tree->commit();
                status = s_core->commit_hw_updates(cores_actions[CORE_ID]);
                ASSERT_EQ(LA_STATUS_SUCCESS, status);

            } else {
                if (verbose) {
                    print_core_stats();
                    printf("iteration=%zu / %zu   inserted %zu  removed %zu  modified %zu  skipped %zu  errors %zu  current %zu\n",
                           iteration,
                           test_actions.size(),
                           insertions,
                           removes,
                           modifies,
                           skipped,
                           errors,
                           insertions - removes);
                }

                ASSERT_TRUE(fail_on_error) << "Failed at iteration %zu\n" << iteration;
                s_tree->withdraw();
                errors++;
            }

            if (show_progress && ((iteration % 1000) == 0)) {
                std::cout << "\r";
                print_core_stats();
                printf("iteration=%zu / %zu   inserted %zu  removed %zu  modified %zu  skipped %zu  errors %zu  current %zu\n",
                       iteration,
                       test_actions.size(),
                       insertions,
                       removes,
                       modifies,
                       skipped,
                       errors,
                       insertions - removes);
                std::cout.flush();
            }
        }

        std::cout << "\n";
        printf("inserted %zu entries to LPM\n", insertions);
        printf("removed %zu entries to LPM\n", removes);
        printf("modified %zu entries to LPM\n", modifies);
        printf("errors %zu\n", errors);
        printf("skipped %zu entries\n", skipped);
        printf("currently has %zu entries\n", insertions - removes);
    }

    void print_core_stats() const
    {
        const auto& l2_stats = s_tree->get_occupancy(lpm_level_e::L2);
        const auto& l2_stats_core = l2_stats[CORE_ID];
        printf("L2 entries = %9lu | L2 entries SRAM = %9lu | L2 entries HBM = %9lu\n",
               l2_stats_core.sram_single_entries + l2_stats_core.hbm_entries,
               l2_stats_core.sram_single_entries,
               l2_stats_core.hbm_entries);
    }

    lpm_key_set_t convert_prefixes_to_full_keys(lpm_key_set_t& prefixes)
    {
        lpm_key_set_t full_keys;
        for (const auto& key : prefixes) {
            size_t full_width;
            bool is_ipv6 = key.bit_from_msb(0);
            if (is_ipv6) {
                full_width = 1 + VRF_LEN + IPV6_IP_LEN;
            } else {
                full_width = 1 + VRF_LEN + IPV4_IP_LEN;
            }
            lpm_key_t full_key(0, full_width);
            full_key.set_bits_from_msb(0, key.get_width(), key);
            full_keys.insert(full_key);
        }
        return full_keys;
    }

    void separate_keys_into_hot_and_cold(lpm_key_set_t& full_keys,
                                         double hot_prefixes_frac,
                                         std::mt19937& rand_engine,
                                         std::vector<lpm_key_t>& hot_prefixes,
                                         std::vector<lpm_key_t>& cold_prefixes)
    {
        std::vector<lpm_key_t> full_keys_vector;
        for (const auto& key : full_keys) {
            full_keys_vector.push_back(key);
        }

        std::shuffle(full_keys_vector.begin(), full_keys_vector.end(), rand_engine);

        size_t n_hot = static_cast<size_t>(std::round(hot_prefixes_frac * full_keys_vector.size()));
        for (size_t i = 0; i < full_keys_vector.size(); i++) {
            if (i < n_hot) {
                hot_prefixes.push_back(full_keys_vector[i]);
            } else {
                cold_prefixes.push_back(full_keys_vector[i]);
            }
        }
    }

    size_t key_to_bucket_idx(const bucketing_tree_scptr& tree, const lpm_key_t& key)
    {
        const lpm_node* node = tree->find_node(key);
        dassert_crit(node);

        while (node->data().bucketing_state == lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG) {
            node = node->get_parent_node();
        }

        lpm_bucket* bucket = tree->get_bucket(node, lpm_level_e::L2);

        lpm_bucket_index_t hw_index = bucket->get_hw_index();
        return hw_index;
    }

    void get_buckets_of_prefixes(std::vector<lpm_key_t>& prefixes,
                                 const bucketing_tree_scptr& tree,
                                 std::vector<size_t>& out_sram_buckets,
                                 std::vector<size_t>& out_hbm_buckets)
    {
        std::vector<size_t> buckets;
        for (const auto& prefix : prefixes) {
            size_t bucket_index = key_to_bucket_idx(tree, prefix);
            bool is_bucket_in_hbm = (bucket_index >= 4096);
            if (is_bucket_in_hbm) {
                out_hbm_buckets.push_back(bucket_index);
            } else {
                out_sram_buckets.push_back(bucket_index);
            }
        }
    }

    size_t sample_a_key_and_get_its_bucket(std::vector<size_t>& hot_buckets,
                                           std::vector<size_t>& cold_buckets,
                                           std::mt19937& rand_engine,
                                           const bucketing_tree_scptr& tree,
                                           double hot_traffic_frac,
                                           double garbage_bucket_probability)
    {
        std::uniform_real_distribution<double> cold_hot_dist(0, 1);
        bool is_hot = cold_hot_dist(rand_engine) < hot_traffic_frac;
        const std::vector<size_t>& buckets = is_hot ? hot_buckets : cold_buckets;

        std::uniform_real_distribution<double> sample_garbage_bucket_dist(0, 1);
        bool do_sample_garbage_bucket
            = (buckets.size() == 0) || (sample_garbage_bucket_dist(rand_engine) < garbage_bucket_probability);

        if (do_sample_garbage_bucket) {
            std::uniform_int_distribution<size_t> buckets_dist(0, 1 << 20);
            size_t selected_garbage_bucket = buckets_dist(rand_engine);
            return selected_garbage_bucket;
        }

        dassert_crit(buckets.size() > 0);

        std::uniform_int_distribution<size_t> buckets_dist(0, buckets.size() - 1);
        size_t selected_bucket = buckets_dist(rand_engine);
        return buckets[selected_bucket];
    }

    void print_histograms(lpm_hbm_cache_manager* s_cache_manager)
    {
        lpm_hbm_cache_manager::lpm_hbm_caching_stats stats = s_cache_manager->get_statistics(false /* reset counters */);
        lpm_hbm_cache_manager::lpm_hbm_caching_params params = s_cache_manager->get_caching_params();

        size_t total_buckets = stats.sram_num_buckets + stats.hbm_num_buckets;

        printf("Hotness Histogram. SRAM = %zu  HBM = %zu  Total Buckets = %zu\n",
               stats.sram_num_buckets,
               stats.hbm_num_buckets,
               total_buckets);

        if (total_buckets == 0) {
            return;
        }

        for (size_t hotness = 0; hotness < lpm_hbm_cache_manager::NUM_HOTNESS_LEVELS; hotness++) {
            size_t percent_sram = std::ceil((double)stats.sram_hotness_histogram[hotness] / total_buckets * 100);
            size_t percent_hbm = std::ceil((double)stats.hbm_hotness_histogram[hotness] / total_buckets * 100);
            if (percent_sram + percent_hbm > 0) {
                if (hotness >= params.hotness_threshold_to_cache) {
                    print_color(RED_COLOR);
                } else if (hotness < params.hotness_threshold_to_evict) {
                    print_color(BLUE_COLOR);
                } else {
                    print_color(YELLOW_COLOR);
                }

                printf("%-4zu", hotness);
                print_color(RESET_COLOR);
                printf(":    ");

                print_color(BLUE_COLOR);
                for (size_t p = 0; p < percent_hbm; p++) {
                    printf("|");
                }
                print_color(RESET_COLOR);

                print_color(RED_COLOR);
                for (size_t p = 0; p < percent_sram; p++) {
                    printf("|");
                }
                print_color(RESET_COLOR);
                printf("\n");
            }
        }
        printf("\n\n");
    }

    void get_hot_prefixes_stats(lpm_hbm_cache_manager* s_cache_manager,
                                const bucketing_tree_scptr& tree,
                                std::vector<lpm_key_t>& hot_prefixes,
                                size_t& num_prefixes_in_sram,
                                size_t& num_prefixes_in_hbm,
                                size_t& num_buckets_in_sram,
                                size_t& num_buckets_in_hbm)
    {
        static constexpr size_t HBM_BUCKET_OFFSET = 4096;

        num_prefixes_in_sram = 0;
        num_prefixes_in_hbm = 0;
        num_buckets_in_sram = 0;
        num_buckets_in_hbm = 0;

        std::set<size_t> buckets_in_sram;
        std::set<size_t> buckets_in_hbm;

        for (const auto& prefix : hot_prefixes) {
            size_t bucket_index = key_to_bucket_idx(tree, prefix);
            if (bucket_index < HBM_BUCKET_OFFSET) {
                num_prefixes_in_sram++;
                buckets_in_sram.insert(bucket_index);
            } else {
                num_prefixes_in_hbm++;
                buckets_in_hbm.insert(bucket_index);
            }
        }

        num_buckets_in_sram = buckets_in_sram.size();
        num_buckets_in_hbm = buckets_in_hbm.size();
    }

    void print_hot_bucket_location(size_t prefixes_in_sram, size_t prefixes_in_hbm, size_t buckets_in_sram, size_t buckets_in_hbm)
    {
        size_t total_prefixes = prefixes_in_sram + prefixes_in_hbm;
        size_t percent_prefixes_hbm = std::ceil(static_cast<double>(prefixes_in_hbm) / total_prefixes * 100);
        size_t percent_prefixes_sram = 100 - percent_prefixes_hbm;

        printf("Hot prefixes (%-7zu SRAM | %-7zu HBM): ", prefixes_in_sram, prefixes_in_hbm);

        print_color(RED_COLOR);
        for (size_t p = 0; p < percent_prefixes_sram; p++) {
            printf("|");
        }
        print_color(RESET_COLOR);

        print_color(BLUE_COLOR);
        for (size_t p = 0; p < percent_prefixes_hbm; p++) {
            printf("|");
        }
        print_color(RESET_COLOR);

        printf("\n");

        size_t total_buckets = buckets_in_sram + buckets_in_hbm;
        size_t percent_buckets_sram = std::ceil(static_cast<double>(buckets_in_sram) / total_buckets * 100);
        size_t percent_buckets_hbm = 100 - percent_buckets_sram;

        printf("Hot buckets  (%-7zu SRAM | %-7zu HBM): ", buckets_in_sram, buckets_in_hbm);

        print_color(RED_COLOR);
        for (size_t p = 0; p < percent_buckets_sram; p++) {
            printf("|");
        }
        print_color(RESET_COLOR);

        print_color(BLUE_COLOR);
        for (size_t p = 0; p < percent_buckets_hbm; p++) {
            printf("|");
        }

        print_color(RESET_COLOR);

        printf("\n");
    }

    void testWithEntriesFromFile(const std::string filename,
                                 lpm_key_set_t& keys_in_system,
                                 double hot_prefixes_frac,
                                 double hot_traffic_frac,
                                 size_t usecs_to_run,
                                 size_t usecs_to_check_progress,
                                 size_t usecs_polling,
                                 size_t usecs_caching,
                                 size_t hotness_threshold_to_cache,
                                 size_t hotness_threshold_to_evict,
                                 size_t usecs_until_hotness_decrease,
                                 size_t max_hotness_level,
                                 double garbage_bucket_probability)
    {
        lpm_key_set_t full_keys = convert_prefixes_to_full_keys(keys_in_system);

        std::set<size_t> buckets;
        for (const auto& key : full_keys) {
            size_t bucket_index = key_to_bucket_idx(s_tree, key);
            buckets.insert(bucket_index);
        }
        size_t num_buckets = buckets.size();

        std::mt19937 gen{random_seed};

        std::vector<lpm_key_t> hot_prefixes;
        std::vector<lpm_key_t> cold_prefixes;
        separate_keys_into_hot_and_cold(full_keys, hot_prefixes_frac, gen, hot_prefixes, cold_prefixes);

        size_t time_start = simulated_time_usec;
        size_t time_last_poll = simulated_time_usec;
        size_t time_last_cache = simulated_time_usec;
        size_t time_last_cooling = simulated_time_usec;

        lpm_hbm_cache_manager::lpm_hbm_caching_params caching_params = s_cache_manager->get_caching_params();
        caching_params.hotness_threshold_to_cache = hotness_threshold_to_cache;
        caching_params.hotness_threshold_to_evict = hotness_threshold_to_evict;
        caching_params.usecs_until_hotness_decrease = usecs_until_hotness_decrease;
        caching_params.max_hotness_level = max_hotness_level;
        s_cache_manager->set_caching_params(caching_params);

        size_t sram_bucket_idx = 0;
        size_t hbm_bucket_idx[4] = {0};

        std::uniform_int_distribution<int> cores_dist(0, N_CORES - 1);

        size_t convergence_time = static_cast<size_t>(-1);
        size_t convergence_half_time = static_cast<size_t>(-1);

        size_t initial_num_hot_prefixes_in_sram;
        size_t initial_num_hot_prefixes_in_hbm;
        size_t initial_num_hot_buckets_in_sram;
        size_t initial_num_hot_buckets_in_hbm;
        get_hot_prefixes_stats(s_cache_manager,
                               s_tree,
                               hot_prefixes,
                               initial_num_hot_prefixes_in_sram,
                               initial_num_hot_prefixes_in_hbm,
                               initial_num_hot_buckets_in_sram,
                               initial_num_hot_buckets_in_hbm);

        std::vector<size_t> hot_sram_buckets;
        std::vector<size_t> hot_hbm_buckets;
        std::vector<size_t> cold_sram_buckets;
        std::vector<size_t> cold_hbm_buckets;

        get_buckets_of_prefixes(hot_prefixes, s_tree, hot_sram_buckets, hot_hbm_buckets);
        get_buckets_of_prefixes(cold_prefixes, s_tree, cold_sram_buckets, cold_hbm_buckets);

        while (1) {
            size_t usecs_runtime = simulated_time_usec - time_start;
            if (usecs_runtime > usecs_to_run) {
                break;
            }

            size_t usecs_since_last_poll = simulated_time_usec - time_last_poll;
            if (usecs_since_last_poll > usecs_polling) {
                sram_bucket_idx = sample_a_key_and_get_its_bucket(
                    hot_sram_buckets, cold_sram_buckets, gen, s_tree, hot_traffic_frac, garbage_bucket_probability);

                s_core->notify_l2_bucket_accessed(sram_bucket_idx);
                s_core->notify_l2_bucket_accessed(sram_bucket_idx ^ 1);

                for (size_t hbm_reg = 0; hbm_reg < 4; hbm_reg++) {
                    bool do_sample_from_hbm = (cores_dist(gen) == 0);
                    if (do_sample_from_hbm) {
                        hbm_bucket_idx[hbm_reg] = sample_a_key_and_get_its_bucket(
                            hot_hbm_buckets, cold_hbm_buckets, gen, s_tree, hot_traffic_frac, garbage_bucket_probability);

                        if (hbm_bucket_idx[hbm_reg] >= 4096) {
                            s_core->notify_l2_bucket_accessed(hbm_bucket_idx[hbm_reg]);
                        }
                    }
                }
                time_last_poll = simulated_time_usec;
            }

            size_t usecs_since_last_caching = simulated_time_usec - time_last_cache;
            size_t usecs_since_last_cooling = simulated_time_usec - time_last_cooling;
            if (usecs_since_last_caching > usecs_caching) {
                bool cooled = s_cache_manager->cool_down_buckets(usecs_since_last_cooling);
                s_core->perform_caching();
                time_last_cache = simulated_time_usec;
                if (cooled) {
                    time_last_cooling = simulated_time_usec;
                }
                get_buckets_of_prefixes(hot_prefixes, s_tree, hot_sram_buckets, hot_hbm_buckets);
                get_buckets_of_prefixes(cold_prefixes, s_tree, cold_sram_buckets, cold_hbm_buckets);
            }

            if ((simulated_time_usec - time_start) % usecs_to_check_progress == 0) {
                size_t num_hot_prefixes_in_sram;
                size_t num_hot_prefixes_in_hbm;
                size_t num_hot_buckets_in_sram;
                size_t num_hot_buckets_in_hbm;

                get_hot_prefixes_stats(s_cache_manager,
                                       s_tree,
                                       hot_prefixes,
                                       num_hot_prefixes_in_sram,
                                       num_hot_prefixes_in_hbm,
                                       num_hot_buckets_in_sram,
                                       num_hot_buckets_in_hbm);

                double ratio_of_hot_prefixes_in_hbm
                    = static_cast<double>(num_hot_prefixes_in_hbm) / (num_hot_prefixes_in_hbm + num_hot_prefixes_in_sram);
                size_t percent_of_hot_prefixes_in_hbm = static_cast<size_t>(std::ceil(ratio_of_hot_prefixes_in_hbm * 100));

                if (show_progress) {
                    if (animated_progress) {
                        printf(CLEAR_SCREEN);
                    }
                    printf("prefixes hot:cold = %lf:%lf   traffic hot:cold = %lf:%lf  threshold to cache %zu   threshold to evict "
                           "%zu   decrease interval %zu usec   polling interval %zu usec\n",
                           hot_prefixes_frac,
                           1 - hot_prefixes_frac,
                           hot_traffic_frac,
                           1 - hot_traffic_frac,
                           hotness_threshold_to_cache,
                           hotness_threshold_to_evict,
                           usecs_until_hotness_decrease,
                           usecs_polling);
                    printf("time = %'zu usec\n", simulated_time_usec - time_start);
                    print_histograms(s_cache_manager);
                    print_hot_bucket_location(
                        num_hot_prefixes_in_sram, num_hot_prefixes_in_hbm, num_hot_buckets_in_sram, num_hot_buckets_in_hbm);

                    printf("%zu%% of hot prefixes are in SRAM after %'zu usecs\n",
                           100 - percent_of_hot_prefixes_in_hbm,
                           simulated_time_usec - time_start);
                }

                if (ratio_of_hot_prefixes_in_hbm <= 0.5) {
                    if (convergence_half_time == static_cast<size_t>(-1)) {
                        convergence_half_time = (simulated_time_usec - time_start);
                    }

                    if (show_progress) {
                        printf(">50%% of hot prefixes are in SRAM after %'zu usecs\n", convergence_half_time);
                    }
                }

                if (ratio_of_hot_prefixes_in_hbm == 0) {
                    if (convergence_time == static_cast<size_t>(-1)) {
                        convergence_time = (simulated_time_usec - time_start);
                    }

                    if (show_progress) {
                        printf("100%% of hot prefixes are in SRAM after %'zu usecs\n", convergence_time);
                    }

                    printf("converged\n");
                    break;
                }
            }

            simulated_time_usec++;
        }

        size_t num_hot_prefixes_in_sram;
        size_t num_hot_prefixes_in_hbm;
        size_t num_hot_buckets_in_sram;
        size_t num_hot_buckets_in_hbm;

        get_hot_prefixes_stats(s_cache_manager,
                               s_tree,
                               hot_prefixes,
                               num_hot_prefixes_in_sram,
                               num_hot_prefixes_in_hbm,
                               num_hot_buckets_in_sram,
                               num_hot_buckets_in_hbm);

        if (show_progress) {
            if (animated_progress) {
                printf(CLEAR_SCREEN);
            }
            print_histograms(s_cache_manager);
            print_hot_bucket_location(
                num_hot_prefixes_in_sram, num_hot_prefixes_in_hbm, num_hot_buckets_in_sram, num_hot_buckets_in_hbm);
        }

        double ratio_of_hot_prefixes_in_hbm
            = static_cast<double>(num_hot_prefixes_in_hbm) / (num_hot_prefixes_in_hbm + num_hot_prefixes_in_sram);
        size_t percent_of_hot_prefixes_in_hbm = static_cast<size_t>(ratio_of_hot_prefixes_in_hbm * 100);

        double ratio_of_hot_buckets_in_hbm
            = static_cast<double>(num_hot_buckets_in_hbm) / (num_hot_buckets_in_hbm + num_hot_buckets_in_sram);
        size_t percent_of_hot_buckets_in_hbm = static_cast<size_t>(ratio_of_hot_buckets_in_hbm * 100);
        printf("\n");
        printf("File: %s\n", filename.c_str());
        printf("polling every %'zu usec    caching every %'zu usec\n", usecs_polling, usecs_caching);
        printf("prefixes hot:cold = %lf:%lf   traffic hot:cold = %lf:%lf\n",
               hot_prefixes_frac,
               1 - hot_prefixes_frac,
               hot_traffic_frac,
               1 - hot_traffic_frac);
        if (convergence_time == static_cast<size_t>(-1)) {
            printf("did not converge:   %zu hot prefixes in HBM (%zu%%)  %zu hot buckets in HBM (%zu%%)\n",
                   num_hot_prefixes_in_hbm,
                   percent_of_hot_prefixes_in_hbm,
                   num_hot_buckets_in_hbm,
                   percent_of_hot_buckets_in_hbm);
        } else {
            printf("converged  after: %'zu usec\n", convergence_time);
        }

        printf("CSV:%s, %zu, %zu, %zu, %zu, %zu, %zu, %zu, %zu, %zu, %zu, %zu, %zu, %zu, %lf, %lf, %zu, %zu, %zu, %zu, %zu, %zu\n",
               filename.c_str(),
               usecs_polling,
               usecs_caching,
               hotness_threshold_to_cache,
               hotness_threshold_to_evict,
               usecs_until_hotness_decrease,
               full_keys.size(),
               num_buckets,
               initial_num_hot_prefixes_in_sram + initial_num_hot_prefixes_in_hbm,
               initial_num_hot_prefixes_in_sram,
               initial_num_hot_prefixes_in_hbm,
               initial_num_hot_buckets_in_sram + initial_num_hot_buckets_in_hbm,
               initial_num_hot_buckets_in_sram,
               initial_num_hot_buckets_in_hbm,
               hot_prefixes_frac,
               hot_traffic_frac,
               num_hot_prefixes_in_hbm,
               num_hot_buckets_in_hbm,
               percent_of_hot_prefixes_in_hbm,
               percent_of_hot_buckets_in_hbm,
               convergence_time,
               convergence_half_time);
    }

    void testWithEntriesFromFileMultipleConfigurations(const std::string filename,
                                                       size_t max_entries,
                                                       std::vector<double>& hot_prefixes_frac_vec,
                                                       std::vector<double>& hot_traffic_frac_vec,
                                                       size_t usecs_to_run,
                                                       size_t usecs_to_check_progress,
                                                       std::vector<size_t>& usecs_polling_vec,
                                                       size_t usecs_caching,
                                                       std::vector<size_t>& hotness_threshold_to_cache_vec,
                                                       size_t hotness_threshold_to_evict,
                                                       std::vector<size_t>& usecs_until_hotness_decrease_vec,
                                                       size_t max_hotness_level,
                                                       double garbage_bucket_probability)
    {

        lpm_key_set_t keys_in_system;
        loadEntriesFromFile(filename, max_entries, false /* fail_on_error */, 1000 /* iterations_to_cool_down */, keys_in_system);

        for (size_t usecs_polling : usecs_polling_vec) {
            for (size_t hotness_threshold_to_cache : hotness_threshold_to_cache_vec) {
                for (size_t usecs_until_hotness_decrease : usecs_until_hotness_decrease_vec) {
                    for (double hot_prefixes_frac : hot_prefixes_frac_vec) {
                        for (double hot_traffic_frac : hot_traffic_frac_vec) {
                            testWithEntriesFromFile(filename,
                                                    keys_in_system,
                                                    hot_prefixes_frac,
                                                    hot_traffic_frac,
                                                    usecs_to_run,
                                                    usecs_to_check_progress,
                                                    usecs_polling,
                                                    usecs_caching,
                                                    hotness_threshold_to_cache,
                                                    hotness_threshold_to_evict,
                                                    usecs_until_hotness_decrease,
                                                    max_hotness_level,
                                                    garbage_bucket_probability);
                        }
                    }
                }
            }
        }
    }
};

ll_device_sptr LpmHbmCachingCoreTest::s_ll_device(nullptr);
lpm_core_tcam_utils_scptr LpmHbmCachingCoreTest::s_core_tcam_utils(nullptr);

TEST_F(LpmHbmCachingCoreTest, DISABLED_Repro)
{
    std::string filename("test/hw_tables/lpm/inputs/repro.txt.gz");
    size_t max_entries = static_cast<size_t>(-1);

    std::vector<double> hot_prefixes_frac{0.8};
    std::vector<double> hot_traffic_frac{0.99};
    size_t usecs_to_run = 1000000000000;
    size_t usecs_to_check_progress = 1000000;
    std::vector<size_t> usecs_polling{3000};
    size_t usecs_caching = 100000;
    std::vector<size_t> hotness_threshold_to_cache{7};
    size_t hotness_threshold_to_evict = 1;
    std::vector<size_t> usecs_until_hotness_decrease{10000000};
    size_t max_hotness_level = 8;
    double garbage_bucket_probability = 0.1;

    testWithEntriesFromFileMultipleConfigurations(filename,
                                                  max_entries,
                                                  hot_prefixes_frac,
                                                  hot_traffic_frac,
                                                  usecs_to_run,
                                                  usecs_to_check_progress,
                                                  usecs_polling,
                                                  usecs_caching,
                                                  hotness_threshold_to_cache,
                                                  hotness_threshold_to_evict,
                                                  usecs_until_hotness_decrease,
                                                  max_hotness_level,
                                                  garbage_bucket_probability);
}

TEST_F(LpmHbmCachingCoreTest, DISABLED_ConsecutiveIPV4_100K_Multi)
{
    std::string filename("test/hw_tables/lpm/inputs/lpm_data.ipv4_1million.txt.gz");
    size_t max_entries = 100000;
    std::vector<double> hot_prefixes_frac{0.001, 0.005, 0.01, 0.05, 0.1, 0.2, 0.3};
    std::vector<double> hot_traffic_frac{0.999, 0.99, 0.95, 0.9, 0.8, 0.7};
    size_t usecs_to_run = 100000000;
    size_t usecs_to_check_progress = 1000000;
    std::vector<size_t> usecs_polling{3000};
    size_t usecs_caching = 100000;
    std::vector<size_t> hotness_threshold_to_cache{7};
    size_t hotness_threshold_to_evict = 1;
    std::vector<size_t> usecs_until_hotness_decrease{1000000};
    size_t max_hotness_level = 8;
    double garbage_bucket_probability = 0.1;

    testWithEntriesFromFileMultipleConfigurations(filename,
                                                  max_entries,
                                                  hot_prefixes_frac,
                                                  hot_traffic_frac,
                                                  usecs_to_run,
                                                  usecs_to_check_progress,
                                                  usecs_polling,
                                                  usecs_caching,
                                                  hotness_threshold_to_cache,
                                                  hotness_threshold_to_evict,
                                                  usecs_until_hotness_decrease,
                                                  max_hotness_level,
                                                  garbage_bucket_probability);
}
