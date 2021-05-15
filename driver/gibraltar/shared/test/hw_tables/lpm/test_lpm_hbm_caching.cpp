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
#include "lpm/lpm_distributor.h"
#include "test_lpm_read_entries.h"
#include "test_lpm_types.h"
#include <algorithm>
#include <cmath>
#include <locale>
#include <random>
#include <set>

using namespace silicon_one;

// Colors
constexpr bool use_colors = true;
constexpr char RED_COLOR[] = "\033[0;31m";
constexpr char BLUE_COLOR[] = "\033[0;34m";
constexpr char YELLOW_COLOR[] = "\033[0;33m";
constexpr char RESET_COLOR[] = "\033[0m";
constexpr char CLEAR_SCREEN[] = "\033[2J\033[1;1H";

struct prefix_location {
    size_t core_id;
    size_t l2_bucket;

    bool operator<(const prefix_location& other) const
    {
        if (core_id == other.core_id) {
            return l2_bucket < other.l2_bucket;
        }

        return core_id < other.core_id;
    }
};

static void
print_color(const char color[])
{
    if (!use_colors) {
        return;
    }
    printf("%s", color);
}

class LpmHbmCachingTest : public ::testing::Test
{
protected:
    typedef std::set<lpm_key_t, key_less_operator> lpm_key_set_t;

    static constexpr size_t N_CORES = 16;
    static constexpr size_t VRF_LEN = 11;
    static constexpr size_t IPV4_IP_LEN = 32;
    static constexpr size_t IPV6_IP_LEN = 128;

    bool verbose = false;
    bool show_progress = true;
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
    }

    static void TearDownTestCase()
    {
        s_ll_device.reset();
    }

    lpm_core_sptr get_core(const logical_lpm_sptr& lpm, size_t core_id) const
    {
        return std::const_pointer_cast<lpm_core>(lpm->get_core(core_id));
    }

    lpm_core_scptr get_core(const logical_lpm_scptr& lpm, size_t core_id) const
    {
        return lpm->get_core(core_id);
    }

    bucketing_tree_scptr get_tree(const logical_lpm_scptr& lpm) const
    {
        return lpm->get_tree();
    }

    lpm_hbm_cache_manager& get_hbm_cache_manager(const logical_lpm_sptr& lpm, size_t core_id) const
    {
        return get_core(lpm, core_id)->get_hbm_cache_manager();
    }

    void check_tree(const lpm_node* node)
    {
        if (node == nullptr) {
            return;
        }

        const lpm_node* left_child = node->get_left_child();
        const lpm_node* right_child = node->get_right_child();
        for (const lpm_node* child : {left_child, right_child}) {
            if (child != nullptr) {
                const lpm_node* parent = child->get_parent_node();
                ASSERT_NE(parent, nullptr);
                ASSERT_EQ(parent, node);

                check_tree(child);
            }
        }
    }

    void check_trees(const logical_lpm_scptr& lpm)
    {
        for (size_t core_id = 0; core_id < N_CORES; core_id++) {
            auto tree = get_tree(lpm);
            check_tree(tree->get_root_node());
        }
    }

    void SetUp()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::ERROR;
        logger::instance().set_logging_level(0, silicon_one::la_logger_component_e::TABLES, logger_level);

        lpm_settings settings = create_lpm_settings(s_ll_device);
        update_lpm_settings(settings);
        s_lpm = create_logical_lpm(s_ll_device, settings);

        for (size_t coreid = 0; coreid < N_CORES; coreid++) {
            auto cache_manager = get_hbm_cache_manager(s_lpm, coreid);
            cache_manager.toggle_simulated_time_mode(true);
        }
        setlocale(LC_NUMERIC, "");
    }

    void TearDown()
    {
        s_lpm.reset();
        s_entries.clear();
    }

    static ll_device_sptr s_ll_device;     // Low level device.
    logical_lpm_sptr s_lpm;                // Logical LPM.
    test_data_lpm_entries_set_t s_entries; // Entries set to track the entries in core.
    size_t simulated_time_usec = 0;        // Simulated time.

    void update_lpm_settings(lpm_settings& settings)
    {
        settings.l2_buckets_per_sram_row = 1;
        settings.l2_max_number_of_hbm_buckets = 12 * 1024;
        settings.trap_destination = trap_destination;
    }

    bool loadEntriesFromFile(const std::string filename,
                             size_t max_entries,
                             bool fail_on_error,
                             size_t iterations_to_cool_down,
                             lpm_key_set_t& out_keys_in_system)
    {
        lpm_read_entries r(true /*v4 and v6*/);
        lpm_read_entries::lpm_test_action_desc_vec_t test_actions = r.read_extended_raw_entries(filename, max_entries, false);

        if (test_actions.empty()) {
            return false;
        }

        if (shuffle_entries) {
            std::default_random_engine re{random_seed};
            std::shuffle(test_actions.begin(), test_actions.end(), re);
        }

        lpm_hbm_cache_manager::lpm_hbm_caching_params params = get_hbm_cache_manager(s_lpm, 0).get_caching_params();

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
                for (size_t coreid = 0; coreid < N_CORES; coreid++) {
                    get_hbm_cache_manager(s_lpm, coreid).cool_down_buckets(params.usecs_until_hotness_decrease);
                }
                check_trees(s_lpm);
            }

            /* 128 IPv6 entries don't go to LPM, but to EM */
            if (action.is_update && (action.update_desc.m_key.get_width() == IPV6_IP_LEN + VRF_LEN + 1)) {
                skipped++;
                continue;
            }

            if (action.is_update && (action.update_desc.m_action == lpm_action_e::INSERT)) {
                la_status status = s_lpm->insert(action.update_desc.m_key, action.update_desc.m_payload);
                if ((status != LA_STATUS_SUCCESS) && verbose) {
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
                if (status != LA_STATUS_SUCCESS) {
                    if (fail_on_error) {
                        printf("Insert failed at iteration %zu\n", iteration);
                        return false;
                    }
                    errors++;
                    continue;
                }

                out_keys_in_system.insert(action.update_desc.m_key);
                insertions++;
                // check_trees(s_lpm);
            } else if (action.is_update && (action.update_desc.m_action == lpm_action_e::REMOVE)) {
                la_status status = s_lpm->remove(action.update_desc.m_key);
                if ((status != LA_STATUS_SUCCESS) && verbose) {
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
                if (status != LA_STATUS_SUCCESS) {
                    if (fail_on_error) {
                        printf("Insert failed at iteration %zu\n", iteration);
                        return false;
                    }
                    errors++;
                    continue;
                }

                status = s_lpm->modify(action.update_desc.m_key, action.update_desc.m_payload);
                if ((status != LA_STATUS_SUCCESS) && verbose) {
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
                if (status != LA_STATUS_SUCCESS) {
                    if (fail_on_error) {
                        printf("Insert failed at iteration %zu\n", iteration);
                        return false;
                    }
                    errors++;
                    continue;
                }

                modifies++;
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

        check_trees(s_lpm);

        return true;
    }

    void print_core_stats() const
    {
        const auto& l2_stats = get_tree(s_lpm)->get_occupancy(lpm_level_e::L2);
        for (size_t coreid = 0; coreid < N_CORES; coreid++) {
            const auto& l2_stats_core = l2_stats[coreid];
            printf("Core ID = %04lu | L2 entries = %9lu | L2 entries SRAM = %9lu | L2 entries HBM = %9lu\n",
                   coreid,
                   l2_stats_core.sram_single_entries + l2_stats_core.hbm_entries,
                   l2_stats_core.sram_single_entries,
                   l2_stats_core.hbm_entries);
        }
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

    prefix_location key_to_location(const logical_lpm_scptr& lpm, const lpm_key_t& key)
    {
        const auto& distributor = lpm->get_distributer();

        lpm_key_t hit_key;
        lpm_payload_t hit_group;
        distributor_cell_location hit_location;
        la_status status = distributor.lookup_tcam_tree(key, hit_key, hit_group, hit_location);
        dassert_crit(status == LA_STATUS_SUCCESS);

        size_t coreid = lpm->get_core_index_by_group(hit_group);

        dassert_crit(coreid < N_CORES);

        auto tree = get_tree(lpm);
        const lpm_node* node = tree->find_node(key);
        dassert_crit(node != nullptr);

        while (node->data().bucketing_state == lpm_bucketing_data::node_bucketing_state::DOES_NOT_BELONG) {
            node = node->get_parent_node();
        }

        lpm_bucket* bucket = tree->get_bucket(node, lpm_level_e::L2);

        lpm_bucket_index_t hw_index = bucket->get_hw_index();
        return {.core_id = coreid, .l2_bucket = static_cast<size_t>(hw_index)};
    }

    void get_locations_of_prefixes(std::vector<lpm_key_t>& prefixes,
                                   const logical_lpm_scptr& lpm,
                                   std::vector<prefix_location>& out_sram_buckets,
                                   std::vector<prefix_location>& out_hbm_buckets)
    {
        std::vector<size_t> buckets;
        for (const auto& prefix : prefixes) {
            prefix_location location = key_to_location(lpm, prefix);
            bool is_bucket_in_hbm = (location.l2_bucket >= 4096);

            if (is_bucket_in_hbm) {
                out_hbm_buckets.push_back(location);
            } else {
                out_sram_buckets.push_back(location);
            }
        }
    }

    prefix_location sample_a_key_and_get_its_location(std::vector<prefix_location>& hot_buckets,
                                                      std::vector<prefix_location>& cold_buckets,
                                                      std::mt19937& rand_engine,
                                                      const logical_lpm_scptr& lpm,
                                                      double hot_traffic_frac,
                                                      double garbage_bucket_probability)
    {
        std::uniform_real_distribution<double> cold_hot_dist(0, 1);
        bool is_hot = cold_hot_dist(rand_engine) < hot_traffic_frac;
        const std::vector<prefix_location>& buckets = is_hot ? hot_buckets : cold_buckets;

        std::uniform_real_distribution<double> sample_garbage_bucket_dist(0, 1);
        bool do_sample_garbage_bucket
            = (buckets.size() == 0) || (sample_garbage_bucket_dist(rand_engine) < garbage_bucket_probability);

        if (do_sample_garbage_bucket) {
            std::uniform_int_distribution<size_t> buckets_dist(0, 1 << 20);
            size_t selected_garbage_bucket = buckets_dist(rand_engine);
            std::uniform_int_distribution<size_t> core_dist(0, N_CORES);
            size_t random_core = core_dist(rand_engine);
            return {.core_id = random_core, .l2_bucket = selected_garbage_bucket};
        }

        dassert_crit(buckets.size() > 0);

        std::uniform_int_distribution<size_t> buckets_dist(0, buckets.size() - 1);
        size_t selected_bucket = buckets_dist(rand_engine);
        return buckets[selected_bucket];
    }

    void print_histograms(const logical_lpm_sptr& lpm)
    {
        for (size_t core_id = 0; core_id < N_CORES; core_id++) {
            print_histograms(lpm, core_id);
        }
    }

    void print_histograms(const logical_lpm_sptr& lpm, size_t core_id)
    {
        auto cache_manager = get_hbm_cache_manager(lpm, core_id);
        printf("Core ID = %zu\n", core_id);
        lpm_hbm_cache_manager::lpm_hbm_caching_stats stats = cache_manager.get_statistics(false /* reset counters */);
        lpm_hbm_cache_manager::lpm_hbm_caching_params params = cache_manager.get_caching_params();

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

    void get_hot_prefixes_stats(const logical_lpm_scptr& lpm,
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

        std::set<prefix_location> buckets_in_sram;
        std::set<prefix_location> buckets_in_hbm;

        for (const auto& prefix : hot_prefixes) {
            prefix_location location = key_to_location(lpm, prefix);
            if (location.l2_bucket < HBM_BUCKET_OFFSET) {
                num_prefixes_in_sram++;
                buckets_in_sram.insert(location);
            } else {
                num_prefixes_in_hbm++;
                buckets_in_hbm.insert(location);
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

        check_trees(s_lpm);

        std::set<prefix_location> buckets;
        for (const auto& key : full_keys) {
            prefix_location location = key_to_location(s_lpm, key);
            buckets.insert(location);
        }
        size_t num_buckets = buckets.size();

        std::mt19937 gen{random_seed};

        std::vector<lpm_key_t> hot_prefixes;
        std::vector<lpm_key_t> cold_prefixes;
        separate_keys_into_hot_and_cold(full_keys, hot_prefixes_frac, gen, hot_prefixes, cold_prefixes);

        size_t time_start = simulated_time_usec;
        size_t time_last_poll = simulated_time_usec;
        size_t time_last_cache = simulated_time_usec;
        size_t time_last_cooling[N_CORES] = {simulated_time_usec};

        lpm_hbm_cache_manager::lpm_hbm_caching_params caching_params = get_hbm_cache_manager(s_lpm, 0).get_caching_params();
        caching_params.hotness_threshold_to_cache = hotness_threshold_to_cache;
        caching_params.hotness_threshold_to_evict = hotness_threshold_to_evict;
        caching_params.usecs_until_hotness_decrease = usecs_until_hotness_decrease;
        caching_params.max_hotness_level = max_hotness_level;
        for (size_t core_id = 0; core_id < N_CORES; core_id++) {
            get_hbm_cache_manager(s_lpm, core_id).set_caching_params(caching_params);
        }

        std::array<size_t, N_CORES> sram_bucket_idx = {{0}};
        std::array<prefix_location, 4> hbm_bucket_idx;

        std::uniform_int_distribution<int> cores_dist(0, N_CORES - 1);

        size_t convergence_time = static_cast<size_t>(-1);
        size_t convergence_half_time = static_cast<size_t>(-1);

        size_t initial_num_hot_prefixes_in_sram;
        size_t initial_num_hot_prefixes_in_hbm;
        size_t initial_num_hot_buckets_in_sram;
        size_t initial_num_hot_buckets_in_hbm;
        get_hot_prefixes_stats(s_lpm,
                               hot_prefixes,
                               initial_num_hot_prefixes_in_sram,
                               initial_num_hot_prefixes_in_hbm,
                               initial_num_hot_buckets_in_sram,
                               initial_num_hot_buckets_in_hbm);

        std::vector<prefix_location> hot_sram_buckets;
        std::vector<prefix_location> hot_hbm_buckets;
        std::vector<prefix_location> cold_sram_buckets;
        std::vector<prefix_location> cold_hbm_buckets;

        get_locations_of_prefixes(hot_prefixes, s_lpm, hot_sram_buckets, hot_hbm_buckets);
        get_locations_of_prefixes(cold_prefixes, s_lpm, cold_sram_buckets, cold_hbm_buckets);

        constexpr size_t NUM_SAMPLES = 100 * N_CORES;

        while (1) {
            size_t usecs_runtime = simulated_time_usec - time_start;
            if (usecs_runtime > usecs_to_run) {
                break;
            }

            size_t usecs_since_last_poll = simulated_time_usec - time_last_poll;
            if (usecs_since_last_poll > usecs_polling) {
                for (size_t sample = 0; sample < NUM_SAMPLES; sample++) {
                    prefix_location location = sample_a_key_and_get_its_location(
                        hot_sram_buckets, cold_sram_buckets, gen, s_lpm, hot_traffic_frac, garbage_bucket_probability);
                    sram_bucket_idx[location.core_id] = location.l2_bucket;
                }

                for (size_t core_id = 0; core_id < N_CORES; core_id++) {
                    get_core(s_lpm, core_id)->notify_l2_bucket_accessed(sram_bucket_idx[core_id]);
                    get_core(s_lpm, core_id)->notify_l2_bucket_accessed(sram_bucket_idx[core_id] ^ 1);
                }

                for (size_t hbm_reg = 0; hbm_reg < 4; hbm_reg++) {
                    hbm_bucket_idx[hbm_reg] = sample_a_key_and_get_its_location(
                        hot_hbm_buckets, cold_hbm_buckets, gen, s_lpm, hot_traffic_frac, garbage_bucket_probability);

                    if (hbm_bucket_idx[hbm_reg].l2_bucket >= 4096) {
                        get_core(s_lpm, hbm_bucket_idx[hbm_reg].core_id)
                            ->notify_l2_bucket_accessed(hbm_bucket_idx[hbm_reg].l2_bucket);
                    }
                }
                time_last_poll = simulated_time_usec;
            }

            size_t usecs_since_last_caching = simulated_time_usec - time_last_cache;
            if (usecs_since_last_caching > usecs_caching) {
                for (size_t core_id = 0; core_id < N_CORES; core_id++) {
                    size_t usecs_since_last_cooling = simulated_time_usec - time_last_cooling[core_id];
                    bool cooled = get_hbm_cache_manager(s_lpm, core_id).cool_down_buckets(usecs_since_last_cooling);
                    get_core(s_lpm, core_id)->perform_caching();
                    time_last_cache = simulated_time_usec;
                    if (cooled) {
                        time_last_cooling[core_id] = simulated_time_usec;
                    }
                }
                get_locations_of_prefixes(hot_prefixes, s_lpm, hot_sram_buckets, hot_hbm_buckets);
                get_locations_of_prefixes(cold_prefixes, s_lpm, cold_sram_buckets, cold_hbm_buckets);
            }

            if ((simulated_time_usec - time_start) % usecs_to_check_progress == 0) {
                size_t num_hot_prefixes_in_sram;
                size_t num_hot_prefixes_in_hbm;
                size_t num_hot_buckets_in_sram;
                size_t num_hot_buckets_in_hbm;

                get_hot_prefixes_stats(s_lpm,
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
                    print_histograms(s_lpm);
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

        get_hot_prefixes_stats(s_lpm,
                               hot_prefixes,
                               num_hot_prefixes_in_sram,
                               num_hot_prefixes_in_hbm,
                               num_hot_buckets_in_sram,
                               num_hot_buckets_in_hbm);

        if (show_progress) {
            if (animated_progress) {
                printf(CLEAR_SCREEN);
            }
            print_histograms(s_lpm);
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
        bool ok = loadEntriesFromFile(
            filename, max_entries, false /* fail_on_error */, 1000 /* iterations_to_cool_down */, keys_in_system);
        ASSERT_TRUE(ok) << "loadEntriesFromFile: " << filename << " Failed";

        check_trees(s_lpm);

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

ll_device_sptr LpmHbmCachingTest::s_ll_device(nullptr);

TEST_F(LpmHbmCachingTest, DISABLED_Repro)
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

TEST_F(LpmHbmCachingTest, DISABLED_ConsecutiveIPV4_100K_Multi)
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
