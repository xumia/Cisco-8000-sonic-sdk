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

#include "hw_tables/logical_lpm.h"
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "test_lpm_types.h"

using namespace silicon_one;

// Logical LPM tester
class LpmTest : public ::testing::Test
{
protected:
    // Set up test case: load LPM with entries.
    static void SetUpTestCase()
    {
        std::string filename = "test/hw_tables/lpm/inputs/bgptable.txt.gz";
        srand(random_seed);

        PRINTF("Random seed: %lu\n", random_seed);

        stopwatch stopwatch;

        PRINTF("Create new logical LPM\n");

        s_ll_device = ll_device::create(0, device_path.c_str());

        lpm_settings settings = create_lpm_settings(s_ll_device);
        update_lpm_settings(settings);

        s_lpm = create_logical_lpm(s_ll_device, settings);

        const size_t ITERATIONS = 10;
        size_t logical_lpm_number_of_entries = num_of_entries * ITERATIONS;
        size_t count_success = 0;

        lpm_action_desc_vec_t actions(read_entries(filename, logical_lpm_number_of_entries, true /*v4 and v6*/));
        ASSERT_EQ(actions.empty(), false);

        stopwatch.start();
        for (size_t idx = 0; idx < ITERATIONS; ++idx) {
            const auto& begin_it = actions.begin() + idx * num_of_entries;
            lpm_action_desc_vec_t iter_actions(begin_it, begin_it + num_of_entries);
            la_status status = s_lpm->update(iter_actions, count_success);
            ASSERT_EQ(LA_STATUS_SUCCESS, status);
        }
        stopwatch.stop();

        for (size_t j = 0; j < actions.size(); j++) {
            const lpm_key_t& key(actions[j].m_key);
            lpm_payload_t payload = actions[j].m_payload;

            s_entries.insert(test_data_lpm_entry(key, payload));
        }

        size_t num_of_read_entries = actions.size();
        uint64_t time_ms = stopwatch.get_interval_time(stopwatch::time_unit_e::MS);
        uint64_t time_ns = stopwatch.get_interval_time(stopwatch::time_unit_e::NS);
        uint64_t ips = num_of_read_entries * 1000 * 1000 * 1000 / time_ns;
        PRINTF("Done reading %lu entries in %lu ms (%lu insertions per second)\n", num_of_read_entries, time_ms, ips);
    }

    // Tear down case: remove all entries from LPM.
    static void TearDownTestCase()
    {
        lpm_action_desc_vec_t actions;
        size_t count_success = 0;

        for (const auto& test_data_lpm_entry : s_entries) {
            actions.push_back(lpm_action_desc(lpm_action_e::REMOVE, test_data_lpm_entry.m_key, INVALID_PAYLOAD));
        }

        random_shuffle(actions.begin(), actions.end());

        ASSERT_EQ(LA_STATUS_SUCCESS, s_lpm->update(actions, count_success));

        const auto& tree = s_lpm->get_tree();
        core_buckets_occupancy_vec l1_cores_occupancy = tree->get_occupancy(lpm_level_e::L1);
        core_buckets_occupancy_vec l2_cores_occupancy = tree->get_occupancy(lpm_level_e::L2);
        constexpr size_t N_CORES = 16;
        for (size_t core_id = 0; core_id < N_CORES; core_id++) {
            const auto& core = s_lpm->get_core(core_id);
            const lpm_core_tcam& tcam = core->get_tcam();
            ASSERT_LE(tcam.get_occupancy().occupied_cells, distributor_size);

            const auto& l1_core_buckets_occupancy = l1_cores_occupancy[core_id];
            const auto& l2_core_buckets_occupancy = l2_cores_occupancy[core_id];
            ASSERT_LE(l1_core_buckets_occupancy.sram_buckets, distributor_size);
            ASSERT_LE(l2_core_buckets_occupancy.sram_buckets, distributor_size);
        }

        s_lpm.reset();

        s_ll_device.reset();
    }

    static void update_lpm_settings(lpm_settings& settings)
    {
        settings.num_cores = num_of_cores;
        settings.num_distributor_lines = distributor_size;
        settings.distributor_row_width = distributor_width;
        settings.l2_double_bucket_size = l2_double_bucket_size;
        settings.l2_max_bucket_size = l2_max_bucket_size;
        settings.hbm_max_bucket_size = 0; /*no HBM*/
        settings.l1_double_bucket_size = l1_double_bucket_size;
        settings.l1_max_sram_buckets = l1_max_number_of_buckets;
        settings.l1_max_bucket_size = l1_max_bucket_size;
        settings.max_bucket_depth = max_bucket_depth;
        settings.tcam_max_quad_entries = max_tcam_quad_entries;
        settings.l2_buckets_per_sram_row = l2_buckets_per_sram_row;
        settings.l2_max_number_of_sram_buckets = l2_max_number_of_sram_buckets;
        settings.l2_max_number_of_hbm_buckets = 0; /* max HBM bucket size */
        settings.tcam_num_banksets = tcam_num_banksets;
        settings.tcam_bank_size = tcam_bank_size;
        settings.trap_destination = trap_destination;
        settings.l1_buckets_per_sram_row = l1_buckets_per_sram_row;
    }

    bool lookup_check(size_t i,
                      size_t number_of_entries,
                      const test_data_lpm_entries_vec_t& entries_vec,
                      set_alloc<size_t>& used_indices) const
    {
        size_t index = rand() % number_of_entries;
        size_t iter = 0;
        while (used_indices.count(index) == 1 && iter < 10) {
            index = rand() % number_of_entries;
            iter++;
        }
        used_indices.insert(index);

        const test_data_lpm_entry& entry(entries_vec[index]);
        const lpm_key_t& key(entry.m_key);
        lpm_key_t lookupped_key;
        lpm_payload_t lookupped_payload;
        la_status status = s_lpm->lookup(key, lookupped_key, lookupped_payload);
        if (status != LA_STATUS_SUCCESS) {
            return false;
        }

        return (key == lookupped_key) && (entry.m_payload == lookupped_payload);
    }

    size_t print_stats() const
    {
        size_t total_num_of_entries = 0;
        vector_alloc<size_t> cores_util(s_lpm->get_cores_utilization());
        for (size_t index = 0; index < num_of_cores; index++) {
            total_num_of_entries += cores_util[index];
        }

        size_t max_number_of_entries_in_core = l2_max_number_of_sram_buckets * l2_double_bucket_size / 2;
        PRINTF("Entries distribution between cores:\n");
        for (size_t index = 0; index < num_of_cores; index++) {
            size_t num_of_entries_in_core = cores_util[index];
            float util = 100.0 * num_of_entries_in_core / max_number_of_entries_in_core;
            PRINTF("Core %2lu: number of entries = %lu, utilization = %.1f%%\n", index, num_of_entries_in_core, util);
        }

        return total_num_of_entries;
    }

    size_t find_max_utilization() const
    {
        size_t max_util = 0;
        vector_alloc<size_t> cores_util(s_lpm->get_cores_utilization());
        for (size_t index = 0; index < num_of_cores; index++) {
            size_t util = cores_util[index];

            max_util = std::max(max_util, util);
        }

        return max_util;
    }

    enum { NUMBER_OF_INSRTIONS_BETWEEN_REBALANCE = 1000 };

    static ll_device_sptr s_ll_device;            // Low level device.
    static logical_lpm_sptr s_lpm;                // Logical LPM.
    static test_data_lpm_entries_set_t s_entries; // Entries set to track the entries in core.
};

ll_device_sptr LpmTest::s_ll_device(nullptr);
logical_lpm_sptr LpmTest::s_lpm;
test_data_lpm_entries_set_t LpmTest::s_entries;

TEST_F(LpmTest, SanityTest)
{
    ASSERT_NE(s_entries.size(), (size_t)0);

    size_t total_num_of_entries = print_stats();
    ASSERT_EQ(total_num_of_entries, s_entries.size());
}

TEST_F(LpmTest, LookupTest)
{
    ASSERT_NE(s_entries.size(), (size_t)0);

    test_data_lpm_entries_vec_t entries_vec(s_entries.begin(), s_entries.end());
    size_t number_of_entries = entries_vec.size();
    size_t num_lookups = num_of_entries / 2;

    set_alloc<size_t> used_indices;
    for (size_t i = 0; i < num_lookups; i++) {
        ASSERT_EQ(true, lookup_check(i, number_of_entries, entries_vec, used_indices)) << "Iteration " << i;
    }
}

TEST_F(LpmTest, LoadBalanceSanityTest)
{
    ASSERT_NE(s_entries.size(), (size_t)0);

    // Generate entry not in Logical LPM.
    lpm_payload_t payload(1);
    lpm_key_t key;

    lpm_key_t temp_key;
    lpm_payload_t dummy_payload;
    la_status status;

    do {
        key = rand_key();
        status = s_lpm->lookup(key, temp_key, dummy_payload);

    } while (key == temp_key && status == LA_STATUS_SUCCESS);

    size_t old_max = find_max_utilization();

    // Insert and remove the same entry many times, to artificially cause rebalance.
    for (size_t i = 0; i < NUMBER_OF_INSRTIONS_BETWEEN_REBALANCE; i++) {
        ASSERT_EQ(LA_STATUS_SUCCESS, s_lpm->insert(key, payload));
        ASSERT_EQ(LA_STATUS_SUCCESS, s_lpm->remove(key));
    }

    size_t new_max = find_max_utilization();

    size_t total_num_of_entries = print_stats();
    PRINTF("Max core utilization before rebalance = %lu, max core utilization after rebalance = %lu\n", old_max, new_max);
    ASSERT_EQ(total_num_of_entries, s_entries.size());
}

TEST_F(LpmTest, LookupTest2)
{
    ASSERT_NE(s_entries.size(), (size_t)0);
    test_data_lpm_entries_vec_t entries_vec(s_entries.begin(), s_entries.end());
    size_t number_of_entries = entries_vec.size();
    size_t num_lookups = num_of_entries / 2;

    set_alloc<size_t> used_indices;
    for (size_t i = 0; i < num_lookups; i++) {
        ASSERT_EQ(true, lookup_check(i, number_of_entries, entries_vec, used_indices)) << "Iteration " << i;
    }
}
