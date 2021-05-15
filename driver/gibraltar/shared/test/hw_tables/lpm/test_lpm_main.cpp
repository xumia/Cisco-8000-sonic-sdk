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

#include "lpm/lpm_bucket_occupancy_utils.h"
#include "test_lpm_read_entries.h"
#include "test_lpm_types.h"
#include <algorithm>

size_t num_of_entries = 10000;
size_t l2_buckets_per_sram_row = 2;
size_t l2_max_bucket_size = is_gb() ? 18 : 17;
size_t l2_max_hbm_bucket_size = 24;
size_t l2_double_bucket_size = is_gb() ? 18 : 20;
size_t l2_max_number_of_sram_buckets = silicon_one::NUM_OF_L2_SRAM_BUCKETS;
size_t l2_max_number_of_hbm_buckets = silicon_one::NUM_OF_L2_HBM_BUCKETS;
size_t l1_max_bucket_size = 6;
size_t l1_double_bucket_size = 8;
size_t l1_max_number_of_buckets = silicon_one::NUM_OF_L1_BUCKETS;
size_t l1_buckets_per_sram_row = 2;
size_t max_tcam_quad_entries = silicon_one::LPM_TCAM_QUAD_ENTRIES;
size_t max_bucket_depth = 16;
size_t tcam_num_banksets = 1;
size_t tcam_bank_size = 512;
std::string device_path = "/dev/testdev";
size_t num_of_cores = 16;
size_t distributor_size = silicon_one::LPM_DISTRIBUTOR_SIZE;
size_t distributor_width = silicon_one::LPM_DISTRIBUTOR_WIDTH;
uint64_t random_seed = 0;
bool enable_hbm = true;
double rebalance_start_threshold = 0.8;
double rebalance_end_threshold = 0.9;
size_t rebalance_interval = 1000;
size_t number_lines = 400000;
bool verbose = false;
bool shuffle_entries = false;
size_t trap_destination = 0xc0ffe;

static const size_t LPM_PAYLOAD_WIDTH = 20;

namespace silicon_one
{

test_data_lpm_bucket::test_data_lpm_bucket(const lpm_bucket& bucket)
    : m_index(bucket.get_sw_index()),
      m_root(bucket.get_root()),
      m_default_payload(),
      m_entries(bucket.size(), test_data_lpm_entry(lpm_key_t(), INVALID_PAYLOAD)),
      m_hw_index(bucket.get_hw_index())
{
    lpm_key_payload default_entry = bucket.get_default_entry();
    m_default_payload = default_entry.payload;

    size_t i = 0;
    lpm_key_payload_vec entries = bucket.get_entries();
    for (const lpm_key_payload& entry : entries) {
        m_entries[i] = test_data_lpm_entry(entry.key, entry.payload);
        i++;
    }

    std::sort(m_entries.begin(), m_entries.end(), entry_less_operator());
}

bool
test_data_lpm_bucket::operator==(const test_data_lpm_bucket& other) const
{
    if (m_index == other.m_index && m_root == other.m_root && m_default_payload == other.m_default_payload
        && m_entries == other.m_entries
        && m_hw_index == other.m_hw_index) {
        return true;
    }

    if (m_index != other.m_index) {
        printf("Bucket indices don't match: left = %lu, right = %lu\n", m_index, other.m_index);
    }

    if (m_root != other.m_root) {
        printf("Bucket roots don't match: left = %s, right = %s\n", m_root.to_string().c_str(), other.m_root.to_string().c_str());
    }

    if (m_default_payload != other.m_default_payload) {
        printf("Bucket defaults don't match: left = %u, right = %u\n", m_default_payload, other.m_default_payload);
    }

    if (m_entries != other.m_entries) {
        printf("Bucket entries doesn't match:\n");
        printf("Left entries:\n");
        print_entries(m_entries);
        printf("Right entries:\n");
        print_entries(other.m_entries);
    }

    return false;
}

size_t
test_data_lpm_bucket::size() const
{
    size_t bucket_size = m_entries.size();

    size_t root_width = m_root.get_width();
    for (const auto& test_data_lpm_entry : m_entries) {
        size_t width = test_data_lpm_entry.m_key.get_width();
        if (width < root_width) {
            printf("Test data bucket %lu error: the width of entry %s is %lu which is smaller than the width %lu of the root %s\n",
                   m_index,
                   test_data_lpm_entry.m_key.to_string().c_str(),
                   width,
                   root_width,
                   m_root.to_string().c_str());

            return -1;
        }

        if ((width - root_width) > max_bucket_depth) {
            bucket_size++;
        }
    }

    return bucket_size;
}

test_data_lpm_core::test_data_lpm_core(const lpm_core_sptr& core)
    : m_l2_buckets(get_buckets(core->get_tree(), lpm_level_e::L2)),
      m_l1_buckets(get_buckets(core->get_tree(), lpm_level_e::L1)),
      m_tcam_entries(get_entries(core->get_tcam()))
{
}

bool
test_data_lpm_core::operator==(const test_data_lpm_core& other) const
{
    if (m_l2_buckets == other.m_l2_buckets && m_l1_buckets == other.m_l1_buckets && m_tcam_entries == other.m_tcam_entries) {
        return true;
    }

    if (m_l2_buckets != other.m_l2_buckets) {
        printf("L2 buckets don't match\n");
    }

    if (m_l1_buckets != other.m_l1_buckets) {
        printf("L1 buckets don't match\n");
    }

    if (m_tcam_entries != other.m_tcam_entries) {
        printf("TCAM entries don't match\n");
    }

    return false;
}

uint64_t
rand_uint64()
{
    uint64_t a = rand();
    a <<= 32;
    a += rand();

    return a;
}

lpm_key_t
rand_key()
{
    return rand_key(BITS_IN_IPV4_ADDRESS);
}

lpm_key_t
rand_key(size_t max_width)
{
    size_t width = rand() % max_width + 1;
    uint64_t rand_value = rand_uint64();
    lpm_key_t key(rand_value, width);

    key = key >> (key.get_width() - width);

    bool entry_type = (rand() % 10) == 0;
    key.set_bit(key.get_width() - 1, entry_type);

    return key;
}

lpm_key_t
rand_key_not_null()
{
    return rand_key_not_null(BITS_IN_IPV4_ADDRESS);
}

lpm_key_t
rand_key_not_null(size_t max_width)
{
    lpm_key_t key = rand_key(max_width);
    while (key.is_null()) {
        key = rand_key(max_width);
    }

    return key;
}

lpm_payload_t
rand_payload()
{
    return rand_payload(LPM_PAYLOAD_WIDTH);
}

lpm_payload_t
rand_payload(size_t width)
{
    dassert_crit(width <= 32);
    lpm_payload_t payload = rand() & bit_utils::ones(width);
    return payload;
}

lpm_payload_t
rand_payload_not_null()
{
    return rand_payload_not_null(LPM_PAYLOAD_WIDTH);
}

lpm_payload_t
rand_payload_not_null(size_t max_width)
{
    lpm_payload_t payload = rand_payload(max_width);
    while (payload == INVALID_PAYLOAD) {
        payload = rand_payload(max_width);
    }

    return payload;
}

lpm_action_desc_vec_t
read_entries(const std::string& given_filename, size_t num_of_entries, bool ipv4_and_ipv6)
{
    lpm_read_entries r(ipv4_and_ipv6);
    lpm_action_desc_vec_t actions = r.read_entries(given_filename, num_of_entries);

    if (shuffle_entries) {
        sort(actions.begin(), actions.end(), action_less_operator());
        actions.erase(unique(actions.begin(), actions.end(), action_equal_operator()), actions.end());
    }

    for (auto& action : actions) {
        action.m_action = silicon_one::lpm_action_e::INSERT;
        if (shuffle_entries) {
            action.m_payload = rand_payload_not_null();
        }
    }

    if (shuffle_entries) {
        random_shuffle(actions.begin(), actions.end());
    }

    return actions;
}

lpm_implementation_desc_vec
convert_api_to_imp_actions(const lpm_action_desc_vec_t& api_actions)
{
    lpm_implementation_desc_vec imp_actions;
    for (const lpm_action_desc& desc : api_actions) {
        imp_actions.push_back(lpm_action_desc_internal(desc));
    }

    return imp_actions;
}

test_data_lpm_buckets_vec_t
get_buckets(const bucketing_tree& tree, lpm_level_e level)
{
    test_data_lpm_buckets_vec_t test_data_buckets;
    map_alloc<size_t, size_t> bucket_index_to_test_data_index_map;
    set_alloc<const lpm_bucket*> bucket_set;
    bucketing_tree::bucketing_tree_level_parameters parameters = tree.get_parameters(level);
    size_t max_bucket_depth = tree.get_max_bucket_depth();

    for (const auto& bucket : tree.get_buckets(level)) {
        if (!bucket || bucket->empty()) {
            continue;
        }
        size_t index = bucket->get_hw_index();
        bucket_set.insert(bucket.get());

        // TODO: all this comparison is not good. Need to compare double and single entries.
        size_t root_width = bucket->get_root_width();
        lpm_bucket::occupancy_data bucket_data = lpm_bucket_occupancy_utils::get_bucket_occupancy(
            bucket.get(), root_width + max_bucket_depth, parameters.support_double_entries);

        bucket_index_to_test_data_index_map.insert(std::make_pair(index, test_data_buckets.size()));
        test_data_lpm_bucket test_data_bucket(*bucket.get());
        test_data_buckets.push_back(test_data_bucket);
        size_t test_data_size_bucket = test_data_bucket.size();

        if ((bucket_data.single_entries + bucket_data.double_entries * 2) != test_data_size_bucket) {
            printf("bucket=%d, bucket size=%lu, test data bucket size=%lu\n",
                   bucket->get_hw_index(),
                   bucket_data.total_entries,
                   test_data_size_bucket);

            return test_data_lpm_buckets_vec_t();
        }
    }

    for (test_data_lpm_buckets_vec_t::iterator it = test_data_buckets.begin(); it != test_data_buckets.end(); it++) {
    }

    return test_data_buckets;
}

test_data_lpm_entries_vec_t
get_entries(const test_data_lpm_buckets_vec_t& buckets)
{
    test_data_lpm_entries_set_t entries_set;

    for (const auto& test_data_lpm_bucket : buckets) {
        const test_data_lpm_entries_vec_t& bucket_entries(test_data_lpm_bucket.m_entries);
        entries_set.insert(bucket_entries.begin(), bucket_entries.end());
    }

    return test_data_lpm_entries_vec_t(entries_set.begin(), entries_set.end());
}

test_data_lpm_entries_vec_t
get_entries(const lpm_core_tcam& tcam)
{
    test_data_lpm_entries_vec_t test_data_entries;
    for (auto entry : tcam.get_entries()) {
        test_data_entries.push_back(test_data_lpm_entry(entry.key, entry.payload));
    }

    return test_data_entries;
}

test_data_lpm_entries_vec_t
get_entries(const bucketing_tree& tree)
{
    test_data_lpm_buckets_vec_t buckets(get_buckets(tree, lpm_level_e::L2));
    return get_entries(buckets);
}

void
print_entries(const test_data_lpm_entries_set_t& entries)
{
    int i = 0;
    for (const auto& test_data_lpm_entry : entries) {
        printf("  Entry: index: %d, key: %s, payload: %u\n",
               i++,
               test_data_lpm_entry.m_key.to_string().c_str(),
               test_data_lpm_entry.m_payload);
    }
}

void
print_entries(const test_data_lpm_entries_vec_t& entries)
{
    int i = 0;
    for (const auto& test_data_lpm_entry : entries) {
        printf("  Entry: index: %d, key: %s, payload: %u\n",
               i++,
               test_data_lpm_entry.m_key.to_string().c_str(),
               test_data_lpm_entry.m_payload);
    }
}

void
print_buckets(const test_data_lpm_buckets_vec_t& buckets, bool print_entries)
{
    for (const auto& test_data_bucket : buckets) {
        const test_data_lpm_entries_vec_t& entries(test_data_bucket.m_entries);
        printf("  Bucket: index: %lu, root: %s, size: %lu, default payload: %u\n",
               test_data_bucket.m_index,
               test_data_bucket.m_root.to_string().c_str(),
               entries.size(),
               test_data_bucket.m_default_payload);

        if (print_entries) {
            for (const auto& test_data_lpm_entry : entries) {
                printf("    Entry: key: %s, payload: %u\n",
                       test_data_lpm_entry.m_key.to_string().c_str(),
                       test_data_lpm_entry.m_payload);
            }
        }
    }
}

void
create_tree_group_roots(const bucketing_tree_sptr& tree,
                        const lpm_core_sptr& core,
                        lpm_action_desc_internal_set& out_default_group_roots)
{
    // 0 - IPv4 and 1 - IPv6
    out_default_group_roots.clear();
    lpm_implementation_desc_vec actions;
    size_t core_id = (core) ? core->get_id() : 0;

    for (size_t idx : {0, 1}) {
        // Default group
        lpm_key_t default_key(idx /*prefix*/, 1);
        lpm_action_desc_internal add_group_action
            = lpm_action_desc_internal(lpm_implementation_action_e::ADD_GROUP_ROOT, default_key, trap_destination);
        add_group_action.m_group_id = idx;
        add_group_action.m_core_id = core_id;
        actions.push_back(add_group_action);
    }

    size_t failed_core;
    lpm_implementation_desc_vec_levels_cores cores_actions;
    la_status status = tree->update(actions, cores_actions, failed_core);
    ASSERT_EQ(LA_STATUS_SUCCESS, status);

    if (core != nullptr) {
        status = core->update_tcam(cores_actions[core_id][LEVEL1]);
        ASSERT_EQ(LA_STATUS_SUCCESS, status) << "TCAM update failed with status: " << status.message();

        status = core->commit_hw_updates(cores_actions[core_id]);
        ASSERT_EQ(LA_STATUS_SUCCESS, status) << "commit_hw_updates failed with status: " << status.message();
    }

    tree->commit();

    std::copy(actions.begin(), actions.end(), std::inserter(out_default_group_roots, out_default_group_roots.end()));
}

} // namespace silicon_one

//-----------------------------------------------------------------------------------------------------
void
usage(const char* prog)
{
    fprintf(stderr, "Usage: %s [gtest parameters] [test parameters]\n", prog);

    fprintf(stderr, "\ngtest parameters:\n");
    fprintf(stderr, "  Must start with --. For more information use: --help\n");
    fprintf(stderr, "  For LPM tree tests use:         --gtest_filter=LpmTreeTest.*\n");
    fprintf(stderr, "  For LPM core tests use:         --gtest_filter=LpmCoreTest.*\n");
    fprintf(stderr, "  For LPM distribution tests use: --gtest_filter=LpmTest.*\n");
    fprintf(stderr, "  For LPM insertion tests use:    --gtest_filter=LpmInsertionTest.*\n");
    fprintf(stderr, "  For scaled down LPM tests use:  --gtest_filter=LpmScaledDownTest.*\n");

    fprintf(stderr, "\ntest parameters information:\n");
    fprintf(stderr, "  Must be in a format <param>=<value>\n\n");
    fprintf(stderr, "  num_of_cores                  - Number of LPM cores.\n");
    fprintf(stderr, "  num_of_entries                - Number of entries to insert to tree, less than 600000.\n");
    fprintf(stderr, "  l2_max_bucket_size            - Maximum size of a single L2 bucket.\n");
    fprintf(stderr, "  l2_double_bucket_size         - Size of a pair of L2 buckets. Should be greater than l2_max_bucket_size\n");
    fprintf(stderr, "                                  but smaller than twice l2_max_bucket_size.\n");
    fprintf(stderr, "  l2_max_number_of_sram_buckets - Maximal number of L2 buckets in on-die SRAM\n");
    fprintf(stderr, "  l2_max_number_of_hbm_buckets  - Maximal number of L2 buckets in HBM\n");
    fprintf(stderr, "  l1_max_bucket_size            - Maximum size of a single L1 bucket.\n");
    fprintf(stderr, "  l1_double_bucket_size         - Size of a pair of L1 buckets. Should be greater than l1_max_bucket_size\n");
    fprintf(stderr, "                                  but smaller than twice l1_max_bucket_size.\n");
    fprintf(stderr, "  l1_max_number_of_buckets      - Maximal number of L1 buckets\n");
    fprintf(stderr, "  file                          - File to take inputs from.\n");
    fprintf(stderr, "  occupancy_file                - File to take inputs from for occupancy test.\n");
    fprintf(stderr, "  random_seed                   - Random seed for all tests.\n");
    fprintf(stderr, "  enable_hbm                    - Enable HBM (applicable to LpmActionsTest only).\n");
    fprintf(stderr, "  shuffle_entries               - Shuffle order of entries programming.\n");
    fprintf(stderr, "  rebalance_start_threshold     - Rebalance start fairness threshold\n");
    fprintf(stderr, "  rebalance_end_threshold       - Rebalance end fairness threshold\n");
    fprintf(stderr, "  rebalance_interval            - Rebalance interval\n");
}
//-----------------------------------------------------------------------------------------------------

bool
parse_args(int argc, char** argv)
{
    for (int idx = 1; idx < argc; ++idx) {
        std::string arg(argv[idx]);
        if (arg.find("--") == 0) {
            // this is gtest argument
            continue;
        }

        size_t delim_idx = arg.find("=");
        if (delim_idx == std::string::npos) {
            fprintf(stderr, "-E- Received illegal argument format %s. Should be <arg>=<val>. Abort...\n", arg.c_str());
            return false;
        }

        std::string arg_name = arg.substr(0, delim_idx);
        std::string arg_val = arg.substr(delim_idx + 1, arg.length());
        if (arg_name == "num_of_entries") {
            num_of_entries = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "l2_max_bucket_size") {
            l2_max_bucket_size = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "l2_double_bucket_size") {
            l2_double_bucket_size = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "l2_max_number_of_sram_buckets") {
            l2_max_number_of_sram_buckets = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "l2_max_number_of_hbm_buckets") {
            l2_max_number_of_hbm_buckets = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "l1_max_bucket_size") {
            l1_max_bucket_size = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "l1_double_bucket_size") {
            l1_double_bucket_size = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "l1_max_number_of_buckets") {
            l1_max_number_of_buckets = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "num_of_cores") {
            num_of_cores = std::stoull(arg_val, nullptr, 10);

        } else if (arg_name == "random_seed") {
            random_seed = std::stoull(arg_val, nullptr, 10);
        } else if (arg_name == "enable_hbm") {
            enable_hbm = (arg_val == "true" ? true : false);
        } else if (arg_name == "verbose") {
            verbose = (arg_val == "true" ? true : false);
        } else if (arg_name == "number_lines") {
            number_lines = std::stoull(arg_val, nullptr, 10);
        } else if (arg_name == "rebalance_interval") {
            rebalance_interval = std::stoull(arg_val, nullptr, 10);
        } else if (arg_name == "shuffle_entries") {
            shuffle_entries = (arg_val == "true" ? true : false);
        } else if (arg_name == "rebalance_start_threshold") {
            rebalance_start_threshold = atof(arg_val.c_str());
        } else if (arg_name == "rebalance_end_threshold") {
            rebalance_end_threshold = atof(arg_val.c_str());

        } else {
            fprintf(stderr, "-E- Received illegal argument %s. Abort...\n", arg.c_str());
            return false;
        }
    }
    return true;
}

//-----------------------------------------------------------------------------------------------------

int
main(int argc, char** argv)
{
    if (std::getenv("IS_VALGRIND")) {
        printf("Valgrind enviroment, gtest is disabled.\n");
        return 0;
    }
    if (!parse_args(argc, argv)) {
        usage(argv[0]);
        return 1;
    }

    if (l2_double_bucket_size < l2_max_bucket_size || l2_double_bucket_size > 2 * l2_max_bucket_size) {
        fprintf(stderr,
                "-E- double bucket size should be greater than max bucket size, but not greater than twice max bucket size\n");
        return 1;
    }

    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
