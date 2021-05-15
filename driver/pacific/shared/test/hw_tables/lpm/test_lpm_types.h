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

#ifndef __LEABA_TEST_LPM_TYPES_H__
#define __LEABA_TEST_LPM_TYPES_H__

#include "hw_tables/hw_tables_fwd.h"
#include "hw_tables/lpm_types.h"
#include "lpm/lpm_core.h"
#include "gtest/gtest.h"

#include <stdlib.h>

namespace testing
{
namespace internal
{
enum GTestColor { COLOR_DEFAULT, COLOR_RED, COLOR_GREEN, COLOR_YELLOW };

extern void ColoredPrintf(GTestColor color, const char* fmt, ...);
}
}

#define PRINTF(...)                                                                                                                \
    {                                                                                                                              \
        testing::internal::ColoredPrintf(testing::internal::COLOR_GREEN, "[          ] ");                                         \
        testing::internal::ColoredPrintf(testing::internal::COLOR_DEFAULT, __VA_ARGS__);                                           \
    }

// Define types and enums and declare functions used in LPM testing (both tree and core).
// Implement the test helper function (which are used in both tree and core testing).
static inline bool
is_gb()
{
    char* asic = getenv("ASIC");
    return asic && strncmp(asic, "GIBRALTAR", strlen("GIBRALTAR")) == 0;
}

extern std::string filename;                 // File containing input (gzipped).
extern std::string occupancy_filename;       // File containing input (gzipped) for occupancy test.
extern size_t num_of_entries;                // Number of entries read.
extern size_t l2_buckets_per_sram_row;       // Number of buckets in L2 SRAM row.
extern size_t l2_max_bucket_size;            // Maximum bucket size on L2 tree in on-die SRAM.
extern size_t l2_max_hbm_bucket_size;        // Maximum bucket size on L2 tree in HBM.
extern size_t l2_double_bucket_size;         // Double bucket size on L2 tree (used as double_bucket_size for tree test).
extern size_t l2_max_number_of_sram_buckets; // Maximum number of buckets on L2 tree in on-die SRAM (used as
                                             // max_number_of_sram_buckets for tree test).
extern size_t l2_max_number_of_hbm_buckets;  // Maximum number of buckets on L2 tree in HBM (used as max_number_of_hbm_buckets in
                                             // tests which enable HBM).
extern size_t l1_max_bucket_size;            // Maximum bucket size on L1 tree.
extern size_t l1_double_bucket_size;         // Double bucket size on L1 tree.
extern size_t l1_max_number_of_buckets;      // Maximum number of buckets on L1 tree.
extern size_t l1_max_number_of_buckets_extended; // Maximum number of buckets on L1 tree with HBM extension.
extern size_t l1_buckets_per_sram_row;           // Number of buckets in L1 SRAM row.
extern size_t max_tcam_quad_entries;             // Maximum number of long entries in TCAM.
extern size_t max_bucket_depth;                  // Maximum number of bits comparable in a bucket.
extern size_t tcam_num_banksets;                 // Number of banksets in TCAM.
extern size_t tcam_bank_size;                    // Number of rows in single TCAM bank.
extern std::string device_path;                  // Device path.
extern size_t num_of_cores;                      // Number of LPM cores.
extern size_t distributor_size;                  // Number of entries in distributor TCAM.
extern size_t distributor_width;                 // Maximum number of bits comparable in distributor TCAM.
extern size_t number_lines;                      // Maximum number of lines to read from customer table test.
extern uint64_t random_seed;                     // Random seed for all tests.
extern bool enable_hbm;                          // Enable HBM (applicable to LpmActionsTest).
extern bool verbose;                             // Enable debug mode.
extern bool shuffle_entries;                     // Shuffle order of entry prorgramming.
extern double rebalance_start_threshold;         // Rebalance start threshold for the logical_lpm (applicable to LpmActionsTest)
extern double rebalance_end_threshold;           // Rebalance end threshold for the logical_lpm (applicable to LpmActionsTest)
extern size_t rebalance_interval;                // Rebalance interval of the logical_lpm (applicable to LpmActionsTest)
extern size_t trap_destination;                  // Payload of destination to raise a trap.

namespace silicon_one
{

enum {
    LPM_DISTRIBUTOR_SIZE = 128, // Size of the distributor TCAM.
    LPM_DISTRIBUTOR_WIDTH = 80, // Width of the distributor TCAM.

    NUM_OF_L1_BUCKETS = 4 * 1024,                               // Number of buckets on the L1 SRAM.
    NUM_OF_L2_SRAM_BUCKETS = 4096,                              // Number of buckets on the L2 SRAM.
    NUM_OF_L2_HBM_BUCKETS = 16 * 1024 - NUM_OF_L2_SRAM_BUCKETS, // Number of L2 buckets in HBM.
    BITS_IN_IPV4_ADDRESS = 32,                                  // Number of bits in IPv4 address.
    LPM_TCAM_QUAD_ENTRIES = 240,

    // Tree test enums
    NUM_OF_ACTION_CHECK_ERRORS = 100,         // Number of times to check errors.
    NUM_OF_TREE_BULK_ACTIONS = 1000,          // Additional bulk update to tree.
    NUM_OF_TREE_ONE_AT_A_TIME_ACTIONS = 1000, // Additional one at a time updates to tree.

    // Core test enums
    NUM_OF_LOOKUP_CHECKS = 10000,                    // Number of lookup checks.
    NUM_OF_ERROR_CORE_TESTS = 100,                   // Number of times to check errors.
    NUM_OF_CORE_BULK_ACTIONS = 1000,                 // Additional bulk updates to core.
    NUM_OF_CORE_ONE_AT_A_TIME_ACTIONS = 1500,        // Additional one at a time updates to core.
    NUM_OF_ACTIONS_IN_RECOVERY_TEST = 10000,         // Number of entries to load in recovery test.
    NUM_OF_TCAM_ENTRIES_FOR_INSTRUCTION_TEST = 1000, // Number of entries in TCAM instruction test.
    NUM_OF_TCAM_ENTRIES_FOR_OVERFLOW_TEST = 4000,    // Number of entries in TCAM overflow test.
    NUM_OF_LOGICAL_LPM_LOOKUP_TESTS = 100000         // Number of logical LPM lookup checks.
};

// Test data structures

// Test data structure entry
struct test_data_lpm_entry {
    test_data_lpm_entry()
    {
    }

    test_data_lpm_entry(const lpm_key_t& key, lpm_payload_t payload) : m_key(key), m_payload(payload)
    {
    }

    bool operator==(const test_data_lpm_entry& other) const
    {
        return m_key == other.m_key && m_payload == other.m_payload;
    }

    lpm_key_t m_key;
    lpm_payload_t m_payload;
};

typedef vector_alloc<test_data_lpm_entry> test_data_lpm_entries_vec_t;

enum { TEST_DATA_LPM_BUCKET_UNPAIRED_INDEX = SIZE_MAX };

// Test data structure bucket
struct test_data_lpm_bucket {
    test_data_lpm_bucket(const lpm_bucket& bucket);

    bool operator==(const test_data_lpm_bucket& other) const;

    // Returns the number of HW entries, i.e. each double entry is counted as two.
    size_t size() const;

    // Returns the number of logical entries.
    size_t num_of_entries() const
    {
        return m_entries.size();
    }

    bool empty() const
    {
        return m_entries.empty();
    }

    size_t m_index;
    lpm_key_t m_root;
    lpm_payload_t m_default_payload;
    test_data_lpm_entries_vec_t m_entries;
    size_t m_hw_index;
};

// All LPM tree data is represted by this type.
typedef vector_alloc<test_data_lpm_bucket> test_data_lpm_buckets_vec_t;

// Test data structure core
struct test_data_lpm_core {
    test_data_lpm_core(const lpm_core_sptr& core);

    bool operator==(const test_data_lpm_core& other) const;

    test_data_lpm_buckets_vec_t m_l2_buckets;
    test_data_lpm_buckets_vec_t m_l1_buckets;
    test_data_lpm_entries_vec_t m_tcam_entries;
};

// Less operator for actions based on their key. Required for action set.
struct action_less_operator {
    bool operator()(const lpm_action_desc& laction, const lpm_action_desc& raction) const
    {
        return key_less_operator()(laction.m_key, raction.m_key);
    }
};

// Equal operator for actions based on their key. Required for unique function used to remove duplicates on read_entries.
struct action_equal_operator {
    bool operator()(const lpm_action_desc& laction, const lpm_action_desc& raction) const
    {
        return (laction.m_key == raction.m_key);
    }
};

// Less operator for entries based on their key. Required for test_data entry set.
struct entry_less_operator {
    bool operator()(const test_data_lpm_entry& lentry, const test_data_lpm_entry& rentry) const
    {
        return key_less_operator()(lentry.m_key, rentry.m_key);
    }
};

// Less operator for entries based on their key. Required for test_data entry set.
struct action_desc_internal_less_operator {
    bool operator()(const lpm_action_desc_internal& lentry, const lpm_action_desc_internal& rentry) const
    {
        return key_less_operator()(lentry.m_key, rentry.m_key);
    }
};

typedef set_alloc<lpm_action_desc, action_less_operator> lpm_action_desc_set_t;
typedef set_alloc<lpm_key_t, key_less_operator> key_set_t;
typedef set_alloc<test_data_lpm_entry, entry_less_operator> test_data_lpm_entries_set_t;
typedef set_alloc<lpm_action_desc_internal, action_desc_internal_less_operator> lpm_action_desc_internal_set;
typedef map_alloc<size_t, test_data_lpm_entry> test_data_lpm_entries_map_t;

// Load a given number of entries and randomize thier order according to random_seed.
lpm_action_desc_vec_t read_entries(const std::string& given_filename, size_t num_of_entries, bool ipv4_and_ipv6);

// Read entries and than convert to internal entries. Used to tests internal class.
lpm_implementation_desc_vec convert_api_to_imp_actions(const lpm_action_desc_vec_t& api_actions);

// Generate random uint64_t.
uint64_t rand_uint64();

// Generate random key and payload with width up to givan maximum (default is IPv4 length).
lpm_key_t rand_key(size_t max_width);
lpm_key_t rand_key();
lpm_payload_t rand_payload(size_t max_width);
lpm_payload_t rand_payload();

// Generate random key and payload which is not NULL (default is IPv4 length).
lpm_key_t rand_key_not_null(size_t max_width);
lpm_key_t rand_key_not_null();
lpm_payload_t rand_payload_not_null(size_t max_width);
lpm_payload_t rand_payload_not_null();

// Get test data buckets vector out of an LPM tree.
test_data_lpm_buckets_vec_t get_buckets(const bucketing_tree& tree, lpm_level_e level);

// Get test data entries vector out of a buckets vector.
test_data_lpm_entries_vec_t get_entries(const test_data_lpm_buckets_vec_t& buckets);

// Get test data entries vector out of an LPM tree.
test_data_lpm_entries_vec_t get_entries(const bucketing_tree& tree);

// Get test data entries vector out of an LPM TCAM.
test_data_lpm_entries_vec_t get_entries(const lpm_core_tcam& tcam);

// Print an entries set.
void print_entries(const test_data_lpm_entries_set_t& entries);

// Print an entries vector.
void print_entries(const test_data_lpm_entries_vec_t& entries);

// Print a vector of test_data buckets, print thier entries if specified.
void print_buckets(const test_data_lpm_buckets_vec_t& buckets, bool print_entries);

// Creates a default group roots for the tree.
void create_tree_group_roots(const bucketing_tree_sptr& tree,
                             const lpm_core_sptr& core,
                             lpm_action_desc_internal_set& out_default_group_roots);

} // namespace silicon_one

#endif
