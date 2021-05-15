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
#include "lld/ll_device.h"
#include "lld/pacific_tree.h"
#include "test_lpm_types.h"
#include <random>

constexpr size_t CORE_ID = 3;
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

using namespace silicon_one;

class LpmHbmTest : public ::testing::Test
{
protected:
    bool verbose = false;

    static void SetUpTestCase()
    {
        s_ll_device = ll_device::create(0, device_path.c_str());
        s_core_tcam_utils = create_core_tcam_utils(s_ll_device);
    }

    static void TearDownTestCase()
    {
        s_ll_device.reset();
    }

    void SetUp()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::INFO;
        logger::instance().set_logging_level(0, silicon_one::la_logger_component_e::TABLES, logger_level);
        logger::instance().set_logging_level(
            silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, logger_level);

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
    }

    void TearDown()
    {
        s_core.reset();
        s_tree.reset();
    }

    static ll_device_sptr s_ll_device;                  // Low level device.
    static lpm_core_tcam_utils_scptr s_core_tcam_utils; // Core TCAM utils
    bucketing_tree_sptr s_tree;                         // LPM tree.
    lpm_core_sptr s_core;                               // LPM core.
};

ll_device_sptr LpmHbmTest::s_ll_device(nullptr);
lpm_core_tcam_utils_scptr LpmHbmTest::s_core_tcam_utils(nullptr);

// generic test for when we want to reproduce something on LPM
TEST_F(LpmHbmTest, MoveBucketsAround)
{
    if (s_ll_device->is_gibraltar()) {
        return;
    }

    // Insert key to LPM core
    lpm_key_t key(0x1234, 16);
    lpm_payload_t payload = 0xabcde;
    lpm_implementation_desc_vec_levels_cores cores_actions;
    la_status status = s_tree->insert(key, payload, cores_actions);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "Insert failed with status: " << status.message();

    for (size_t core = 0; core < num_of_cores; core++) {
        for (size_t level_idx = 0; level_idx < NUM_LEVELS; level_idx++) {
            if (core != CORE_ID) {
                ASSERT_TRUE(cores_actions[core][level_idx].empty())
                    << "Tree outputs actions to another core(s)" << status.message();
            }
        }
    }

    status = s_core->update_tcam(cores_actions[CORE_ID][LEVEL1]);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "TCAM update failed with status: " << status.message();

    s_tree->commit();
    status = s_core->commit_hw_updates(cores_actions[CORE_ID]);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "commit_hw_updates failed with status: " << status.message();

    // Make sure we can find it
    lpm_key_t result_key;
    lpm_payload_t result_payload;
    status = s_core->lookup(key, result_key, result_payload);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "Lookup after insert failed with status: " << status.message();
    ASSERT_EQ(key, result_key) << "Lookup after insert found wrong key. expected: " << key.to_string()
                               << "  got: " << result_key.to_string();
    ASSERT_EQ(payload, result_payload) << "Lookup after insert found wrong payload. expected: " << payload
                                       << "  got: " << result_payload;

    // Find its L2 bucket
    const lpm_bucket* l2_bucket = s_tree->get_bucket(key, lpm_level_e::L2);
    ASSERT_NE(l2_bucket, nullptr) << "Got null L2 bucket after insert";
    int bucket_idx = l2_bucket->get_hw_index();
    ASSERT_LT(bucket_idx, 4096) << "key was inserted into HBM!"; // SRAM buckets are below 4K.

    // Move its L2 bucket from SRAM to HBM
    status = s_core->move_l2_bucket(bucket_idx, l2_bucket_location_e::HBM);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "Failed to move bucket to HBM with status: " << status.message();

    // Make sure we still can find it
    status = s_core->lookup(key, result_key, result_payload);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "Lookup after moving to HBM failed with status: " << status.message();
    ASSERT_EQ(key, result_key) << "Lookup after moving to HBM found wrong key. expected: " << key.to_string()
                               << "  got: " << result_key.to_string();
    ASSERT_EQ(payload, result_payload) << "Lookup after moving to HBM found wrong payload. expected: " << payload
                                       << "  got: " << result_payload;

    // Find its new bucket
    l2_bucket = s_tree->get_bucket(key, lpm_level_e::L2);
    ASSERT_NE(l2_bucket, nullptr) << "Got null L2 bucket after moving to HBM";
    bucket_idx = l2_bucket->get_hw_index();
    ASSERT_GE(bucket_idx, 4096) << "bucket is still in SRAM!"; // HBM buckets are 4K and above.

    // Move it back to SRAM
    status = s_core->move_l2_bucket(bucket_idx, l2_bucket_location_e::SRAM);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "Failed to move bucket back to SRAM with status: " << status.message();

    // Find its new bucket in SRAM
    l2_bucket = s_tree->get_bucket(key, lpm_level_e::L2);
    ASSERT_NE(l2_bucket, nullptr) << "Got null L2 bucket after moving back to SRAM";
    bucket_idx = l2_bucket->get_hw_index();
    ASSERT_LT(bucket_idx, 4096) << "bucket is still in HBM!"; // SRAM buckets are below 4K.

    // Make sure we still can find it
    status = s_core->lookup(key, result_key, result_payload);
    ASSERT_EQ(LA_STATUS_SUCCESS, status) << "Lookup after moving back to SRAM failed with status: " << status.message();
    ASSERT_EQ(key, result_key) << "Lookup after moving back to SRAM found wrong key. expected: " << key.to_string()
                               << "  got: " << result_key.to_string();
    ASSERT_EQ(payload, result_payload) << "Lookup after moving back to SRAM found wrong payload. expected: " << payload
                                       << "  got: " << result_payload;
}
