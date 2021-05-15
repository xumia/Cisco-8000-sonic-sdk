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

#include "common/stopwatch.h"
#include "hw_tables/em_core.h"
#include "hw_tables/em_hasher.h"
#include "gtest/gtest.h"

#include <algorithm>

using namespace silicon_one;
using namespace std;

typedef bit_vector em_key_t;
typedef bit_vector em_payload_t;
typedef em::hash_bv_t em_hash_bv_t;
typedef em::hasher_params em_hasher_params;

em_hash_bv_t rand_em_hash_bv(size_t width);
em_key_t rand_em_key(size_t width);
em_payload_t rand_em_payload(size_t width);
em_hasher_params rand_em_hasher_params(size_t key_width);
physical_em create_dummy_physical_em(size_t num_of_banks,
                                     size_t num_of_bank_entries,
                                     size_t num_of_cam_entries,
                                     size_t entry_width,
                                     const vector<size_t>& key_widths);

// EM core tester
class EmCoreTest : public ::testing::Test
{
protected:
    enum {
        NUM_OF_BANKS = 4,
        NUM_OF_BANK_ENTRIES = 4096,
        NUM_OF_CAM_ENTRIES = 32,
        ENTRY_WIDTH = 100,
        MOVING_DEPTH = 3,
        KEY_WIDTH1 = 80,
        KEY_WIDTH2 = 40
    };

    // Set up test case: load core with entries.
    static void SetUpTestCase()
    {
        uint64_t seed = time(0);
        srand(seed);

        vector<size_t> key_widths{KEY_WIDTH1, KEY_WIDTH2};
        physical_em em = create_dummy_physical_em(NUM_OF_BANKS, NUM_OF_BANK_ENTRIES, NUM_OF_CAM_ENTRIES, ENTRY_WIDTH, key_widths);
        s_core = new em_core(nullptr /*no writes to physical device*/, em, MOVING_DEPTH);

        // Random entries (check for duplicates).
        size_t max_entries_in_em = NUM_OF_BANKS * NUM_OF_BANK_ENTRIES + NUM_OF_CAM_ENTRIES;
        set<uint64_t> keys;
        vector<std::pair<em_key_t, em_payload_t> > entries_to_insert;
        for (size_t i = 0; i < max_entries_in_em; i++) {
            size_t key_width = (size_t)((rand() % 2) ? KEY_WIDTH1 : KEY_WIDTH2);
            size_t payload_width = ENTRY_WIDTH - key_width;

            em_payload_t payload(rand_em_payload(payload_width));
            em_key_t key(rand_em_key(key_width));
            while (keys.count(key.get_value()) != 0) {
                em_key_t key(rand_em_key(key_width));
            }
            keys.insert(key.get_value());
            entries_to_insert.push_back(make_pair(key, payload));
        }

        // Insert random entries, measure time.
        size_t fast_entries_inserted = 0;
        size_t nine_tenths_ous_of_max = max_entries_in_em * 9 / 10;
        stopwatch stopwatch;
        stopwatch.start();
        for (fast_entries_inserted = 0; fast_entries_inserted < nine_tenths_ous_of_max; fast_entries_inserted++) {
            if (fast_entries_inserted % 10000 == 0) {
                printf("             Insertion #%lu\n", fast_entries_inserted);
            }

            const em_key_t& key(entries_to_insert[fast_entries_inserted].first);
            const em_payload_t& payload(entries_to_insert[fast_entries_inserted].second);

            la_status status = s_core->insert(key, payload);

            if (status != LA_STATUS_SUCCESS) {
                break;
            }
        }
        stopwatch.stop();

        uint64_t fast_time_ms = stopwatch.get_interval_time(stopwatch::time_unit_e::MS);
        uint64_t fast_time_ns = stopwatch.get_interval_time(stopwatch::time_unit_e::NS);
        uint64_t fast_ips = fast_entries_inserted * 1000 * 1000 * 1000 / fast_time_ns;

        size_t entries_inserted;
        stopwatch.start();
        for (entries_inserted = fast_entries_inserted; entries_inserted < max_entries_in_em; entries_inserted++) {
            if (entries_inserted % 10000 == 0) {
                printf("             Insertion #%lu\n", entries_inserted);
            }

            const em_key_t& key(entries_to_insert[entries_inserted].first);
            const em_payload_t& payload(entries_to_insert[entries_inserted].second);

            la_status status = s_core->insert(key, payload);

            if (status != LA_STATUS_SUCCESS) {
                break;
            }
        }
        stopwatch.stop();

        size_t slow_entries_inserted = entries_inserted - fast_entries_inserted;
        uint64_t slow_time_ms = stopwatch.get_interval_time(stopwatch::time_unit_e::MS);
        uint64_t slow_time_ns = stopwatch.get_interval_time(stopwatch::time_unit_e::NS);
        uint64_t slow_ips = slow_entries_inserted * 1000 * 1000 * 1000 / slow_time_ns;

        uint64_t time_ms = slow_time_ms + fast_time_ms;
        uint64_t time_ns = slow_time_ns + fast_time_ns;
        uint64_t ips = entries_inserted * 1000 * 1000 * 1000 / time_ns;

        float util = 100.0 * entries_inserted / max_entries_in_em;
        printf("             Done inserting %lu entries (max capacity = %lu, utilization = %.2f%%) in %lu ms (%lu insertions per "
               "second) with seed %lu\n",
               entries_inserted,
               max_entries_in_em,
               util,
               time_ms,
               ips,
               seed);
        printf("             First 90%% of entries (%lu entries) we're inserted in %lu ms (%lu insertion per second)\n",
               fast_entries_inserted,
               fast_time_ms,
               fast_ips);
        printf("             The remaining entries (%lu entries) we're inserted in %lu ms (%lu insertion per second)\n",
               slow_entries_inserted,
               slow_time_ms,
               slow_ips);
        printf("             EM core params: NUM_OF_BANKS = %d, NUM_OF_BANK_ENTRIES = %d, NUM_OF_CAM_ENTRIES = %d, MOVING_DEPTH = "
               "%d\n",
               NUM_OF_BANKS,
               NUM_OF_BANK_ENTRIES,
               NUM_OF_CAM_ENTRIES,
               MOVING_DEPTH);
        ASSERT_GE(entries_inserted, (size_t)(NUM_OF_BANKS * NUM_OF_BANK_ENTRIES * 9 / 10));

        // Track entries in EM.
        for (size_t i = 0; i < entries_inserted; i++) {
            const em_key_t& key(entries_to_insert[i].first);
            const em_payload_t& payload(entries_to_insert[i].second);

            s_entries_in_core.push_back(make_pair(key, payload));
        }
    }

    // Tear down case: remove all entries from core.
    static void TearDownTestCase()
    {
        random_shuffle(s_entries_in_core.begin(), s_entries_in_core.end());
        for (const auto& entry : s_entries_in_core) {
            const em_key_t& key(entry.first);

            ASSERT_EQ(LA_STATUS_SUCCESS, s_core->erase(key));
        }

        delete s_core;
    }

    // Lookup every entry in EM core.
    la_status lookup_test(const vector<pair<em_key_t, em_payload_t> >& entries = s_entries_in_core,
                          const em_core& core = *s_core) const
    {
        size_t count = 0;
        for (const auto& entry : entries) {
            const em_key_t& key(entry.first);
            const em_payload_t& payload(entry.second);

            em_payload_t lookupped_payload;
            la_status status = core.lookup(key, lookupped_payload);
            if (status != LA_STATUS_SUCCESS) {
                printf("Lookup failed with status %d on iteration %lu. Key = %s\n", status.value(), count, key.to_string().c_str());
                return status;
            }

            if (payload != lookupped_payload) {
                printf("Lookup returned payload is different then expected on iteration %lu."
                       "Key = %s, payload = %s, lookupped payload = %s\n",
                       count,
                       key.to_string().c_str(),
                       payload.to_string().c_str(),
                       lookupped_payload.to_string().c_str());
                return LA_STATUS_EUNKNOWN;
            }

            count++;
        }

        return LA_STATUS_SUCCESS;
    }

    static em_core* s_core;                                         // EM core.
    static vector<pair<em_key_t, em_payload_t> > s_entries_in_core; // Entries in core.
};

em_core* EmCoreTest::s_core(nullptr);
vector<pair<em_key_t, em_payload_t> > EmCoreTest::s_entries_in_core;

// Lookup every entry in EM core.
TEST_F(EmCoreTest, LookupTest)
{
    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test());
}

// Invalid inputs fails.
TEST_F(EmCoreTest, InvalidInputsTest)
{
    // Key is invalid.
    for (size_t i = 0; i < 100; i++) {

        em_key_t key = em_key_t(rand());
        while (key.get_width() == KEY_WIDTH1 || key.get_width() == KEY_WIDTH2) {
            key = em_key_t(rand());
        }

        size_t action = rand() % 4;
        switch (action) {
        case 0:
            ASSERT_EQ(LA_STATUS_EINVAL, s_core->insert(key, em_payload_t())) << i;
            break;
        case 1:
            ASSERT_EQ(LA_STATUS_EINVAL, s_core->erase(key)) << i;
            break;
        case 2:
            ASSERT_EQ(LA_STATUS_EINVAL, s_core->update(key, em_payload_t())) << i;
            break;
        case 3:
            em_payload_t dummy;
            ASSERT_EQ(LA_STATUS_EINVAL, s_core->lookup(key, dummy)) << i;
            break;
        }
    }

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test());

    // Key is valid but together with payload they aren't valid.
    for (size_t i = 0; i < 100; i++) {

        size_t width = (rand() % 2) ? KEY_WIDTH1 : KEY_WIDTH2;
        em_key_t key = em_key_t(rand(), width).bits_from_msb(0, width);
        em_payload_t payload = em_payload_t(rand());

        while (key.get_width() + payload.get_width() == ENTRY_WIDTH) {
            payload = em_payload_t(rand());
        }

        size_t action = rand() % 2;
        switch (action) {
        case 0:
            ASSERT_EQ(LA_STATUS_EINVAL, s_core->insert(key, payload)) << i;
            break;
        case 1:
            ASSERT_EQ(LA_STATUS_EINVAL, s_core->update(key, payload)) << i;
            break;
        }
    }

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test());
}

// Not found or exist fails
TEST_F(EmCoreTest, NotFoundAndExistTest)
{
    set<size_t> keys;
    for (const auto& entry : s_entries_in_core) {
        keys.insert(entry.first.get_value());
    }

    // Randomize valid entries, make sure removing/updating/lookupping not existing entries and inserting existing entries fail.
    for (size_t i = 0; i < 100; i++) {

        size_t key_width = (rand() % 2) ? KEY_WIDTH1 : KEY_WIDTH2;
        size_t payload_width = ENTRY_WIDTH - key_width;

        em_key_t key = em_key_t(rand(), key_width).bits_from_msb(0, key_width);
        em_payload_t payload = em_payload_t(rand(), payload_width).bits_from_msb(0, payload_width);

        if (keys.count(key.get_value()) != 0) {
            ASSERT_EQ(LA_STATUS_EEXIST, s_core->insert(key, payload)) << i;
        } else {
            size_t action = rand() % 3;
            switch (action) {
            case 0:
                ASSERT_EQ(LA_STATUS_ENOTFOUND, s_core->erase(key)) << i;
                break;
            case 1:
                ASSERT_EQ(LA_STATUS_ENOTFOUND, s_core->update(key, payload)) << i;
                break;
            case 2:
                em_payload_t dummy;
                ASSERT_EQ(LA_STATUS_ENOTFOUND, s_core->lookup(key, dummy)) << i;
                break;
            }
        }
    }

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test());
}

TEST_F(EmCoreTest, HasherEncryptDecryptTest)
{
    size_t key_width = 320;

    em_hasher h(key_width, rand_em_hasher_params(key_width));

    em::key_t key(rand_em_key(key_width));
    for (size_t iter = 0; iter < 100; iter++) {
        em::key_t encrypted_key = h.encrypt(key);
        em::key_t decrypted_key = h.decrypt(encrypted_key);

        ASSERT_EQ(decrypted_key, key) << iter;

        key = encrypted_key;
    }
}

// Make sure entries insertion fail when no free slots for them nor movings possible.
// Make sure entries insertion succeeds when they can be inserted into free slots.
TEST_F(EmCoreTest, FailAndSucceedTest)
{
    // ****** NOTE: THIS TEST (and the next two) WOULD FAIL IF HASHERS CONSTRUCTION ARE CHANGED.
    // ******       It depends on randomization (with constant seed) of hashers params.
    // ******       These params would eventually be constants.
    // ******       If the randomization changes or constant are given, this test should be updated.

    const size_t entry_width = 40;
    const size_t key_width1 = 16;
    const size_t key_width2 = 20;

    logger::instance().set_logging_level(
        silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, silicon_one::la_logger_level_e::INFO);

    vector<size_t> key_widths{key_width2, key_width1};
    physical_em em = create_dummy_physical_em(2, 4 /* num of bank entries */, 1 /* num of cam entries */, entry_width, key_widths);

    em_core core(nullptr /*no writes to physical device*/, em, 0 /* moving depth */);

    // ****** The randomized values are (if test fails first check that these haven't changed):
    //
    //                                    long div | long init | short div | short init |   rc5 parameter
    //        key width #1 (4): bank #0: (  11101  |   1100    |    11     |     1      |  11  11  11  11  )
    //                          bank #1: (  10111  |   1000    |    11     |     1      |  10  11  10  10  )
    //        key width #2 (6): bank #0: ( 1000011 |  111110   |    101    |     11     |  100 100 101 101 )
    //                          bank #1: ( 1111111 |  110111   |    101    |     11     |  110 100 110 101 )

    vector<pair<em_key_t, em_payload_t> > entries;

    vector<size_t> initial_keys = {1, 3, 8, 10, 11};
    vector<size_t> initial_payloads = initial_keys;
    for (size_t i = 0; i < initial_keys.size(); i++) {
        em_key_t key(initial_keys[i], key_width1);
        em_payload_t payload(initial_payloads[i], entry_width - key_width1);

        ASSERT_EQ(LA_STATUS_SUCCESS, core.insert(key, payload)) << i;
        entries.push_back(make_pair(key, payload));
    }

    // Now our table is filled as follows (results are manually verified):
    //
    //     entry #     0   1   2   3
    //
    //     bank  #0  | - | 3 | 1 | - |
    //     bank  #1  | - | 10| 8 | - |
    //
    //     CAM       | 11|

    // We will now insert keys (with width #2) that should fail cause no free entry exists for them.
    // These are specially chosen keys such that their hash value is taken for each bank, moving depth is 0 and CAM is occupied.
    vector<size_t> keys_to_fail = {2, 5};
    vector<size_t> payloads_to_fail = keys_to_fail;
    for (size_t i = 0; i < keys_to_fail.size(); i++) {
        em_key_t key(keys_to_fail[i], key_width2);
        em_payload_t payload(payloads_to_fail[i], entry_width - key_width2);

        ASSERT_EQ(LA_STATUS_ERESOURCE, core.insert(key, payload)) << i;
    }

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test(entries, core));

    // The table haven't changed since both attempts failed.

    // We will now insert keys (with width #2) that should succed cause free entry exists for them.
    // These are specially chosen keys such that their hash value is not taken for every bank.
    vector<size_t> keys_to_succeed = {4, 6, 10};
    vector<size_t> payloads_to_succeed = keys_to_succeed;
    for (size_t i = 0; i < keys_to_succeed.size(); i++) {
        em_key_t key(keys_to_succeed[i], key_width2);
        em_payload_t payload(payloads_to_succeed[i], entry_width - key_width2);

        ASSERT_EQ(LA_STATUS_SUCCESS, core.insert(key, payload)) << i;
        entries.push_back(make_pair(key, payload));
    }

    // Now our table is filled as follows (results are manually verified):
    //
    //     entry #     0   1   2   3
    //
    //     bank  #0  | 6'| 3 | 1 |10'|
    //     bank  #1  | 4'| 10| 8 | - |
    //
    //     CAM       | 11|

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test(entries, core));
}

TEST_F(EmCoreTest, CollisionHandlingTest)
{
    // ****** NOTE: THIS TEST (and the next) WOULD FAIL IF HASHERS CONSTRUCTION ARE CHANGED.
    // ******       It depends on randomization (with constant seed) of hashers params.
    // ******       These params would eventually be constants.
    // ******       If the randomization changes or constant are given, this test should be updated.

    const size_t entry_width = 40;
    const size_t key_width1 = 16;
    const size_t key_width2 = 20;

    logger::instance().set_logging_level(
        silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, silicon_one::la_logger_level_e::INFO);

    vector<size_t> key_widths{key_width2, key_width1};
    physical_em em = create_dummy_physical_em(2, 4 /* num of bank entries */, 0 /* num of cam entries */, entry_width, key_widths);

    em_core core(nullptr /*no writes to physical device*/, em, 4 /* moving depth */);

    // The arrows in costructor mark the difference between cores in comparison to previous test.

    // ****** The randomized values are idetical to those of the previous test.

    vector<pair<em_key_t, em_payload_t> > entries;

    vector<size_t> initial_keys = {1, 5, 2, 8, 3, 7, 6};
    vector<size_t> initial_payloads = initial_keys;
    for (size_t i = 0; i < initial_keys.size(); i++) {
        em_key_t key(initial_keys[i], key_width1);
        em_payload_t payload(initial_payloads[i], entry_width - key_width1);

        ASSERT_EQ(LA_STATUS_SUCCESS, core.insert(key, payload)) << i;
        entries.push_back(make_pair(key, payload));
    }

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test(entries, core));

    // Now our table is filled as follows (results are manually verified):
    //
    //     entry #     0   1   2   3
    //
    //     bank  #0  | 5 | 8 | 1 | 7 |
    //     bank  #1  | 2 | 3 | - | 6 |
    //

    // This entry should be inserted after moving 5 entries inside EM core.
    const size_t colliding_val = 14;
    em_key_t collision_handling_key(colliding_val, key_width1);
    em_payload_t collision_handling_payload(colliding_val, entry_width - key_width1);

    ASSERT_EQ(LA_STATUS_SUCCESS, core.insert(collision_handling_key, collision_handling_payload));
    entries.push_back(make_pair(collision_handling_key, collision_handling_payload));

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test(entries, core));
}

TEST_F(EmCoreTest, CamScrubbingTest)
{
    // ****** NOTE: THIS TEST WOULD FAIL IF HASHERS CONSTRUCTION ARE CHANGED.
    // ******       It depends on randomization (with constant seed) of hashers params.
    // ******       These params would eventually be constants.
    // ******       If the randomization changes or constant are given, this test should be updated.

    const size_t entry_width = 40;
    const size_t key_width1 = 16;
    const size_t key_width2 = 20;

    logger::instance().set_logging_level(
        silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, silicon_one::la_logger_level_e::INFO);

    vector<size_t> key_widths{key_width2, key_width1};
    physical_em em = create_dummy_physical_em(2, 4 /* num of bank entries */, 1 /* num of cam entries */, entry_width, key_widths);

    em_core core(nullptr /*no writes to physical device*/, em, 3 /* moving depth */);

    // The arrows in costructor mark the difference between cores in comparison to previous test.

    // ****** The randomized values are idetical to those of the previous test.

    vector<pair<em_key_t, em_payload_t> > entries;

    vector<size_t> initial_keys = {1, 5, 2, 8, 3, 7, 13, 6, 14};
    vector<size_t> initial_payloads = initial_keys;
    for (size_t i = 0; i < initial_keys.size(); i++) {
        em_key_t key(initial_keys[i], key_width1);
        em_payload_t payload(initial_payloads[i], entry_width - key_width1);
        ASSERT_EQ(LA_STATUS_SUCCESS, core.insert(key, payload)) << i;
        entries.push_back(make_pair(key, payload));
    }

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test(entries, core));
    const size_t entry_idx_to_remove = 4;
    ASSERT_EQ(LA_STATUS_SUCCESS, core.erase(em_key_t(initial_keys[entry_idx_to_remove], key_width1)));
    entries.erase(entries.begin() + entry_idx_to_remove);
    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test(entries, core));

    // Now our table is filled as follows (results are manually verified):
    //
    //     entry #     0   1   2   3
    //
    //     bank  #0  | 5 | 8 | 1 | 7 |
    //     bank  #1  | 2 | 3 | 13| 6 |
    //
    //      CAM      | 14|

    // This entry should be inserted after moving 3 entries inside EM core, making room in CAM.
    size_t colliding_val = 22;
    em_key_t collision_handling_key(colliding_val, key_width1);
    em_payload_t collision_handling_payload(colliding_val, entry_width - key_width1);
    ASSERT_EQ(LA_STATUS_SUCCESS, core.insert(collision_handling_key, collision_handling_payload));
    entries.push_back(make_pair(collision_handling_key, collision_handling_payload));

    ASSERT_EQ(LA_STATUS_SUCCESS, lookup_test(entries, core));
}

bit_vector
rand_bv(size_t width)
{
    bit_vector result(0, width);
    size_t step = bit_utils::bits_to_represent(RAND_MAX);
    for (size_t lsb = 0; lsb < width; lsb += step) {
        size_t msb = min(width - 1, lsb + step - 1);
        result.set_bits(msb, lsb, rand());
    }

    return result.bits(width - 1, 0);
}

em_hash_bv_t
rand_em_hash_bv(size_t width)
{
    em_hash_bv_t result(0, width);
    bit_vector random_bv(rand_bv(width));
    result.set_bits(width - 1, 0, random_bv);

    return result;
}

em_key_t
rand_em_key(size_t width)
{
    em_key_t result(0, width);
    bit_vector random_bv(rand_bv(width));
    result.set_bits(width - 1, 0, random_bv);

    return result;
}

em_payload_t
rand_em_payload(size_t width)
{
    em_payload_t result(0, width);
    bit_vector random_bv(rand_bv(width));
    result.set_bits(width - 1, 0, random_bv);

    return result;
}

em_hasher_params
rand_em_hasher_params(size_t key_width)
{
    size_t bits_to_rep_half_width = bit_utils::bits_to_represent(key_width / 2 - 1);

    bit_vector rc5_parameter(rand_bv(2 * key_width));
    em_hash_bv_t long_div(rand_em_hash_bv(key_width + 1));
    em_hash_bv_t long_init(rand_em_hash_bv(key_width));
    em_hash_bv_t short_div(rand_em_hash_bv(bits_to_rep_half_width + 1));
    em_hash_bv_t short_init(rand_em_hash_bv(bits_to_rep_half_width));

    long_div.set_bits(0, 0, 1);
    long_div.set_bits_from_msb(0, 1, 1);
    short_div.set_bits(0, 0, 1);
    short_div.set_bits_from_msb(0, 1, 1);

    em_hasher_params params{rc5_parameter, long_div, long_init, short_div, short_init};

    return params;
}

physical_em
create_dummy_physical_em(size_t num_of_banks,
                         size_t num_of_bank_entries,
                         size_t num_of_cam_entries,
                         size_t entry_width,
                         const vector<size_t>& key_widths)
{
    physical_em ret;
    ret.key_widths = key_widths;
    dassert_crit(!key_widths.empty());
    ret.banks.resize(num_of_banks);
    ret.bank_size = num_of_bank_entries;
    ret.cam_size = num_of_cam_entries;
    ret.data_width = entry_width;
    size_t primary_key = key_widths[0];
    for (size_t bank_index = 0; bank_index < num_of_banks; bank_index++) {
        ret.banks[bank_index].rc5 = em::generate_pseudo_rc5(primary_key, bank_index);
        ret.banks[bank_index].is_active = true;
    }

    return ret;
}
