// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "common/logger.h"
#include "lpm/lpm_core_tcam.h"
#include "lpm/lpm_core_tcam_akpg.h"
#include "lpm/lpm_core_tcam_pacific_gb.h"
#include "lpm/lpm_core_tcam_utils_akpg.h"
#include "lpm/lpm_core_tcam_utils_base.h"
#include "lpm/lpm_core_tcam_utils_pacific_gb.h"
#include "test_lpm_types.h"
#include "gtest/gtest.h"

using namespace silicon_one;

class LpmCoreTcamTest : public testing::TestWithParam<bool>
{
protected:
    enum { NUM_BANKS = 4 };

    void SetUp()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::ERROR;
        logger::instance().set_logging_level(
            silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, logger_level);
    }

    void TearDown()
    {
        if (s_tcam != nullptr) {
            delete s_tcam;
            s_tcam = nullptr;
        }
    }

    size_t location_to_flat_row(const tcam_cell_location& location)
    {
        size_t flat_row = location.bankset * s_bankset_size + location.bank * s_num_cells_in_bank + location.cell;
        return flat_row;
    }

    size_t get_cells_for_key(const lpm_key_t& key)
    {
        logical_tcam_type_e logical_tcam = m_tcam_utils->get_logical_tcam_type_of_key(key);
        size_t num_cells = lpm_core_tcam_utils_base::get_num_cells_in_block_type(logical_tcam);
        return num_cells;
    }

    void apply_instructions(vector_alloc<lpm_key_payload>& core_tcam_model, lpm_core_tcam::hardware_instruction_vec& instructions)
    {

        size_t tcam_size = core_tcam_model.size();
        ASSERT_EQ(tcam_size, s_bankset_size * s_num_banksets);

        for (const auto& instruction : instructions) {
            switch (instruction.instruction_type) {

            case lpm_core_tcam::hardware_instruction::type_e::INSERT: {
                auto instruction_data = boost::get<lpm_core_tcam::hardware_instruction::insert>(instruction.instruction_data);
                size_t num_cells_per_block = get_cells_for_key(instruction_data.key);
                size_t flat_row = location_to_flat_row(instruction_data.location);

                for (size_t bank = 0; bank < num_cells_per_block; bank++) {
                    ASSERT_EQ(core_tcam_model[flat_row + bank * s_num_cells_in_bank].key, lpm_key_t());
                }

                core_tcam_model[flat_row] = lpm_key_payload{.key = instruction_data.key, .payload = instruction_data.payload};
                break;
            }

            case lpm_core_tcam::hardware_instruction::type_e::MODIFY_PAYLOAD: {
                auto instruction_data
                    = boost::get<lpm_core_tcam::hardware_instruction::modify_payload>(instruction.instruction_data);
                size_t num_cells_per_block = get_cells_for_key(instruction_data.key);
                size_t flat_row = location_to_flat_row(instruction_data.location);

                for (size_t bank = 1; bank < num_cells_per_block; bank++) {
                    ASSERT_EQ(core_tcam_model[flat_row + bank * s_num_cells_in_bank].key, lpm_key_t());
                }
                ASSERT_EQ(core_tcam_model[flat_row].key, instruction_data.key);

                core_tcam_model[flat_row] = lpm_key_payload{.key = instruction_data.key, .payload = instruction_data.payload};
                break;
            }

            case lpm_core_tcam::hardware_instruction::type_e::REMOVE: {
                auto instruction_data = boost::get<lpm_core_tcam::hardware_instruction::remove>(instruction.instruction_data);
                size_t flat_row = location_to_flat_row(instruction_data.location);
                ASSERT_NE(core_tcam_model[flat_row].key, lpm_key_t());
                core_tcam_model[flat_row] = lpm_key_payload();
                break;
            }

            default:
                ASSERT_TRUE(false);
                break;
            }
        }
    }

    bool lookup_tcam_model(vector_alloc<lpm_key_payload>& core_tcam_model,
                           lpm_key_t lookup_key,
                           lpm_key_t& out_hit_key,
                           lpm_payload_t& out_hit_payload)
    {
        for (size_t cell = 0; cell < core_tcam_model.size(); cell++) {
            if (core_tcam_model[cell].key == lpm_key_t()) {
                continue;
            }
            if (is_contained(core_tcam_model[cell].key, lookup_key)) {
                out_hit_key = core_tcam_model[cell].key;
                out_hit_payload = core_tcam_model[cell].payload;
                return true;
            }
        }

        return false;
    }

    void dump_tcam_model(vector_alloc<lpm_key_payload>& core_tcam_model)
    {
        printf("TCAM model dump:\n");
        for (size_t cell = 0; cell < core_tcam_model.size(); cell++) {
            if (core_tcam_model[cell].key != lpm_key_t()) {
                printf("cell=%zu:  key=0x%s/%zu  payload=%u\n",
                       cell,
                       core_tcam_model[cell].key.to_string().c_str(),
                       core_tcam_model[cell].key.get_width(),
                       core_tcam_model[cell].payload);
            }
        }
    }

    void create_lpm_core_tcam(size_t num_banksets, size_t num_cells_per_bank, size_t max_num_quad_blocks)
    {
        bool is_akpg = GetParam();
        s_num_banksets = num_banksets;
        s_num_cells_in_bank = num_cells_per_bank;
        s_bankset_size = num_cells_per_bank * NUM_BANKS;
        s_max_quad_entries = max_num_quad_blocks;
        if (is_akpg) {
            m_tcam_utils = std::make_shared<lpm_core_tcam_utils_akpg>();
            s_tcam = new lpm_core_tcam_akpg(name, num_banksets, num_cells_per_bank, m_tcam_utils);
        } else {
            m_tcam_utils = std::make_shared<lpm_core_tcam_utils_pacific_gb>();
            s_tcam = new lpm_core_tcam_pacific_gb(name, num_banksets, num_cells_per_bank, max_num_quad_blocks, m_tcam_utils);
        }
    }

    std::string name = std::string("Test TCAM");
    static lpm_core_tcam* s_tcam;
    static size_t s_num_banksets;
    static size_t s_num_cells_in_bank;
    static size_t s_bankset_size;
    static size_t s_max_quad_entries; // relevant for Pacific/GB tests
    lpm_core_tcam_utils_scptr m_tcam_utils;
};

lpm_core_tcam* LpmCoreTcamTest::s_tcam(nullptr);
size_t LpmCoreTcamTest::s_num_banksets;
size_t LpmCoreTcamTest::s_num_cells_in_bank;
size_t LpmCoreTcamTest::s_bankset_size;
size_t LpmCoreTcamTest::s_max_quad_entries;

TEST_P(LpmCoreTcamTest, BasicInsertV4)
{
    size_t num_banksets = 1;
    size_t num_cells_per_bank = 3;
    size_t max_num_quad_blocks = 1;

    create_lpm_core_tcam(num_banksets, num_cells_per_bank, max_num_quad_blocks);

    size_t tcam_cells = s_tcam->get_num_cells();
    bool is_akpg = GetParam();
    // For AKPG last two cells are blocked, but for Pacific/GB last row is always blocked.
    size_t max_num_singles = is_akpg ? tcam_cells - 2 : tcam_cells - 4;
    vector_alloc<lpm_key_payload> tcam_model(tcam_cells);

    lpm_implementation_desc_vec tcam_updates;
    lpm_core_tcam::hardware_instruction_vec tcam_hardware_updates;

    lpm_key_t key;
    lpm_payload_t payload;
    la_status status;

    for (size_t i = 0; i < max_num_singles - 1; i++) {
        key = lpm_key_t(0x120 + i, 12);
        payload = i + 1;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    key = lpm_key_t(0x1200, 16);
    payload = 8;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(tcam_model, tcam_hardware_updates);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    key = lpm_key_t(0x120, 12);
    payload = 9;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    tcam_updates.clear();

    key = lpm_key_t(0x140, 12);
    payload = 10;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    tcam_updates.clear();

    lpm_key_t lookup_key;
    lpm_key_t hit_key;
    lpm_payload_t hit_payload;
    bool hit;

    lookup_key = lpm_key_t(0x1200, 16);
    hit = lookup_tcam_model(tcam_model, lookup_key, hit_key, hit_payload);
    ASSERT_TRUE(hit);
    ASSERT_EQ(hit_key, lpm_key_t(0x1200, 16));
    ASSERT_EQ(hit_payload, 8U);

    lookup_key = lpm_key_t(0x130, 12);
    hit = lookup_tcam_model(tcam_model, lookup_key, hit_key, hit_payload);
    ASSERT_FALSE(hit);

    lookup_key = lpm_key_t(0x1201, 16);
    hit = lookup_tcam_model(tcam_model, lookup_key, hit_key, hit_payload);
    ASSERT_TRUE(hit);
    ASSERT_EQ(hit_key, lpm_key_t(0x120, 12));
    ASSERT_EQ(hit_payload, 1U);
}

TEST_P(LpmCoreTcamTest, BasicInsertMix)
{
    size_t num_banksets = 1;
    size_t num_cells_per_bank = 5;
    size_t max_num_quad_blocks = 1;

    create_lpm_core_tcam(num_banksets, num_cells_per_bank, max_num_quad_blocks);

    size_t tcam_cells = s_tcam->get_num_cells();

    vector_alloc<lpm_key_payload> tcam_model(tcam_cells);

    lpm_implementation_desc_vec tcam_updates;
    lpm_core_tcam::hardware_instruction_vec tcam_hardware_updates;

    lpm_key_t key;
    lpm_payload_t payload;
    la_status status;

    key = lpm_key_t(0x800, 12); // short IPv6
    payload = 1;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    key = lpm_key_t(0x802, 12); // short IPv6
    payload = 2;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    key = lpm_key_t(0x103, 16); // IPv4
    payload = 3;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    key = lpm_key_t(0xf, 4) << 100; // Long IPv6
    payload = 4;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(tcam_model, tcam_hardware_updates);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    key = lpm_key_t(0xf, 4) << 100;
    payload = 5;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    tcam_updates.clear();

    key = lpm_key_t(0x80000000000, 44); // double IPv6
    payload = 6;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(tcam_model, tcam_hardware_updates);
    tcam_updates.clear();

    lpm_key_t lookup_key;
    lpm_key_t hit_key;
    lpm_payload_t hit_payload;
    bool hit;

    lookup_key = lpm_key_t(0xf, 4) << 104;
    hit = lookup_tcam_model(tcam_model, lookup_key, hit_key, hit_payload);
    ASSERT_TRUE(hit);
    ASSERT_EQ(hit_key, lpm_key_t(0xf, 4) << 100);
    ASSERT_EQ(hit_payload, 4U);

    lookup_key = lpm_key_t(0x10300, 24);
    hit = lookup_tcam_model(tcam_model, lookup_key, hit_key, hit_payload);
    ASSERT_TRUE(hit);
    ASSERT_EQ(hit_key, lpm_key_t(0x103, 16));
    ASSERT_EQ(hit_payload, 3U);

    lookup_key = lpm_key_t(0x80000000000, 44);
    hit = lookup_tcam_model(tcam_model, lookup_key, hit_key, hit_payload);
    ASSERT_TRUE(hit);
    ASSERT_EQ(hit_key, lpm_key_t(0x80000000000, 44));
    ASSERT_EQ(hit_payload, 6U);
}

TEST_P(LpmCoreTcamTest, BasicInsertRemoveMix2Banksets)
{
    size_t num_banksets = 2;
    size_t num_cells_per_bank = 3;
    size_t max_num_quad_blocks = 1;

    create_lpm_core_tcam(num_banksets, num_cells_per_bank, max_num_quad_blocks);

    size_t tcam_cells = s_tcam->get_num_cells();

    vector_alloc<lpm_key_payload> tcam_model(tcam_cells);

    lpm_implementation_desc_vec tcam_updates;
    lpm_core_tcam::hardware_instruction_vec tcam_hardware_updates;

    lpm_key_t key;
    lpm_payload_t payload;
    la_status status;

    for (size_t i = 0; i < 7; i++) {
        key = lpm_key_t(0x80000000000 + i, 44); // double IPv6
        payload = i + 1;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(tcam_model, tcam_hardware_updates);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    key = lpm_key_t(0x80000000006, 44); // double IPv6
    payload = 8;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    tcam_updates.clear();

    key = lpm_key_t(0x80000000006, 44); // try again. make sure that update failure doesn't roll back previous updates as well.
    payload = 8;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    tcam_updates.clear();

    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x109 + i, 16); // IPv4
        payload = 9 + i;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(tcam_model, tcam_hardware_updates);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    bool is_akpg = GetParam();
    if (!is_akpg) {
        key = lpm_key_t(0x10d, 16); // IPv4
        payload = 13;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
        status = s_tcam->update(tcam_updates, tcam_hardware_updates);
        ASSERT_EQ(status, LA_STATUS_ERESOURCE);
        tcam_updates.clear();
    }

    key = lpm_key_t(0xf, 4) << 100; // Long IPv6
    payload = 4;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    tcam_updates.clear();

    key = lpm_key_t(0x80000000006, 44); // remove one double IPv6
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, key));

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(tcam_model, tcam_hardware_updates);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    key = lpm_key_t(0xf, 4) << 100; // Long IPv6
    payload = 4;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(tcam_model, tcam_hardware_updates);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    if (is_akpg) {
        for (size_t i = 0; i < 2; i++) {
            key = lpm_key_t(0x111 + i, 16); // IPv4
            payload = 9;
            tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
        }
    }

    key = lpm_key_t(0x110, 16); // IPv4
    payload = 10;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    tcam_updates.clear();
}

TEST_P(LpmCoreTcamTest, BasicWithdraw2Banksets)
{
    size_t num_banksets = 2;
    size_t num_cells_per_bank = 3;
    size_t max_num_quad_blocks = 1;

    create_lpm_core_tcam(num_banksets, num_cells_per_bank, max_num_quad_blocks);

    size_t tcam_cells = s_tcam->get_num_cells();

    vector_alloc<lpm_key_payload> tcam_model(tcam_cells);

    lpm_implementation_desc_vec tcam_updates;
    lpm_core_tcam::hardware_instruction_vec tcam_hardware_updates;

    lpm_key_t key;
    lpm_payload_t payload;
    la_status status;

    for (size_t i = 0; i < 7; i++) {
        key = lpm_key_t(0x80000000000 + i, 44); // double IPv6
        payload = i + 1;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x109 + i, 16); // IPv4
        payload = 9 + i;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    key = lpm_key_t(0x10a, 16); // IPv4
    payload = 13;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    tcam_updates.clear();

    key = lpm_key_t(0x109, 16); // IPv4
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, key));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    key = lpm_key_t(0x109, 16); // IPv4
    payload = 99;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    key = lpm_key_t(0x109, 16); // IPv4
    payload = 100;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    tcam_updates.clear();

    s_tcam->withdraw();

    bool is_akpg = GetParam();
    size_t max_num_singles = is_akpg ? tcam_cells - 2 : tcam_cells - 4;

    for (size_t i = 0; i < max_num_singles; i++) {
        key = lpm_key_t(0x109 + i, 16); // IPv4
        payload = 200 + i;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();
}

TEST_P(LpmCoreTcamTest, PushPullRows)
{
    bool is_akpg = GetParam();

    size_t num_banksets = 2;
    size_t num_cells_per_bank = 3;
    size_t max_num_quad_blocks = 1;
    create_lpm_core_tcam(num_banksets, num_cells_per_bank, max_num_quad_blocks);

    // For AKPG last two cells are blocked, but for Pacific/GB last row is always blocked.
    size_t tcam_cells = s_tcam->get_num_cells();
    size_t max_num_singles = is_akpg ? tcam_cells - 2 : tcam_cells - 4;

    vector_alloc<lpm_key_payload> tcam_model(tcam_cells);

    lpm_implementation_desc_vec tcam_updates;
    lpm_core_tcam::hardware_instruction_vec tcam_hardware_updates;

    // Fill the V4 with entries with specific order
    for (size_t i = 0; i < max_num_singles; i++) {
        lpm_key_t key = lpm_key_t(0, i + 5); // Simple IPv4
        lpm_payload_t payload = 1 + i;
        tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    la_status status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    // Remove random key in the middle
    lpm_key_t key = lpm_key_t(0, 20);
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, key, INVALID_PAYLOAD));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    // Insert key high in the tree to pull rows
    lpm_payload_t payload = 2;
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, lpm_key_t(0, 3), payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    // Remove random key in the middle
    key = lpm_key_t(0, 18);
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, key, INVALID_PAYLOAD));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();

    // Insert key low in the tree to push rows
    tcam_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, lpm_key_t(0, 30), payload));
    status = s_tcam->update(tcam_updates, tcam_hardware_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    tcam_updates.clear();
    tcam_hardware_updates.clear();
}

INSTANTIATE_TEST_CASE_P(AkpgTest, LpmCoreTcamTest, testing::Values(true));

INSTANTIATE_TEST_CASE_P(PacificGBTest, LpmCoreTcamTest, testing::Values(false));
