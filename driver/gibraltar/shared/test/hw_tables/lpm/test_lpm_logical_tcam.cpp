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
#include "lpm/lpm_logical_tcam.h"
#include "test_lpm_types.h"
#include "gtest/gtest.h"

using namespace silicon_one;

class LpmLogicalTcamTest : public ::testing::Test
{
protected:
    static constexpr size_t TCAM_SIZE = 4;

    struct tcam_model_entry {
        lpm_key_t key;
        lpm_payload_t payload;
        bool valid;
    };

    static lpm_logical_tcam* s_tcam;
    static vector_alloc<tcam_model_entry> s_tcam_model;

    void SetUp()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::ERROR;
        logger::instance().set_logging_level(0, silicon_one::la_logger_component_e::TABLES, logger_level);
        logger::instance().set_logging_level(
            silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, logger_level);

        s_tcam = new lpm_logical_tcam(std::string("Test TCAM"), TCAM_SIZE);

        s_tcam_model.resize(TCAM_SIZE);
    }

    void TearDown()
    {
        delete s_tcam;
        s_tcam = nullptr;

        s_tcam_model.clear();
    }

    size_t get_number_of_valid_nodes()
    {
        return get_number_of_valid_nodes(s_tcam->get_root_node());
    }

    size_t get_number_of_valid_nodes(const lpm_logical_tcam_tree_node* node)
    {
        if (node == nullptr) {
            return 0;
        }

        size_t num = (node->is_valid() ? 1 : 0);
        num += get_number_of_valid_nodes(node->get_left_child());
        num += get_number_of_valid_nodes(node->get_right_child());
        return num;
    }

    size_t get_number_of_occupied_entries()
    {
        return s_tcam->get_entries().size();
    }

    la_status update_tcam_model(lpm_logical_tcam::logical_instruction& instruction)
    {
        switch (instruction.instruction_type) {
        case lpm_logical_tcam::logical_instruction::type_e::INSERT: {
            size_t row = instruction.row;
            if (s_tcam_model[row].valid) {
                return LA_STATUS_EEXIST;
            }
            s_tcam_model[row].key = instruction.key;
            s_tcam_model[row].payload = instruction.payload;
            s_tcam_model[row].valid = true;
            return LA_STATUS_SUCCESS;
        }

        case lpm_logical_tcam::logical_instruction::type_e::REMOVE: {
            size_t row = instruction.row;
            if (!s_tcam_model[row].valid) {
                return LA_STATUS_ENOTFOUND;
            }
            s_tcam_model[row].key = lpm_key_t();
            s_tcam_model[row].payload = INVALID_PAYLOAD;
            s_tcam_model[row].valid = false;
            return LA_STATUS_SUCCESS;
        }

        case lpm_logical_tcam::logical_instruction::type_e::MODIFY_PAYLOAD: {
            size_t row = instruction.row;
            if (!s_tcam_model[row].valid) {
                return LA_STATUS_ENOTFOUND;
            }

            if (s_tcam_model[row].key != instruction.key) {
                return LA_STATUS_EINVAL;
            }

            s_tcam_model[row].payload = instruction.payload;
            s_tcam_model[row].valid = true;
            return LA_STATUS_SUCCESS;
        }

        default:
            assert(false);
            return LA_STATUS_EUNKNOWN;
        }
    }

    la_status lookup_tcam_model(lpm_key_t key, lpm_key_t& out_key, lpm_payload_t& out_payload, size_t& out_row)
    {
        for (size_t row = 0; row < s_tcam_model.size(); row++) {
            if (!s_tcam_model[row].valid) {
                continue;
            }

            if (is_contained(s_tcam_model[row].key, key)) {
                out_key = s_tcam_model[row].key;
                out_payload = s_tcam_model[row].payload;
                out_row = row;
                return LA_STATUS_SUCCESS;
            }
        }

        return LA_STATUS_ENOTFOUND;
    }
};

lpm_logical_tcam* LpmLogicalTcamTest::s_tcam(nullptr);
vector_alloc<LpmLogicalTcamTest::tcam_model_entry> LpmLogicalTcamTest::s_tcam_model;

TEST_F(LpmLogicalTcamTest, BasicInsertLookup)
{
    ASSERT_EQ(get_number_of_valid_nodes(), 0U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());

    lpm_key_t key;
    lpm_payload_t payload;
    lpm_logical_tcam::logical_instruction_vec out_instructions;

    key = lpm_key_t(0x123, 12);
    payload = 1;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x1234, 16);
    payload = 2;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x1235, 16);
    payload = 3;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);
    payload = 4;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_EEXIST);

    key = lpm_key_t(0x1236, 16);
    payload = 5;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x1237, 16);
    payload = 6;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_ERESOURCE);

    ASSERT_EQ(get_number_of_valid_nodes(), 4U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());

    size_t out_row;
    lpm_key_t out_key;
    lpm_payload_t out_payload;

    key = lpm_key_t(0x12, 8);
    ASSERT_EQ(s_tcam->lookup_tcam_tree(key, out_key, out_payload, out_row), LA_STATUS_ENOTFOUND);
    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_ENOTFOUND);

    key = lpm_key_t(0x1237, 16);
    ASSERT_EQ(s_tcam->lookup_tcam_tree(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x123, 12));
    ASSERT_EQ(out_payload, 1U);
    ASSERT_EQ(out_row, 3U);

    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x123, 12));
    ASSERT_EQ(out_payload, 1U);
    ASSERT_EQ(out_row, 3U);

    key = lpm_key_t(0x1236, 16);
    ASSERT_EQ(s_tcam->lookup_tcam_tree(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x1236, 16));
    ASSERT_EQ(out_payload, 5U);
    ASSERT_NE(out_row, 0U);

    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x1236, 16));
    ASSERT_EQ(out_payload, 5U);
    ASSERT_NE(out_row, 0U);
}

TEST_F(LpmLogicalTcamTest, BasicBlockUnblock)
{
    ASSERT_EQ(get_number_of_valid_nodes(), 0U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());

    lpm_key_t key;
    lpm_payload_t payload;
    lpm_logical_tcam::logical_instruction_vec out_instructions;

    key = lpm_key_t(0x123, 12);
    payload = 1;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x1234, 16);
    payload = 2;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    ASSERT_EQ(get_number_of_valid_nodes(), 2U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());

    size_t out_row;
    lpm_key_t out_key;
    lpm_payload_t out_payload;

    key = lpm_key_t(0x1235, 16);
    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x123, 12));
    ASSERT_EQ(out_payload, 1U);
    ASSERT_EQ(out_row, 1U);

    ASSERT_EQ(s_tcam->block(1 /* row */, out_instructions), LA_STATUS_SUCCESS);

    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x123, 12));
    ASSERT_EQ(out_payload, 1U);
    ASSERT_EQ(out_row, 2U);

    key = lpm_key_t(0x1236, 16);
    payload = 3;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x1237, 16);
    payload = 4;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_ERESOURCE);

    s_tcam->unblock(1 /* row */);
    key = lpm_key_t(0x1237, 16);
    payload = 4;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    ASSERT_EQ(s_tcam->block(1 /* row */, out_instructions), LA_STATUS_ERESOURCE);
}

TEST_F(LpmLogicalTcamTest, BasicWithdraw)
{
    ASSERT_EQ(get_number_of_valid_nodes(), 0U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());

    lpm_key_t key;
    lpm_payload_t payload;
    lpm_logical_tcam::logical_instruction_vec out_instructions;

    key = lpm_key_t(0x123, 12);
    payload = 1;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x1234, 16);
    payload = 2;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    ASSERT_EQ(get_number_of_valid_nodes(), 2U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());
    s_tcam->commit();

    // withdraw after commit, should have no effect
    s_tcam->withdraw();
    ASSERT_EQ(get_number_of_valid_nodes(), 2U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());

    size_t out_row;
    lpm_key_t out_key;
    lpm_payload_t out_payload;

    key = lpm_key_t(0x1235, 16);
    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x123, 12));
    ASSERT_EQ(out_payload, 1U);

    key = lpm_key_t(0x12345, 20);
    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x1234, 16));
    ASSERT_EQ(out_payload, 2U);

    // perform some inserts and removes then withdraw them
    key = lpm_key_t(0x12345, 20);
    payload = 3;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12346, 20);
    payload = 4;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12345, 20);
    ASSERT_EQ(s_tcam->remove(key, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12346, 20);
    ASSERT_EQ(s_tcam->remove(key, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12347, 20);
    payload = 5;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12345, 20);
    payload = 6;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12345, 20);
    ASSERT_EQ(s_tcam->remove(key, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x123, 12);
    ASSERT_EQ(s_tcam->remove(key, out_instructions), LA_STATUS_SUCCESS);

    ASSERT_EQ(s_tcam->block(1 /* row */, out_instructions), LA_STATUS_SUCCESS);
    ASSERT_EQ(s_tcam->block(0 /* row */, out_instructions), LA_STATUS_SUCCESS);
    ASSERT_EQ(s_tcam->unblock(1 /* row */), LA_STATUS_SUCCESS);

    s_tcam->withdraw();

    ASSERT_EQ(get_number_of_valid_nodes(), 2U);
    ASSERT_EQ(get_number_of_occupied_entries(), get_number_of_valid_nodes());

    key = lpm_key_t(0x12345, 20);
    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x1234, 16));
    ASSERT_EQ(out_payload, 2U);

    key = lpm_key_t(0x12347, 20);
    ASSERT_EQ(s_tcam->lookup_tcam_table(key, out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x1234, 16));
    ASSERT_EQ(out_payload, 2U);
}

TEST_F(LpmLogicalTcamTest, BasicInstructions)
{
    lpm_key_t key;
    lpm_payload_t payload;
    lpm_logical_tcam::logical_instruction_vec out_instructions;

    key = lpm_key_t(0x123, 12);
    payload = 1;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x1234, 16);
    payload = 2;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    size_t row = 0;
    ASSERT_EQ(s_tcam->block(row, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12345, 20);
    payload = 3;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12, 8);
    payload = 4;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_ERESOURCE);

    key = lpm_key_t(0x12345, 20);
    ASSERT_EQ(s_tcam->remove(key, out_instructions), LA_STATUS_SUCCESS);

    key = lpm_key_t(0x12, 8);
    payload = 5;
    ASSERT_EQ(s_tcam->insert(key, payload, out_instructions), LA_STATUS_SUCCESS);

    for (auto& instruction : out_instructions) {
        ASSERT_EQ(update_tcam_model(instruction), LA_STATUS_SUCCESS);
    }

    size_t out_row;
    lpm_key_t out_key;
    lpm_payload_t out_payload;

    ASSERT_EQ(lookup_tcam_model(lpm_key_t(0x123, 12), out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x123, 12));
    ASSERT_EQ(out_payload, 1U);
    ASSERT_EQ(out_row, 2U);

    ASSERT_EQ(lookup_tcam_model(lpm_key_t(0x1235, 16), out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x123, 12));
    ASSERT_EQ(out_payload, 1U);
    ASSERT_EQ(out_row, 2U);

    ASSERT_EQ(lookup_tcam_model(lpm_key_t(0x121, 12), out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x12, 8));
    ASSERT_EQ(out_payload, 5U);
    ASSERT_EQ(out_row, 3U);

    ASSERT_EQ(lookup_tcam_model(lpm_key_t(0x12345, 20), out_key, out_payload, out_row), LA_STATUS_SUCCESS);
    ASSERT_EQ(out_key, lpm_key_t(0x1234, 16));
    ASSERT_EQ(out_payload, 2U);
    ASSERT_EQ(out_row, 1U);

    ASSERT_FALSE(s_tcam_model[0].valid); // we blocked this row. must not be used
}
