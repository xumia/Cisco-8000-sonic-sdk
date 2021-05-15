// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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
#include "lpm/lpm_distributor_akpg.h"
#include "lpm/lpm_distributor_pacific_gb.h"
#include "test_lpm_types.h"
#include "gtest/gtest.h"

using namespace silicon_one;

class LpmDistributorTest : public testing::TestWithParam<bool>
{
public:
    struct distributor_parameters {
        std::string name;
        size_t num_banks;
        size_t num_cells_per_bank;
        size_t max_key_width;
    };

    static void SetUpTestCase()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::ERROR;
        logger::instance().set_logging_level(
            silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, logger_level);
    }

    void SetUp()
    {
        bool is_akpg = GetParam();
        std::string name = parameters_map[is_akpg].name;
        num_cells_per_bank = parameters_map[is_akpg].num_cells_per_bank;
        num_banks = parameters_map[is_akpg].num_banks;
        num_cells_in_distributor = num_cells_per_bank * num_banks;
        size_t max_key_width = parameters_map[is_akpg].max_key_width;
        if (is_akpg) {
            s_distributor = new lpm_distributor_akpg(name, num_cells_per_bank, max_key_width);
        } else {
            s_distributor = new lpm_distributor_pacific_gb(name, num_cells_per_bank, max_key_width);
        }
    }

    void TearDown()
    {
        if (s_distributor != nullptr) {
            delete s_distributor;
            s_distributor = nullptr;
        }
    }

    size_t get_num_cells_for_key(lpm_key_t key)
    {
        bool is_ipv6 = key.bit_from_msb(0);
        bool is_akpg = GetParam();
        if (is_akpg) {
            size_t num_cells_for_key = is_ipv6 ? 4 : 2;
            return num_cells_for_key;
        }

        return 1;
    }

    size_t translate_location_to_plain_cell(const distributor_cell_location& location)
    {
        size_t cell = location.bank * num_cells_per_bank + location.cell;
        return cell;
    }

    void apply_updates(vector_alloc<lpm_key_payload>& distributor_model, const lpm_distributor::hardware_instruction_vec& updates)
    {
        for (const lpm_distributor::distributor_hw_instruction& instruction : updates) {
            auto type = boost::apply_visitor(lpm_distributor::visitor_distributor_hw_instruction(), instruction.instruction_data);
            switch (type) {
            case lpm_distributor::distributor_hw_instruction::type_e::INSERT: {
                auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::insert_data>(instruction.instruction_data);
                size_t num_cells_for_key = get_num_cells_for_key(curr_data.key);
                size_t plain_cell = translate_location_to_plain_cell(curr_data.location);
                for (size_t cell_id = 0; cell_id < num_cells_for_key; cell_id++) {
                    size_t tcam_cell = plain_cell + num_cells_per_bank * cell_id;
                    ASSERT_EQ(distributor_model[tcam_cell].key, lpm_key_t());
                }

                distributor_model[plain_cell] = lpm_key_payload{.key = curr_data.key, .payload = curr_data.payload};
                break;
            }

            case lpm_distributor::distributor_hw_instruction::type_e::REMOVE: {
                auto curr_data = boost::get<lpm_distributor::distributor_hw_instruction::remove_data>(instruction.instruction_data);
                size_t plain_cell = translate_location_to_plain_cell(curr_data.location);
                ASSERT_NE(distributor_model[plain_cell].key, lpm_key_t());
                distributor_model[plain_cell] = lpm_key_payload{.key = lpm_key_t(), .payload = INVALID_PAYLOAD};
                break;
            }

            case lpm_distributor::distributor_hw_instruction::type_e::MODIFY_PAYLOAD: {
                auto curr_data
                    = boost::get<lpm_distributor::distributor_hw_instruction::modify_payload_data>(instruction.instruction_data);
                size_t plain_cell = translate_location_to_plain_cell(curr_data.location);
                size_t num_cells_for_key = get_num_cells_for_key(curr_data.key);
                for (size_t cell_id = 1; cell_id < num_cells_for_key; cell_id++) {
                    size_t tcam_cell = plain_cell + num_cells_per_bank * cell_id;
                    ASSERT_EQ(distributor_model[tcam_cell].key, lpm_key_t());
                }

                distributor_model[plain_cell] = lpm_key_payload{.key = curr_data.key, .payload = curr_data.payload};
                break;
            }

            case lpm_distributor::distributor_hw_instruction::type_e::UPDATE_GROUP_TO_CORE:
                break;

            default:
                ASSERT_TRUE(false);
                break;
            }
        }
    }

    void check_lookup_result(vector_alloc<lpm_key_payload>& distributor_model,
                             const lpm_key_t& lookup_key,
                             const lpm_key_t& hit_key,
                             lpm_payload_t hit_payload,
                             const distributor_cell_location& hit_location)
    {
        size_t hit_cell = translate_location_to_plain_cell(hit_location);
        bool found_key = false;
        for (size_t cell_id = 0; cell_id < distributor_model.size(); cell_id++) {
            if (distributor_model[cell_id].key == lpm_key_t()) {
                continue;
            }

            if (is_contained(distributor_model[cell_id].key, lookup_key)) {
                lpm_key_payload key_payload = distributor_model[cell_id];
                ASSERT_EQ(hit_cell, cell_id);
                ASSERT_EQ(key_payload.key, hit_key);
                ASSERT_EQ(key_payload.payload, hit_payload);
                found_key = true;
                break;
            }
        }

        ASSERT_EQ(found_key, true);
    }

    static lpm_distributor* s_distributor;
    static size_t num_banks;
    static size_t num_cells_per_bank;
    static size_t num_cells_in_distributor;
    static map_alloc<bool, distributor_parameters> parameters_map;
};

lpm_distributor* LpmDistributorTest::s_distributor(nullptr);
size_t LpmDistributorTest::num_banks;
size_t LpmDistributorTest::num_cells_per_bank;
size_t LpmDistributorTest::num_cells_in_distributor;
map_alloc<bool, LpmDistributorTest::distributor_parameters> LpmDistributorTest::parameters_map
    = {{true /* akpg params */,
        {.name = std::string("Test AKPG DISTRIBUTOR"), .num_banks = 4, .num_cells_per_bank = 4, .max_key_width = 160}},
       {false /* pacific/gb params */,
        {.name = std::string("Test Pacific/GB DISTRIBUTOR"), .num_banks = 1, .num_cells_per_bank = 16, .max_key_width = 80}}};

TEST_P(LpmDistributorTest, InsertFullIPV4)
{
    lpm_implementation_desc_vec logical_updates;

    lpm_key_t key = lpm_key_t();
    lpm_payload_t payload;

    bool is_akpg = GetParam();
    size_t max_num_ipv4_entries = is_akpg ? num_cells_in_distributor / 2 : num_cells_in_distributor;
    for (size_t i = 0; i < max_num_ipv4_entries - 1; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    lpm_distributor::hardware_instruction_vec hw_updates;
    la_status status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    vector_alloc<lpm_key_payload> distributor_model(num_cells_in_distributor);
    apply_updates(distributor_model, hw_updates);
    logical_updates.clear();
    hw_updates.clear();

    s_distributor->commit();

    key = lpm_key_t(0x100, 12);
    payload = 10;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    logical_updates.clear();
    hw_updates.clear();

    key = lpm_key_t(0x150, 12);
    payload = 10;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    logical_updates.clear();
    hw_updates.clear();

    // Distributor is full, this insert should fail.
    key = lpm_key_t(0x200, 12);
    payload = 10;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
}

TEST_P(LpmDistributorTest, InsertFullIPV6)
{
    lpm_implementation_desc_vec logical_updates;
    lpm_key_t key = lpm_key_t();
    lpm_payload_t payload;

    bool is_akpg = GetParam();
    size_t max_num_ipv6_entries = is_akpg ? num_cells_per_bank : num_cells_in_distributor;

    for (size_t i = 0; i < max_num_ipv6_entries - 1; i++) {
        key = lpm_key_t(0x800 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    lpm_distributor::hardware_instruction_vec hw_updates;
    la_status status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    vector_alloc<lpm_key_payload> distributor_model(num_cells_in_distributor);
    apply_updates(distributor_model, hw_updates);
    logical_updates.clear();
    hw_updates.clear();

    s_distributor->commit();

    key = lpm_key_t(0x800, 12);
    payload = 10;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    hw_updates.clear();
    logical_updates.clear();

    key = lpm_key_t(0x810, 12);
    payload = 10;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    logical_updates.clear();
    hw_updates.clear();

    // Distributor is full, this insert should fail.
    key = lpm_key_t(0x820, 12);
    payload = 10;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
}

TEST_P(LpmDistributorTest, InsertMix)
{
    lpm_implementation_desc_vec logical_updates;
    lpm_distributor::hardware_instruction_vec hw_updates;

    bool is_akpg = GetParam();
    size_t num_ipv6_entries = num_cells_per_bank / 2;
    size_t num_ipv4_entries = is_akpg ? (num_cells_per_bank - num_ipv6_entries) * 2 : num_cells_per_bank / 2;

    lpm_key_t key;
    lpm_payload_t payload;
    // Insert half of IPv4 entries
    for (size_t i = 0; i < num_ipv4_entries / 2; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    la_status status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    vector_alloc<lpm_key_payload> distributor_model(num_cells_in_distributor);
    apply_updates(distributor_model, hw_updates);
    s_distributor->commit();
    logical_updates.clear();
    hw_updates.clear();

    for (size_t i = 0; i < num_ipv6_entries; i++) {
        key = lpm_key_t(0x800 + i, 12);
        payload = 11 + i;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_updates(distributor_model, hw_updates);
    s_distributor->commit();
    logical_updates.clear();
    hw_updates.clear();

    for (size_t i = 0; i < num_ipv4_entries / 2; i++) {
        key = lpm_key_t(0x200 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_updates(distributor_model, hw_updates);
    s_distributor->commit();
    logical_updates.clear();
    hw_updates.clear();

    // Distributor is full, should return OOR.
    key = lpm_key_t(0x850, 12); // IPv6
    payload = 15;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    logical_updates.clear();

    key = lpm_key_t(0x150, 12); // IPv4
    payload = 14;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    key = lpm_key_t(0x800, 12);
    lpm_key_t hit_key = lpm_key_t();
    lpm_payload_t hit_payload;
    distributor_cell_location hit_location;
    status = s_distributor->lookup_tcam_table(key, hit_key, hit_payload, hit_location);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    ASSERT_EQ(hit_key, key);
    ASSERT_EQ(hit_payload, 11U);
    check_lookup_result(distributor_model, key, hit_key, hit_payload, hit_location);

    key = lpm_key_t(0x100, 12);
    status = s_distributor->lookup_tcam_table(key, hit_key, hit_payload, hit_location);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    ASSERT_EQ(hit_key, key);
    ASSERT_EQ(hit_payload, 1U);
    check_lookup_result(distributor_model, key, hit_key, hit_payload, hit_location);
}

TEST_P(LpmDistributorTest, InsertRemoveMix)
{
    lpm_implementation_desc_vec logical_updates;
    lpm_distributor::hardware_instruction_vec hw_updates;

    lpm_key_t key = lpm_key_t();
    lpm_payload_t payload;
    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    key = lpm_key_t(0x800, 12); // IPv6
    payload = 11;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    key = lpm_key_t(0x801, 12); // IPv6
    payload = 13;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    la_status status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    vector_alloc<lpm_key_payload> distributor_model(num_cells_in_distributor);
    apply_updates(distributor_model, hw_updates);
    logical_updates.clear();
    hw_updates.clear();

    key = lpm_key_t(0x800, 12);
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, key));

    key = lpm_key_t(0x801, 12); // IPv6
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, key));

    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::REMOVE, key, payload));
    }

    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_updates(distributor_model, hw_updates);
    logical_updates.clear();
    hw_updates.clear();

    // Insert in clean distributor
    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    key = lpm_key_t(0x800, 12); // IPv6
    payload = 11;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    key = lpm_key_t(0x801, 12); // IPv6
    payload = 13;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_updates(distributor_model, hw_updates);
}

TEST_P(LpmDistributorTest, WithdrawUpdate)
{
    lpm_implementation_desc_vec logical_updates;
    lpm_distributor::hardware_instruction_vec hw_updates;

    lpm_key_t key = lpm_key_t();
    lpm_payload_t payload;
    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    la_status status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    s_distributor->commit();
    vector_alloc<lpm_key_payload> distributor_model(num_cells_in_distributor);
    apply_updates(distributor_model, hw_updates);
    logical_updates.clear();
    hw_updates.clear();

    key = lpm_key_t(0x800, 12); // IPv6
    payload = 11;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    key = lpm_key_t(0x800, 12); // IPv6
    payload = 13;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_EEXIST);
    s_distributor->withdraw();
    logical_updates.clear();
    hw_updates.clear();

    key = lpm_key_t(0x800, 12); // IPv6
    payload = 11;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    key = lpm_key_t(0x801, 12); // IPv6
    payload = 13;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_updates(distributor_model, hw_updates);

    lpm_key_t hit_key = lpm_key_t();
    lpm_payload_t hit_payload;
    distributor_cell_location hit_location;
    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        status = s_distributor->lookup_tcam_table(key, hit_key, hit_payload, hit_location);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        ASSERT_EQ(hit_key, key);
        ASSERT_EQ(hit_payload, payload);
        check_lookup_result(distributor_model, key, hit_key, hit_payload, hit_location);
    }
}

TEST_P(LpmDistributorTest, FullInsertAfterWithdraw)
{
    lpm_implementation_desc_vec logical_updates;
    lpm_distributor::hardware_instruction_vec hw_updates;

    lpm_key_t key = lpm_key_t();
    lpm_payload_t payload;
    bool is_akpg = GetParam();
    size_t max_num_ipv4_entries = is_akpg ? num_cells_in_distributor / 2 : num_cells_in_distributor;
    for (size_t i = 0; i < max_num_ipv4_entries; i++) {
        key = lpm_key_t(0x200 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    la_status status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    s_distributor->withdraw();
    logical_updates.clear();
    hw_updates.clear();

    // After withdraw these updates should succeed.
    for (size_t i = 0; i < max_num_ipv4_entries; i++) {
        key = lpm_key_t(0x200 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    vector_alloc<lpm_key_payload> distributor_model(num_cells_in_distributor);
    apply_updates(distributor_model, hw_updates);
}

TEST_P(LpmDistributorTest, GetEntryTest)
{
    lpm_implementation_desc_vec logical_updates;
    lpm_distributor::hardware_instruction_vec hw_updates;

    lpm_key_t key = lpm_key_t();
    lpm_payload_t payload;
    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    }

    key = lpm_key_t(0x800, 12); // IPv6
    payload = 11;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));
    key = lpm_key_t(0x801, 12); // IPv6
    payload = 13;
    logical_updates.push_back(lpm_action_desc_internal(lpm_implementation_action_e::INSERT, key, payload));

    la_status status = s_distributor->update(logical_updates, hw_updates);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    vector_alloc<lpm_key_payload> distributor_model(num_cells_in_distributor);
    apply_updates(distributor_model, hw_updates);
    logical_updates.clear();
    hw_updates.clear();

    // Lookup at specific cell using get entry
    lpm_key_t hit_key = lpm_key_t();
    lpm_payload_t hit_payload;
    distributor_cell_location hit_location;
    for (size_t i = 0; i < 4; i++) {
        key = lpm_key_t(0x100 + i, 12);
        payload = i + 1;
        status = s_distributor->lookup_tcam_table(key, hit_key, hit_payload, hit_location);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        ASSERT_EQ(hit_key, key);
        ASSERT_EQ(hit_payload, payload);
        lpm_key_payload key_payload;
        status = s_distributor->get_entry(hit_location, key_payload);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        ASSERT_EQ(key_payload.key, hit_key);
        ASSERT_EQ(key_payload.payload, hit_payload);
    }

    lpm_key_payload key_payload;
    key = lpm_key_t(0x800, 12);
    payload = 11;
    status = s_distributor->lookup_tcam_table(key, hit_key, hit_payload, hit_location);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    ASSERT_EQ(hit_key, key);
    ASSERT_EQ(hit_payload, payload);
    status = s_distributor->get_entry(hit_location, key_payload);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    ASSERT_EQ(key_payload.key, hit_key);
    ASSERT_EQ(key_payload.payload, hit_payload);

    key = lpm_key_t(0x801, 12);
    payload = 13;
    status = s_distributor->lookup_tcam_table(key, hit_key, hit_payload, hit_location);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    ASSERT_EQ(hit_key, key);
    ASSERT_EQ(hit_payload, payload);
    status = s_distributor->get_entry(hit_location, key_payload);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    ASSERT_EQ(key_payload.key, hit_key);
    ASSERT_EQ(key_payload.payload, hit_payload);
}

INSTANTIATE_TEST_CASE_P(AkpgTest, LpmDistributorTest, testing::Values(true));

INSTANTIATE_TEST_CASE_P(PacificGBTest, LpmDistributorTest, testing::Values(false));
