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
#include "lpm/lpm_core_tcam_allocator_akpg.h"
#include "test_lpm_types.h"
#include "gtest/gtest.h"

using namespace silicon_one;

class LpmCoreTcamAllocatorAkpgTest : public ::testing::Test
{
protected:
    static lpm_core_tcam_allocator_akpg* s_tcam_allocator;

    void SetUp()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::ERROR;
        logger::instance().set_logging_level(
            silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, logger_level);
    }

    void TearDown()
    {
        delete s_tcam_allocator;
    }

    void apply_instructions(vector_alloc<bool> logical_tcam_model[3],
                            std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS>& free_blocks,
                            lpm_core_tcam_allocator::allocator_instruction_vec& instructions)
    {
        for (const auto& instruction : instructions) {

            switch (instruction.instruction_type) {

            case lpm_core_tcam_allocator::allocator_instruction::instruction_type_e::BLOCK: {
                auto instruction_data
                    = boost::get<lpm_core_tcam_allocator::allocator_instruction::block>(instruction.instruction_data);
                size_t tcam_idx = static_cast<size_t>(instruction_data.logical_tcam);
                size_t logical_row = instruction_data.logical_row;
                if (verbose) {
                    printf("instruction=BLOCK   TCAM=%zu   row=%zu\n", tcam_idx, logical_row);
                }

                ASSERT_FALSE(logical_tcam_model[tcam_idx][logical_row]); // must not try to block a blocked row
                logical_tcam_model[tcam_idx][logical_row] = true;        // block

                free_blocks[tcam_idx]--;
                break;
            }

            case lpm_core_tcam_allocator::allocator_instruction::instruction_type_e::UNBLOCK: {
                auto instruction_data
                    = boost::get<lpm_core_tcam_allocator::allocator_instruction::unblock>(instruction.instruction_data);
                size_t tcam_idx = static_cast<size_t>(instruction_data.logical_tcam);
                size_t logical_row = instruction_data.logical_row;
                if (verbose) {
                    printf("instruction=UNBLOCK   TCAM=%zu   row=%zu\n", tcam_idx, logical_row);
                }

                ASSERT_TRUE(logical_tcam_model[tcam_idx][logical_row]); // must not try to unblock a non-blocked row
                logical_tcam_model[tcam_idx][logical_row] = false;      // unblock

                free_blocks[tcam_idx]++;
                break;
            }

            case lpm_core_tcam_allocator::allocator_instruction::instruction_type_e::BLOCK_ALL_FREE_ROWS: {
                auto instruction_data
                    = boost::get<lpm_core_tcam_allocator::allocator_instruction::block_all_free_rows>(instruction.instruction_data);
                size_t tcam_idx = static_cast<size_t>(instruction_data.logical_tcam);
                if (verbose) {
                    printf("instruction=BLOCK_ALL_FREE_ROWS TCAM=%zu\n", tcam_idx);
                }

                for (size_t i = 0; i < logical_tcam_model[tcam_idx].size(); i++) {
                    logical_tcam_model[tcam_idx][i] = true; // block
                }

                free_blocks[tcam_idx] = 0;
                break;
            }
            }
        }
    }

    la_status run_make_space_and_sanity(logical_tcam_type_e logical_tcam,
                                        const std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS>& free_blocks,
                                        lpm_core_tcam_allocator::allocator_instruction_vec& out_instructions)
    {
        lpm_core_tcam_allocator_akpg::allocator_instruction_vec instructions;
        la_status status = s_tcam_allocator->make_space(logical_tcam, free_blocks, instructions);
        s_tcam_allocator->sanity();
        s_tcam_allocator->withdraw();
        s_tcam_allocator->sanity();
        status = s_tcam_allocator->make_space(logical_tcam, free_blocks, out_instructions);
        if (status != LA_STATUS_SUCCESS) {
            return status;
        }

        s_tcam_allocator->commit();
        return status;
    }

    static constexpr uint8_t NUM_BANKSETS = 1;
    static constexpr uint8_t NUM_TCAMS = lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS;
    static std::string name;
};

lpm_core_tcam_allocator_akpg* LpmCoreTcamAllocatorAkpgTest::s_tcam_allocator(nullptr);
std::string LpmCoreTcamAllocatorAkpgTest::name = std::string("Test TCAM Allocator");

TEST_F(LpmCoreTcamAllocatorAkpgTest, BasicTest1Bankset)
{
    s_tcam_allocator = new lpm_core_tcam_allocator_akpg(name, NUM_BANKSETS, 5 /* num_cells_per_bank */);

    vector_alloc<bool> logical_tcam_model[NUM_TCAMS]; /* vector per logical TCAM. true means row is blocked */
    logical_tcam_model[SINGLE_IDX] = vector_alloc<bool>(20, false /* = not blocked */);
    logical_tcam_model[DOUBLE_IDX] = vector_alloc<bool>(10, false /* = not blocked */);
    logical_tcam_model[QUAD_IDX] = vector_alloc<bool>(5, false /* = not blocked */);

    std::array<size_t, NUM_TCAMS> free_blocks;
    free_blocks[SINGLE_IDX] = 20;
    free_blocks[DOUBLE_IDX] = 10;
    free_blocks[QUAD_IDX] = 5;

    lpm_core_tcam_allocator_akpg::allocator_instruction_vec instructions;
    s_tcam_allocator->initialize(true, instructions);
    apply_instructions(logical_tcam_model, free_blocks, instructions);

    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 18U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now we need space for a QUAD block:
    la_status status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    ASSERT_EQ(free_blocks[SINGLE_IDX], 14U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Let's say we want space for DOUBLE:
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 12U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    free_blocks[DOUBLE_IDX] -= 1;
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 10U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    free_blocks[DOUBLE_IDX] -= 1;
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 8U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |        D        |    S   |    S   |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    free_blocks[SINGLE_IDX] = 0;
    free_blocks[DOUBLE_IDX] += 1;
    free_blocks[QUAD_IDX] = 0;

    // Now let's try to make space for another QUAD block
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);
}

TEST_F(LpmCoreTcamAllocatorAkpgTest, BasicTestOor)
{
    s_tcam_allocator = new lpm_core_tcam_allocator_akpg(name, NUM_BANKSETS, 4 /* num_cells_per_bank */);

    vector_alloc<bool> logical_tcam_model[NUM_TCAMS]; /* vector per logical TCAM. true means row is blocked */
    logical_tcam_model[SINGLE_IDX] = vector_alloc<bool>(16, false /* = not blocked */);
    logical_tcam_model[DOUBLE_IDX] = vector_alloc<bool>(8, false /* = not blocked */);
    logical_tcam_model[QUAD_IDX] = vector_alloc<bool>(4, false /* = not blocked */);

    std::array<size_t, NUM_TCAMS> free_blocks;
    free_blocks[SINGLE_IDX] = 16;
    free_blocks[DOUBLE_IDX] = 8;
    free_blocks[QUAD_IDX] = 4;

    lpm_core_tcam_allocator_akpg::allocator_instruction_vec instructions;
    s_tcam_allocator->initialize(true, instructions);
    apply_instructions(logical_tcam_model, free_blocks, instructions);

    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 14U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Let's build a story
    // Let's say SINGLE has consumed 12 of its entries.
    free_blocks[SINGLE_IDX] -= 12;

    // Now we need space for a DOUBLE block:
    la_status status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    free_blocks[DOUBLE_IDX] -= 1;
    // Now we want to make space for a SINGLE, but it should fail
    status = run_make_space_and_sanity(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    instructions.clear();

    free_blocks[SINGLE_IDX] += 6;
    // Now we want to make space for 3 DOUBLE blocks
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);

    free_blocks[DOUBLE_IDX] -= 1;
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);

    free_blocks[DOUBLE_IDX] -= 1;
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |    S   |    S   |   S    |   N    |
    // +--------+--------+--------+--------+
    // |    S   |    S   |   S    |   N    |
    // +--------+--------+--------+--------+
    //

    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now, let's make space for a singles
    status = run_make_space_and_sanity(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 2U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    free_blocks[DOUBLE_IDX] += 1;
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |    S   |    S   |   S    |   N    |
    // +--------+--------+--------+--------+
    // |    S   |    S   |   S    |   N    |
    // +--------+--------+--------+--------+
    //

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    free_blocks[QUAD_IDX] -= 1;
    free_blocks[DOUBLE_IDX] += 2;
    // Now, let's try to make space for a QUAD
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    free_blocks[QUAD_IDX] -= 1;
    free_blocks[SINGLE_IDX] += 4;
    // Now, let's try to make space for a QUAD but it should fail
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
}

TEST_F(LpmCoreTcamAllocatorAkpgTest, BasicWithdrawTest)
{
    s_tcam_allocator = new lpm_core_tcam_allocator_akpg(name, NUM_BANKSETS, 5 /* num_cells_per_bank */);

    vector_alloc<bool> logical_tcam_model[NUM_TCAMS]; /* vector per logical TCAM. true means row is blocked */
    logical_tcam_model[SINGLE_IDX] = vector_alloc<bool>(20, false /* = not blocked */);
    logical_tcam_model[DOUBLE_IDX] = vector_alloc<bool>(10, false /* = not blocked */);
    logical_tcam_model[QUAD_IDX] = vector_alloc<bool>(5, false /* = not blocked */);

    std::array<size_t, NUM_TCAMS> free_blocks;
    free_blocks[SINGLE_IDX] = 20;
    free_blocks[DOUBLE_IDX] = 10;
    free_blocks[QUAD_IDX] = 5;

    lpm_core_tcam_allocator_akpg::allocator_instruction_vec instructions;
    s_tcam_allocator->initialize(true, instructions);
    apply_instructions(logical_tcam_model, free_blocks, instructions);

    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 18U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now we need space for a 4 DOUBLE block:
    for (int i = 0; i < 4; i++) {
        la_status status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[SINGLE_IDX] -= 2;
    }

    free_blocks[SINGLE_IDX] += 8;
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 10U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 4U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    s_tcam_allocator->commit();
    free_blocks[SINGLE_IDX] = 0;

    // Now let's say we need space for QUAD blocks:
    for (int i = 0; i < 2; i++) {
        la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[DOUBLE_IDX] -= 2;
    }

    la_status status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    s_tcam_allocator->withdraw();
    instructions.clear();
    free_blocks[DOUBLE_IDX] += 4;

    // Now let's try again
    for (int i = 0; i < 2; i++) {
        status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[DOUBLE_IDX] -= 2;
    }

    free_blocks[DOUBLE_IDX] += 4;
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 2U);

    free_blocks[QUAD_IDX] -= 2;
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    instructions.clear();
}

TEST_F(LpmCoreTcamAllocatorAkpgTest, AllConvertCases)
{
    s_tcam_allocator = new lpm_core_tcam_allocator_akpg(name, NUM_BANKSETS, 6 /* num_cells_per_bank */);

    vector_alloc<bool> logical_tcam_model[NUM_TCAMS]; /* vector per logical TCAM. true means row is blocked */
    logical_tcam_model[SINGLE_IDX] = vector_alloc<bool>(24, false /* = not blocked */);
    logical_tcam_model[DOUBLE_IDX] = vector_alloc<bool>(12, false /* = not blocked */);
    logical_tcam_model[QUAD_IDX] = vector_alloc<bool>(6, false /* = not blocked */);

    std::array<size_t, NUM_TCAMS> free_blocks;
    free_blocks[SINGLE_IDX] = 24;
    free_blocks[DOUBLE_IDX] = 12;
    free_blocks[QUAD_IDX] = 6;

    lpm_core_tcam_allocator_akpg::allocator_instruction_vec instructions;
    s_tcam_allocator->initialize(true, instructions);
    apply_instructions(logical_tcam_model, free_blocks, instructions);

    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 22U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now lets convert 4 blocks to DOUBLE.
    for (int i = 0; i < 4; i++) {
        la_status status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[SINGLE_IDX] -= 2;
    }

    free_blocks[SINGLE_IDX] += 8;
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 14U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 4U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    // Now lets convert D S S -> QUAD:
    free_blocks[DOUBLE_IDX] = 2;
    free_blocks[SINGLE_IDX] = 0;
    la_status status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |    S   |    S   |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    // Now lets convert S S S S -> QUAD:
    free_blocks[SINGLE_IDX] += 4;
    free_blocks[QUAD_IDX] = 0;
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now lets convert S S -> D:
    free_blocks[SINGLE_IDX] = 4;
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 2U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    // Now lets convert D D -> QUAD:
    free_blocks[DOUBLE_IDX] = 2;
    free_blocks[QUAD_IDX] = 0;
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now lets convert QUAD -> S S S S:
    status = run_make_space_and_sanity(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 4U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |    S   |    S   |    S   |    S   |
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    // Now lets convert S S S S back to QUAD:
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now lets convert D -> S S:
    free_blocks[DOUBLE_IDX] = 1;
    status = run_make_space_and_sanity(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 2U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now lets convert S S D -> QUAD:
    free_blocks[DOUBLE_IDX] += 1;
    free_blocks[QUAD_IDX] = 0;
    status = run_make_space_and_sanity(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now TCAM should look like this:
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   N    |
    // +--------+--------+--------+--------+

    // Now lets convert QUAD -> D D:
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 2U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    free_blocks[DOUBLE_IDX] = 0;
    free_blocks[SINGLE_IDX] = 2;
    status = run_make_space_and_sanity(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    instructions.clear();
}
