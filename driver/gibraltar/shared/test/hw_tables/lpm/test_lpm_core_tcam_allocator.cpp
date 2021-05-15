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
#include "lpm/lpm_core_tcam_allocator.h"
#include "lpm/lpm_core_tcam_allocator_pacific_gb.h"
#include "test_lpm_types.h"
#include "gtest/gtest.h"

using namespace silicon_one;

class LpmCoreTcamAllocatorTest : public ::testing::Test
{
protected:
    static lpm_core_tcam_allocator_pacific_gb* s_tcam_allocator;

    void SetUp()
    {
        silicon_one::la_logger_level_e logger_level
            = verbose ? silicon_one::la_logger_level_e::DEBUG : silicon_one::la_logger_level_e::ERROR;
        logger::instance().set_logging_level(
            silicon_one::logger::NO_DEVICE, silicon_one::la_logger_component_e::TABLES, logger_level);
    }

    void TearDown()
    {
        if (s_tcam_allocator != nullptr) {
            delete s_tcam_allocator;
            s_tcam_allocator = nullptr;
        }
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
                    printf("instruction=BLOCK_ALL_FREE_ROWS   TCAM=%zu\n", tcam_idx);
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

    void initialize(size_t num_banksets,
                    size_t num_cells_per_bank,
                    size_t max_num_quad_blocks,
                    vector_alloc<bool>* logical_tcam_model,
                    std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS>& free_blocks)
    {
        s_tcam_allocator = new lpm_core_tcam_allocator_pacific_gb(
            std::string("Test TCAM Allocator"), num_banksets, num_cells_per_bank, max_num_quad_blocks);

        size_t num_cells = num_banksets * num_cells_per_bank * lpm_core_tcam_allocator::NUM_BANKS_PER_BANKSET;
        logical_tcam_model[SINGLE_IDX] = vector_alloc<bool>(num_cells, false /* = not blocked */);
        logical_tcam_model[DOUBLE_IDX] = vector_alloc<bool>(num_cells / 2, false /* = not blocked */);
        logical_tcam_model[QUAD_IDX] = vector_alloc<bool>(max_num_quad_blocks, false /* = not blocked */);

        free_blocks[SINGLE_IDX] = num_cells;
        free_blocks[DOUBLE_IDX] = num_cells / 2;
        free_blocks[QUAD_IDX] = max_num_quad_blocks;

        lpm_core_tcam_allocator::allocator_instruction_vec instructions;
        s_tcam_allocator->initialize(true /* block_last_block_group */, instructions);
        apply_instructions(logical_tcam_model, free_blocks, instructions);
    }
};

lpm_core_tcam_allocator_pacific_gb* LpmCoreTcamAllocatorTest::s_tcam_allocator(nullptr);

TEST_F(LpmCoreTcamAllocatorTest, BasicTest1Bankset)
{
    vector_alloc<bool> logical_tcam_model[3]; /* vector per logical TCAM. true means row is blocked */
    std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS> free_blocks;
    initialize(1 /* num_banksets */, 4 /* num_cells_per_bank */, 2 /* max_num_quad_blocks */, logical_tcam_model, free_blocks);

    // Current state of TCAM
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 12
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 0

    ASSERT_EQ(free_blocks[SINGLE_IDX], 12U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Let's build a story
    // Let's say SINGLE has consumed 8 of its entries.
    free_blocks[SINGLE_IDX] -= 8;

    // Now:
    // free_blocks[SINGLE_IDX] = 4
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 0
    //
    // Now we need space for a QUAD block:
    lpm_core_tcam_allocator::allocator_instruction_vec instructions;
    la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 0
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 1

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Let's say SINGLE logical TCAM has release 4 SINGLEs (due to remove operation)
    free_blocks[SINGLE_IDX] += 4;

    // free_blocks[SINGLE_IDX] = 4
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 1
    //
    // Now we want to make space for a DOUBLE
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);

    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // This double could have been taken from QUAD, or from SINGLE. Let's check that:
    if (free_blocks[SINGLE_IDX] == 4) {       // not taken from SINGLE
        ASSERT_EQ(free_blocks[QUAD_IDX], 0U); // must've been taken from QUAD
    } else {
        ASSERT_TRUE((free_blocks[SINGLE_IDX] == 2)
                    || (free_blocks[SINGLE_IDX] == 0)); // depends from which area SINGLEs where converted
    }

    // Let's say we consumed this DOUBLE, and now we want space for another one:
    free_blocks[DOUBLE_IDX] -= 1;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // We are no in one of two states:
    //
    // Either this state:
    // +-----------------+--------+--------+
    // |        D        |///N////|///N////|
    // +-----------------+--------+--------+
    // |        D        |///N////|///N////|
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 0
    // free_blocks[DOUBLE_IDX] = 1
    // free_blocks[QUAD_IDX] = 0
    //
    // +-----------------+--------+--------+
    // |        D        |///N////|///N////|
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 2
    // free_blocks[DOUBLE_IDX] = 1
    // free_blocks[QUAD_IDX] = 0
    //
    // Either way, we cannot insert another DOUBLE (first case we have no free SINGLEs at all, second case, we'll need 4 SINGLEs for
    // a DOUBLE).
    // Let's check that:

    free_blocks[DOUBLE_IDX] -= 1;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    instructions.clear();

    // Let's say now we got 4 new SINGLEs released to us (by a remove operation on SINGLE logical TCAM)
    free_blocks[SINGLE_IDX] += 4;

    // Now let's try to make a space for another QUAD
    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();
}

TEST_F(LpmCoreTcamAllocatorTest, BasicTest2Banksets)
{
    vector_alloc<bool> logical_tcam_model[3]; /* vector per logical TCAM. true means row is blocked */
    std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS> free_blocks;
    initialize(2 /* num_banksets */, 4 /* num_cells_per_bank */, 2 /* max_num_quad_blocks */, logical_tcam_model, free_blocks);

    // Current state of TCAM
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 28
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 0

    ASSERT_EQ(free_blocks[SINGLE_IDX], 28U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Let's build a story
    // Let's say SINGLE has consumed 8 of its entries.
    free_blocks[SINGLE_IDX] -= 8;

    // Now:
    // free_blocks[SINGLE_IDX] = 20
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 0
    //
    // Now we need space for a QUAD block:
    lpm_core_tcam_allocator::allocator_instruction_vec instructions;
    la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // Now TCAM should look like this:

    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 16
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 1

    ASSERT_EQ(free_blocks[SINGLE_IDX], 16U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Let's the free QUAD block was consumed
    free_blocks[QUAD_IDX] -= 1;

    // And so were 12 SINGLE blocks consumed as well
    free_blocks[SINGLE_IDX] -= 12;

    // Now we want to make space for a DOUBLE
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);

    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 2U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Let's say we consumed this DOUBLE, and now we want space for another one:
    free_blocks[DOUBLE_IDX] -= 1;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // We're in this state now (consider this as an example only. the accurate state is implementation dependant)
    //
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 0
    // free_blocks[DOUBLE_IDX] = 1
    // free_blocks[QUAD_IDX] = 0

    // Let's try to consume the DOUBLE we have and allocate a new one. We should fail.
    free_blocks[DOUBLE_IDX] -= 1;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    instructions.clear();

    // Let's release one SINGLE, and try again. We should still fail
    free_blocks[SINGLE_IDX] += 1;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
    instructions.clear();

    // Let's now release one more SINGLE, and try again. We should succeed.
    free_blocks[SINGLE_IDX] += 1;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Let's release the QUAD now:
    free_blocks[QUAD_IDX] += 1;

    // Now let's try to have a SINGLE block
    // Now let's try to make a space for another QUAD
    status = s_tcam_allocator->make_space(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 4U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);
}

TEST_F(LpmCoreTcamAllocatorTest, BasicWithdrawTest2Banksets)
{
    vector_alloc<bool> logical_tcam_model[3]; /* vector per logical TCAM. true means row is blocked */
    std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS> free_blocks;
    initialize(2 /* num_banksets */, 4 /* num_cells_per_bank */, 2 /* max_num_quad_blocks */, logical_tcam_model, free_blocks);

    // Current state of TCAM
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 28
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 0

    ASSERT_EQ(free_blocks[SINGLE_IDX], 28U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // let's convert first SINGLEs into QUADs
    lpm_core_tcam_allocator::allocator_instruction_vec instructions;
    la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    free_blocks[QUAD_IDX] -= 1;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);

    // let's consume this QUAD
    free_blocks[QUAD_IDX] -= 1;

    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    s_tcam_allocator->commit();

    // Now TCAM is like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    // Now let's convert all remaining SINGLEs into DOUBLEs (except the 4 ones in BANKSET0 banks 2/3 which cannot be converted)
    // We won't update TCAM state yet because we'll withdraw these changes
    for (size_t i = 0; i < 8; i++) {
        status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[SINGLE_IDX] -= 2;
    }

    // Now we shouldn't be able to create more DOBULEs
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    // Now let's withdraw and see that we can still insert 8 DOUBLEs
    s_tcam_allocator->withdraw();
    free_blocks[SINGLE_IDX] += 16;

    for (size_t i = 0; i < 8; i++) {
        status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[SINGLE_IDX] -= 2;
    }

    // and just to make sure, we should now fail on the 9th one
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
}

TEST_F(LpmCoreTcamAllocatorTest, QuadAlloc)
{
    vector_alloc<bool> logical_tcam_model[3]; /* vector per logical TCAM. true means row is blocked */
    std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS> free_blocks;
    initialize(1 /* num_banksets */, 5 /* num_cells_per_bank */, 3 /* max_num_quad_blocks */, logical_tcam_model, free_blocks);

    // Current state of TCAM
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    ASSERT_EQ(free_blocks[SINGLE_IDX], 16U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now we need space for DOUBLE block:
    lpm_core_tcam_allocator::allocator_instruction_vec instructions;
    la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |   S    |   S    |   S    |   S    |
    // +-----------------------------------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    ASSERT_EQ(free_blocks[SINGLE_IDX], 14U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Let's consume all SINGLE blocks.
    free_blocks[SINGLE_IDX] = 0;

    // Now we want to make space for a QUAD, but should fail
    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    free_blocks[SINGLE_IDX] = 4;
    free_blocks[DOUBLE_IDX] = 0;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +-----------------------------------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    // Let's try again, but should fail
    free_blocks[SINGLE_IDX] = 2;
    free_blocks[DOUBLE_IDX] = 0;
    free_blocks[QUAD_IDX] = 0;

    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    free_blocks[DOUBLE_IDX] = 1;

    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+
    //
    // free_blocks[SINGLE_IDX] = 0
    // free_blocks[DOUBLE_IDX] = 0
    // free_blocks[QUAD_IDX] = 1

    status = s_tcam_allocator->make_space(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 4U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    free_blocks[SINGLE_IDX] = 6;

    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 4U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    free_blocks[DOUBLE_IDX] = 0;

    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +-----------------------------------+
    // |   S    |    S   |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |///N////|///N////|
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    // Let's make space for DOUBLE block:
    free_blocks[SINGLE_IDX] = 6;
    free_blocks[QUAD_IDX] = 0;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 2U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now TCAM should look like this:
    // +-----------------------------------+
    // |                 Q                 |
    // +-----------------------------------+
    // |                 Q                 |
    // +--------+--------+--------+--------+
    // |        D        |///N////|///N////|
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    // Now, let's try to make space for QUAD, but it should fail again.
    free_blocks[DOUBLE_IDX] = 0;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    // Now, let's free DOUBLE, and try again to make space for QUAD.
    free_blocks[DOUBLE_IDX] = 1;
    free_blocks[SINGLE_IDX] = 0;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);
}

TEST_F(LpmCoreTcamAllocatorTest, SingleDoubleAlloc)
{
    vector_alloc<bool> logical_tcam_model[3]; /* vector per logical TCAM. true means row is blocked */
    std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS> free_blocks;
    initialize(2 /* num_banksets */, 4 /* num_cells_per_bank */, 1 /* max_num_quad_blocks */, logical_tcam_model, free_blocks);

    // Current state of TCAM
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    ASSERT_EQ(free_blocks[SINGLE_IDX], 28U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Now we need space for QUAD block:
    lpm_core_tcam_allocator::allocator_instruction_vec instructions;
    la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 24U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Current state of TCAM
    //
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    free_blocks[SINGLE_IDX] = 0;
    // Let's convert QUAD -> DOUBLE
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Let's release DOUBLE from QUAD region to SINGLE.
    status = s_tcam_allocator->make_space(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 4U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Current state of TCAM
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    // Now, let's convert all SINGLE blocks to DOUBLE.
    free_blocks[SINGLE_IDX] = 28;
    for (int i = 0; i < 9; i++) {
        status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[SINGLE_IDX] -= 2;
    }

    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    free_blocks[SINGLE_IDX] = 28;
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 6U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 10U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Current state of TCAM
    //
    // +--------+--------+--------+--------+
    // |        D        |///N////|///N////|
    // +--------+--------+--------+--------+------------  max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    //
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |        D        |        D        |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    free_blocks[DOUBLE_IDX] = 0;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    // Now, let's convert all DOUBLE to SINGLE.
    free_blocks[DOUBLE_IDX] = 10;
    free_blocks[SINGLE_IDX] = 0;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 4U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 9U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    free_blocks[SINGLE_IDX] = 0;
    for (int i = 0; i < 9; i++) {
        status = s_tcam_allocator->make_space(logical_tcam_type_e::SINGLE, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        free_blocks[DOUBLE_IDX] -= 1;
    }

    free_blocks[DOUBLE_IDX] = 9;
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 18U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    free_blocks[SINGLE_IDX] = 0;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::SINGLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);
}

TEST_F(LpmCoreTcamAllocatorTest, DoubleQuadAlloc)
{
    vector_alloc<bool> logical_tcam_model[3]; /* vector per logical TCAM. true means row is blocked */
    std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS> free_blocks;
    initialize(1 /* num_banksets */, 4 /* num_cells_per_bank */, 1 /* max_num_quad_blocks */, logical_tcam_model, free_blocks);

    // Current state of TCAM
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    ASSERT_EQ(free_blocks[SINGLE_IDX], 12U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    lpm_core_tcam_allocator::allocator_instruction_vec instructions;
    for (size_t i = 0; i < 2; i++) {
        la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
        ASSERT_EQ(status, LA_STATUS_SUCCESS);
        apply_instructions(logical_tcam_model, free_blocks, instructions);
        ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
        free_blocks[DOUBLE_IDX] = 0;
        instructions.clear();
    }

    ASSERT_EQ(free_blocks[SINGLE_IDX], 8U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Current state of TCAM
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |        D        |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    // Let's make space for QUAD, but it should fail
    free_blocks[DOUBLE_IDX] = 1;
    free_blocks[SINGLE_IDX] = 0;
    la_status status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_ERESOURCE);

    free_blocks[DOUBLE_IDX] = 2;
    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);

    // Current state of TCAM
    // +--------+--------+--------+--------+
    // |                 Q                 |
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    status = s_tcam_allocator->make_space(logical_tcam_type_e::DOUBLE, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 1U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 0U);

    // Current state of TCAM
    // +--------+--------+--------+--------+
    // |        D        |///N////|///N////|
    // +--------+--------+--------+--------+------------ max_num_of_quad_blocks
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |   S    |   S    |   S    |   S    |
    // +--------+--------+--------+--------+
    // |///N////|///N////|///N////|///N////|
    // +--------+--------+--------+--------+

    status = s_tcam_allocator->make_space(logical_tcam_type_e::QUAD, free_blocks, instructions);
    ASSERT_EQ(status, LA_STATUS_SUCCESS);
    apply_instructions(logical_tcam_model, free_blocks, instructions);
    instructions.clear();

    ASSERT_EQ(free_blocks[SINGLE_IDX], 0U);
    ASSERT_EQ(free_blocks[DOUBLE_IDX], 0U);
    ASSERT_EQ(free_blocks[QUAD_IDX], 1U);
}
