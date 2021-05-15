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

#include "lpm_core_tcam_allocator_akpg.h"
#include "common/logger.h"
#include "lpm_core_tcam_utils_base.h"

namespace silicon_one
{

lpm_core_tcam_allocator_akpg::lpm_core_tcam_allocator_akpg(std::string name, uint8_t num_banksets, uint32_t num_cells_per_bank)
    : lpm_core_tcam_allocator(name, num_banksets, num_cells_per_bank), m_last_portable_line(num_cells_per_bank - 3)
{
}

void
lpm_core_tcam_allocator_akpg::block_last_blocks(allocator_instruction_vec& out_instructions)
{
    // Block last two cells in last bank, one for IPv4 and one for IPv6 default entry.
    uint8_t bankset = static_cast<uint8_t>(m_num_banksets - 1);
    uint8_t bank = NUM_BANKS_PER_BANKSET - 1;
    for (uint32_t cell = m_num_cells_per_bank - 1; cell > m_last_portable_line; cell--) {
        tcam_cell_location location = {.bankset = bankset, .bank = bank, .cell = cell};
        auto owned_blocks_it = m_owned_blocks[SINGLE_IDX].find(location);
        dassert_crit(owned_blocks_it != m_owned_blocks[SINGLE_IDX].end());
        m_owned_blocks[SINGLE_IDX].erase(owned_blocks_it);
        m_owned_blocks[NOBODY_IDX].insert(location);

        m_owner_of_block[location] = logical_tcam_type_e::NOBODY;

        size_t single_logical_row = translate_location_to_logical_row(logical_tcam_type_e::SINGLE, location);

        allocator_instruction instruction;
        instruction.instruction_type = allocator_instruction::instruction_type_e::BLOCK;
        instruction.instruction_data
            = allocator_instruction::block{.logical_tcam = logical_tcam_type_e::SINGLE, .logical_row = single_logical_row};

        out_instructions.push_back(instruction);
    }
}

la_status
lpm_core_tcam_allocator_akpg::make_space(logical_tcam_type_e logical_tcam,
                                         const free_blocks_array& free_blocks,
                                         allocator_instruction_vec& out_instructions)
{
    log_debug(TABLES,
              "%s: %s   logical_tcam=%s  free_blocks={S=%zu, D=%zu, Q=%zu}",
              m_name.c_str(),
              __func__,
              logical_tcam_to_string(logical_tcam).c_str(),
              free_blocks[SINGLE_IDX],
              free_blocks[DOUBLE_IDX],
              free_blocks[QUAD_IDX]);

    dassert_crit(free_blocks[SINGLE_IDX] <= m_owned_blocks[SINGLE_IDX].size());
    dassert_crit(free_blocks[DOUBLE_IDX] <= m_owned_blocks[DOUBLE_IDX].size());
    dassert_crit(free_blocks[QUAD_IDX] <= m_owned_blocks[QUAD_IDX].size());

    size_t tcam_idx = static_cast<size_t>(logical_tcam);
    if (free_blocks[tcam_idx] > 0) {
        return LA_STATUS_SUCCESS;
    }

    free_blocks_array free_spaces = free_blocks;

    allocator_instruction_vec instructions;
    la_status status = make_space_for_a_block(logical_tcam, free_spaces, instructions);
    return_on_error(status);

    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_tcam_allocator_akpg::make_space_for_a_block(logical_tcam_type_e dst_logical_tcam,
                                                     free_blocks_array& free_blocks,
                                                     allocator_instruction_vec& out_instructions)
{
    size_t alignment = lpm_core_tcam_utils_base::get_num_cells_in_block_type(dst_logical_tcam);

    for (logical_tcam_type_e src_logical_tcam :
         {logical_tcam_type_e::SINGLE, logical_tcam_type_e::DOUBLE, logical_tcam_type_e::QUAD}) {
        size_t src_tcam_idx = static_cast<size_t>(src_logical_tcam);
        if (free_blocks[src_tcam_idx] == 0) {
            continue;
        }

        la_status status = try_convert(src_logical_tcam, dst_logical_tcam, free_blocks, alignment, out_instructions);
        if (status != LA_STATUS_ENOTFOUND) { // LA_STATUS_ERESOURCE or LA_STATUS_SUCCESS
            return status;
        }
    }

    return LA_STATUS_ERESOURCE;
}

la_status
lpm_core_tcam_allocator_akpg::try_convert(logical_tcam_type_e owner_logical_tcam,
                                          const logical_tcam_type_e& dst_logical_tcam,
                                          free_blocks_array& free_blocks,
                                          size_t alignment,
                                          allocator_instruction_vec& out_instructions)
{
    tcam_cell_location location_to_convert;
    size_t owner_tcam_idx = static_cast<size_t>(owner_logical_tcam);
    for (auto it = m_owned_blocks[owner_tcam_idx].begin(); it != m_owned_blocks[owner_tcam_idx].end(); it++) {
        const tcam_cell_location& location = *it;

        if (location.cell > m_last_portable_line && location.bankset == (m_num_banksets - 1)) {
            // To make sure we catch SW/HW bugs the last two 40bits blocks are assigned to NOBODY and contain default V4/V6 values.
            // As a result we don't want to convert any cell in the last 2 lines.
            continue;
        }

        location_to_convert = location;
        // Align location in that block group.
        location_to_convert.bank = location.bank - (location.bank % alignment);

        la_status status = convert_block_group(location_to_convert, dst_logical_tcam, free_blocks, out_instructions);
        return status;
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
lpm_core_tcam_allocator_akpg::convert_block_group(const tcam_cell_location& location,
                                                  logical_tcam_type_e new_owner,
                                                  free_blocks_array& free_blocks,
                                                  allocator_instruction_vec& out_instructions)
{
    uint8_t num_cells_to_acquire = lpm_core_tcam_utils_base::get_num_cells_in_block_type(new_owner);
    size_t last_bank = location.bank + num_cells_to_acquire - 1;

    dassert_crit(last_bank < NUM_BANKS_PER_BANKSET);

    tcam_cell_location current_location = location;

    uint8_t num_released_cells = 0;
    while (current_location.bank <= last_bank) {
        logical_tcam_type_e current_owner = get_owner_of_location(current_location);
        dassert_crit(current_owner != logical_tcam_type_e::NOBODY);

        size_t current_owner_idx = static_cast<size_t>(current_owner);
        if (free_blocks[current_owner_idx] == 0) {
            la_status status = make_space_for_a_block(current_owner, free_blocks, out_instructions);
            return_on_error(status);
        }

        atom_give_up_ownership_of_location(current_owner, current_location, true /* update_withdraw_stack */);
        free_blocks[current_owner_idx]--;

        size_t logical_row = translate_location_to_logical_row(current_owner, current_location);
        allocator_instruction instruction;
        instruction.instruction_type = allocator_instruction::instruction_type_e::BLOCK;
        instruction.instruction_data = allocator_instruction::block{.logical_tcam = current_owner, .logical_row = logical_row};
        out_instructions.push_back(instruction);

        size_t num_cells_in_current_block = lpm_core_tcam_utils_base::get_num_cells_in_block_type(current_owner);
        current_location.bank += num_cells_in_current_block;
        num_released_cells += num_cells_in_current_block;
    }

    dassert_crit(num_released_cells >= num_cells_to_acquire);
    current_location = location;
    size_t number_of_blocks_to_take = num_released_cells / num_cells_to_acquire;
    for (size_t block = 0; block < number_of_blocks_to_take; block++) {
        dassert_crit(current_location.bank <= NUM_BANKS_PER_BANKSET);
        atom_take_ownership_of_location(new_owner, current_location, true /* update_withdraw_stack */);
        size_t new_owner_idx = static_cast<size_t>(new_owner);
        free_blocks[new_owner_idx]++;

        size_t logical_row = translate_location_to_logical_row(new_owner, current_location);
        allocator_instruction instruction;
        instruction.instruction_type = allocator_instruction::instruction_type_e::UNBLOCK;
        instruction.instruction_data = allocator_instruction::unblock{.logical_tcam = new_owner, .logical_row = logical_row};
        out_instructions.push_back(instruction);

        current_location.bank += num_cells_to_acquire;
    }

    dassert_crit(current_location.bank - location.bank == num_released_cells); // All given cells should be taken.

    return LA_STATUS_SUCCESS;
}

size_t
lpm_core_tcam_allocator_akpg::get_max_quad_blocks() const
{
    dassert_crit(false); // Pacific/GB specific
    return 0;
}

} // namespace silicon_one
