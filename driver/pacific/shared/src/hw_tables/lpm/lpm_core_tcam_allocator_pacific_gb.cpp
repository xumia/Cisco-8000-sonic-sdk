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

#include "lpm_core_tcam_allocator_pacific_gb.h"
#include "common/logger.h"
#include "lpm_core_tcam_utils_base.h"
#include <algorithm>

using namespace silicon_one;

// shortcuts
static constexpr logical_tcam_type_e SINGLE = logical_tcam_type_e::SINGLE;
static constexpr logical_tcam_type_e DOUBLE = logical_tcam_type_e::DOUBLE;
static constexpr logical_tcam_type_e QUAD = logical_tcam_type_e::QUAD;
static constexpr logical_tcam_type_e NOBODY = logical_tcam_type_e::NOBODY;

lpm_core_tcam_allocator_pacific_gb::lpm_core_tcam_allocator_pacific_gb(std::string name,
                                                                       uint8_t num_banksets,
                                                                       uint32_t num_cells_per_bank,
                                                                       uint32_t max_num_quad_blocks)
    : lpm_core_tcam_allocator(name, num_banksets, num_cells_per_bank), m_max_num_quad_blocks(max_num_quad_blocks)
{
    dassert_crit(max_num_quad_blocks <= num_cells_per_bank); // we don't support QUADs in bankset > 0
}

void
lpm_core_tcam_allocator_pacific_gb::block_last_blocks(allocator_instruction_vec& out_instructions)
{
    // Block last block group in last bankset
    for (uint8_t bank = 0; bank < NUM_BANKS_PER_BANKSET; bank++) {
        tcam_cell_location location
            = {.bankset = static_cast<uint8_t>(m_num_banksets - 1), .bank = bank, .cell = m_num_cells_per_bank - 1};
        size_t erased = m_owned_blocks[SINGLE_IDX].erase(location);
        dassert_crit(erased == 1);
        m_owned_blocks[NOBODY_IDX].insert(location);

        m_owner_of_block[location] = logical_tcam_type_e::NOBODY;

        size_t single_logical_row = translate_location_to_logical_row(logical_tcam_type_e::SINGLE, location);

        allocator_instruction instruction;
        instruction.instruction_type = allocator_instruction::instruction_type_e::BLOCK;
        instruction.instruction_data = allocator_instruction::block{.logical_tcam = SINGLE, .logical_row = single_logical_row};

        out_instructions.push_back(instruction);
    }
}

//   The physical TCAM is composed of 1 or more banksets. Each bankset is composed of 4 banks.
//   We partition the TCAM into different regions, each has its own set of allowed combinations of blocks within a block group.
//   1. QUAD region: This region contains only QUAD blocks. It is a dynamic region: It grows and shrinks as needed.
//   2. HARDWARE_QUAD region: This is the region after QUAD region, and until max_num_of_quad_blocks.
//      The bottom border of this region is fixed by software. In this region, DOUBLE blocks are considered QUAD by the hardware,
//      because they are above the "max_num_of_quad_blocks" which is configured to the hardware.
//      This means that DOUBLE blocks cannot have neigbors in the same block group in this region.
//   3. BANKSET0 region: This is the rest of Bankset 0. A block group of this region can consist of DOUBLE and SINGLE blocks.
//      DOUBLE blocks must be aligned to bank 0 in this region.
//   4. BANKSETN region: Rest of the TCAM. A block group of this region can consist of DOUBLE and SINGLE blocks.
//      DOUBLE blocks must be aligned to bank 0 or bank 2 in this region.
//
//   When we make space for a block of any type, we assume AND maintain the above constraints. Illustrated in the figure below.
//
//
//
//              Bankset = 0
//
//   Bank 0   Bank 1   Bank 2   Bank 3
// +-----------------------------------+--------------------
// |                 Q                 |
// +-----------------------------------+      QUAD Region
// |                 Q                 |
// +-----------------------------------+
// |                 Q                 |
// +-----------------+--------+--------+--------------------
// |        D        |///N////|///N////|
// +--------+--------+--------+--------+    HARDWARE_QUAD
// |   S    |   S    |   S    |   S    |        Region
// +--------+--------+--------+--------+
// |        D        |///N////|///N////|
// +-----------------+--------+--------+-------------------- max_num_of_quad_blocks
// |        D        |   S    |   S    |
// +--------+--------+--------+--------+
// |   S    |   S    |   S    |   S    |  BANKSET0 Region
// +--------+--------+--------+--------+
// |        D        |   S    |   S    |
// +-----------------+--------+--------+--------------------
//
//
//              Bankset = 1
//
//   Bank 0   Bank 1   Bank 2   Bank 3
// +-----------------+--------+--------+--------------------
// |        D        |   S    |   S    |
// +--------+--------+--------+--------+
// |   S    |   S    |   S    |   S    |
// +--------+--------+--------+--------+  BANKSETN Region
// |        D        |        D        |
// +--------+--------+-----------------+
// |   S    |   S    |        D        |
// +--------+--------+-----------------+--------------------

la_status
lpm_core_tcam_allocator_pacific_gb::make_space(logical_tcam_type_e logical_tcam,
                                               const free_blocks_array& free_blocks,
                                               allocator_instruction_vec& out_instructions)
{

    log_debug(TABLES,
              "%s: %s   logical_tcam=%s  free_blocks={S=%zu,D=%zu,Q=%zu}",
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

    size_t blocks_given = 0;

    allocator_instruction_vec instructions;
    free_blocks_array free_spaces = free_blocks;

    switch (logical_tcam) {
    case logical_tcam_type_e::SINGLE: {
        blocks_given = make_space_for_a_single_block(free_spaces, instructions);
        break;
    }

    case logical_tcam_type_e::DOUBLE: {
        blocks_given = make_space_for_a_double_block(free_spaces, instructions);
        break;
    }

    case logical_tcam_type_e::QUAD: {
        blocks_given = make_space_for_a_quad_block(free_spaces, instructions);
        break;
    }

    default:
        dassert_crit(false);
        return LA_STATUS_EUNKNOWN;
    }

    if (blocks_given == 0) {
        return LA_STATUS_ERESOURCE;
    }

    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
    return LA_STATUS_SUCCESS;
}

lpm_core_tcam_allocator_pacific_gb::tcam_region_e
lpm_core_tcam_allocator_pacific_gb::get_tcam_region_of_location(tcam_cell_location location) const
{
    log_xdebug(TABLES, "%s: %s   location=%s", m_name.c_str(), __func__, location.to_string().c_str());

    tcam_cell_location left_aligned_location = location;
    left_aligned_location.bank = 0;

    if (left_aligned_location.bankset > 0) {
        log_xdebug(TABLES, "%s: %s   region=BANKSETN", m_name.c_str(), __func__);
        return tcam_region_e::BANKSETN;
    }

    logical_tcam_type_e owner = get_owner_of_location(left_aligned_location);
    if (owner == QUAD) {
        log_xdebug(TABLES, "%s: %s   region=QUAD", m_name.c_str(), __func__);
        return tcam_region_e::QUAD;
    }

    size_t quad_logical_row = translate_location_to_logical_row(QUAD, left_aligned_location);
    if (quad_logical_row < m_max_num_quad_blocks) {
        log_xdebug(TABLES, "%s: %s   region=HARDWARE_QUAD", m_name.c_str(), __func__);
        return tcam_region_e::HARDWARE_QUAD;
    }

    log_xdebug(TABLES, "%s: %s   region=BANKSET0", m_name.c_str(), __func__);
    return tcam_region_e::BANKSET0;
}

size_t
lpm_core_tcam_allocator_pacific_gb::make_space_for_a_single_block(free_blocks_array& free_blocks,
                                                                  allocator_instruction_vec& out_instructions)
{
    log_xdebug(TABLES, "%s: %s", m_name.c_str(), __func__);

    // Convert last QUAD block into 4 SINGLE blocks
    if (free_blocks[QUAD_IDX] > 0) {
        size_t released = try_convert(QUAD, /* owner */
                                      search_direction_e::BOTTOM,
                                      tcam_region_e::QUAD,              /* Region to search in */
                                      {QUAD},                           /* convert_from_block_group */
                                      {SINGLE, SINGLE, SINGLE, SINGLE}, /* convert_to_block_group */
                                      4,                                /* alignment */
                                      4,                                /* release blocks */
                                      free_blocks,
                                      out_instructions);
        if (released > 0) {
            return released;
        }
    }

    // Convert a DOUBLE from HARDWARE_QUAD region into 4 SINGLE blocks
    // or a DOUBLE from BANKSET0/BANKSETN into 2 SINGLE blocks (alignment requirements differ).
    if (free_blocks[DOUBLE_IDX] > 0) {
        size_t released = try_convert(DOUBLE, /* owner */
                                      search_direction_e::TOP,
                                      tcam_region_e::HARDWARE_QUAD,     /* Region to search in */
                                      {DOUBLE, NOBODY, NOBODY},         /* convert_from_block_group */
                                      {SINGLE, SINGLE, SINGLE, SINGLE}, /* convert_to_block_group */
                                      4,                                /* alignment */
                                      4,                                /* release blocks */
                                      free_blocks,
                                      out_instructions);
        if (released > 0) {
            return released;
        }

        released = try_convert(DOUBLE, /* owner */
                               search_direction_e::TOP,
                               tcam_region_e::BANKSET0, /* Region to search in */
                               {DOUBLE},                /* convert_from_block_group */
                               {SINGLE, SINGLE},        /* convert_to_block_group */
                               4,                       /* alignment */
                               2,                       /* release blocks */
                               free_blocks,
                               out_instructions);
        if (released > 0) {
            return released;
        }

        released = try_convert(DOUBLE, /* owner */
                               search_direction_e::BOTTOM,
                               tcam_region_e::BANKSETN, /* Region to search in */
                               {DOUBLE},                /* convert_from_block_group */
                               {SINGLE, SINGLE},        /* convert_to_block_group */
                               2,                       /* alignment */
                               2,                       /* release blocks */
                               free_blocks,
                               out_instructions);
        if (released > 0) {
            return released;
        }
    }

    return 0;
}

size_t
lpm_core_tcam_allocator_pacific_gb::make_space_for_a_double_block(free_blocks_array& free_blocks,
                                                                  allocator_instruction_vec& out_instructions)
{
    log_xdebug(TABLES, "%s: %s", m_name.c_str(), __func__);

    // Try to convert a SINGLE block from BANKSETN or BANKSET0 (alignment requirementes differe)
    if (free_blocks[SINGLE_IDX] >= 2) {
        size_t released = try_convert(SINGLE, /* owner */
                                      search_direction_e::BOTTOM,
                                      tcam_region_e::BANKSETN, /* Region to search in */
                                      {SINGLE, SINGLE},        /* convert_from_block_group */
                                      {DOUBLE},                /* convert_to_block_group */
                                      2,                       /* alignment */
                                      1,                       /* release blocks */
                                      free_blocks,
                                      out_instructions);
        if (released > 0) {
            return released;
        }

        released = try_convert(SINGLE, /* owner */
                               search_direction_e::BOTTOM,
                               tcam_region_e::BANKSET0, /* Region to search in */
                               {SINGLE, SINGLE},        /* convert_from_block_group */
                               {DOUBLE},                /* convert_to_block_group */
                               4,                       /* alignment */
                               1,                       /* release blocks */
                               free_blocks,
                               out_instructions);
        if (released > 0) {
            return released;
        }
    }

    // Try to convert a SINGLE block from HARDWARE_QUAD region. This is expensive as it consumes 4 SINGLE blocks for 1 DOUBLE.
    if (free_blocks[SINGLE_IDX] >= 4) {
        size_t released = try_convert(SINGLE, /* owner */
                                      search_direction_e::BOTTOM,
                                      tcam_region_e::HARDWARE_QUAD,     /* Region to search in */
                                      {SINGLE, SINGLE, SINGLE, SINGLE}, /* convert_from_block_group */
                                      {DOUBLE, NOBODY, NOBODY},         /* convert_to_block_group */
                                      4,                                /* alignment */
                                      1,                                /* release blocks */
                                      free_blocks,
                                      out_instructions);
        if (released > 0) {
            return released;
        }
    }

    // Try to convert the last QUAD block into 1 DOUBLE block + 2 x NOBODY blocks
    if (free_blocks[QUAD_IDX] > 0) {
        size_t released = try_convert(QUAD, /* owner */
                                      search_direction_e::BOTTOM,
                                      tcam_region_e::QUAD,      /* Region to search in */
                                      {QUAD},                   /* convert_from_block_group */
                                      {DOUBLE, NOBODY, NOBODY}, /* convert_to_block_group */
                                      4,                        /* alignment */
                                      1,                        /* release blocks */
                                      free_blocks,
                                      out_instructions);
        if (released > 0) {
            return released;
        }
    }

    return 0;
}

size_t
lpm_core_tcam_allocator_pacific_gb::make_space_for_a_quad_block(free_blocks_array& free_blocks,
                                                                allocator_instruction_vec& out_instructions)
{

    // QUAD needs special handling because it has special rules:
    // 1. It has to be contiguous.
    // 2. It cannot cross the max_num_quad_blocks line
    // Hence, we always have to convert the line immediately after QUAD into QUAD,
    //    and make all required arrangements for this to happen (e.g., if this line has DOUBLE, but we have no free DOUBLEs, we'll
    //    create some by converting SINGLEs into DOUBLE first).

    log_xdebug(TABLES, "%s: %s", m_name.c_str(), __func__);

    tcam_cell_location bottommost_location;
    la_status status = get_bottommost_block(QUAD, bottommost_location);

    size_t quad_logical_row_to_convert;
    if (status == LA_STATUS_SUCCESS) {
        quad_logical_row_to_convert = translate_location_to_logical_row(QUAD, bottommost_location) + 1;
    } else { // QUAD region is currently empty
        quad_logical_row_to_convert = 0;
    }

    dassert_crit(quad_logical_row_to_convert <= m_max_num_quad_blocks);

    if (quad_logical_row_to_convert == m_max_num_quad_blocks) {
        log_warning(TABLES, "%s: %s: Cannot allocate any more QUAD blocks. Already at maximum", m_name.c_str(), __func__);
        return 0;
    }

    tcam_cell_location location_to_convert = translate_logical_row_to_location(QUAD, quad_logical_row_to_convert);
    dassert_crit(location_to_convert.bankset == 0);
    dassert_crit(location_to_convert.bank == 0);

    // We have 2 options for current owners, either {(S), S, S, S}, or {(D), N, N}
    logical_tcam_type_e current_owner = get_owner_of_location(location_to_convert);

    size_t withdraw_marker_id = push_marker_to_withdraw_stack();

    if (current_owner == logical_tcam_type_e::SINGLE) { //{S, S, S, S} case
        dassert_crit(is_block_group_equal_to(location_to_convert, {SINGLE, SINGLE, SINGLE, SINGLE}));

        size_t free_single_blocks = free_blocks[SINGLE_IDX];

        // We can't choose which line to convert, the line immediately following QUAD region is {S, S, S, S}, that's a given..
        // Now, we might not have enough (4) free SINGLE blocks in order to convert this block group into a QUAD.
        // In that case, we'll try to convert a DOUBLE or 2 into SINGLEs. Then we'll have enough free SINGLE blocks
        // to perform the convertsions.
        while (free_single_blocks < 4) {
            dassert_crit(free_blocks[QUAD_IDX] == 0);
            size_t space_given = make_space_for_a_single_block(free_blocks, out_instructions);
            if (space_given == 0) {
                withdraw_upto_marker(withdraw_marker_id);
                return 0;
            }

            free_single_blocks += space_given;
        }

        convert_block_group(location_to_convert, {QUAD}, free_blocks, out_instructions);
        return 1;

    } else { //{D, N, N} case
        dassert_crit(is_block_group_equal_to(location_to_convert, {DOUBLE, NOBODY, NOBODY}));

        // Same as before, The line is {D, N, N}, we have no choice here. If we don't have a free DOUBLE, we'll convert some SINGLEs
        // into a DOUBLE.
        size_t free_double_blocks = free_blocks[DOUBLE_IDX];
        if (free_double_blocks == 0) {
            dassert_crit(free_blocks[QUAD_IDX] == 0);
            size_t space_given = make_space_for_a_double_block(free_blocks, out_instructions);
            free_double_blocks = space_given;
        }

        if (free_double_blocks == 0) {
            return 0;
        }

        convert_block_group(location_to_convert, {QUAD}, free_blocks, out_instructions);
        return 1;
    }

    dassert_crit(false);
    return 0;
}

la_status
lpm_core_tcam_allocator_pacific_gb::get_topmost_block(logical_tcam_type_e logical_tcam, tcam_cell_location& out_location) const
{
    size_t tcam_idx = static_cast<size_t>(logical_tcam);
    auto it = m_owned_blocks[tcam_idx].begin();
    if (it == m_owned_blocks[tcam_idx].end()) {
        return LA_STATUS_ERESOURCE;
    }

    out_location = *it;

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_tcam_allocator_pacific_gb::get_bottommost_block(logical_tcam_type_e logical_tcam, tcam_cell_location& out_location) const
{
    size_t tcam_idx = static_cast<size_t>(logical_tcam);
    auto it = m_owned_blocks[tcam_idx].rbegin();
    if (it == m_owned_blocks[tcam_idx].rend()) {
        return LA_STATUS_ERESOURCE;
    }

    out_location = *it;

    return LA_STATUS_SUCCESS;
}

bool
lpm_core_tcam_allocator_pacific_gb::is_block_group_equal_to(tcam_cell_location location,
                                                            const vector_alloc<logical_tcam_type_e>& query) const
{
    tcam_cell_location current_location = location;

    for (const auto& q : query) {
        dassert_crit(current_location.bank < NUM_BANKS_PER_BANKSET);

        logical_tcam_type_e owner = get_owner_of_location(current_location);
        if (owner != q) {
            return false;
        }

        current_location.bank += lpm_core_tcam_utils_base::get_num_cells_in_block_type(q);
    }

    return true;
}

uint8_t
lpm_core_tcam_allocator_pacific_gb::get_num_cells_in_block_group(const vector_alloc<logical_tcam_type_e>& block_group) const
{
    size_t num_cells = 0;

    for (const auto& block : block_group) {
        num_cells += lpm_core_tcam_utils_base::get_num_cells_in_block_type(block);
    }

    return num_cells;
}

size_t
lpm_core_tcam_allocator_pacific_gb::try_convert(logical_tcam_type_e current_owner,
                                                search_direction_e search_direction,
                                                tcam_region_e region_to_search_in,
                                                const vector_alloc<logical_tcam_type_e>& convert_from_block_group,
                                                const vector_alloc<logical_tcam_type_e>& convert_to_block_group,
                                                size_t alignment,
                                                size_t release_blocks,
                                                free_blocks_array& free_blocks,
                                                allocator_instruction_vec& out_instructions)
{
    dassert_crit(get_num_cells_in_block_group(convert_from_block_group) == get_num_cells_in_block_group(convert_to_block_group));

    tcam_cell_location location_to_convert;

    auto search_condition_lambda = [&](const tcam_cell_location& location) {
        if (location.bank % alignment != 0) {
            return false;
        }

        tcam_region_e region = get_tcam_region_of_location(location);
        if (region != region_to_search_in) {
            return false;
        }

        bool block_group_content_match = is_block_group_equal_to(location, convert_from_block_group);
        if (!block_group_content_match) {
            return false;
        }

        return true;
    };

    size_t tcam_idx = static_cast<size_t>(current_owner);
    if (search_direction == search_direction_e::TOP) {
        auto it = std::find_if(m_owned_blocks[tcam_idx].begin(), m_owned_blocks[tcam_idx].end(), search_condition_lambda);
        if (it == m_owned_blocks[tcam_idx].end()) {
            return 0;
        }

        location_to_convert = *it;
    } else {
        auto it = std::find_if(m_owned_blocks[tcam_idx].rbegin(), m_owned_blocks[tcam_idx].rend(), search_condition_lambda);
        if (it == m_owned_blocks[tcam_idx].rend()) {
            return 0;
        }

        location_to_convert = *it;
    }

    convert_block_group(location_to_convert, convert_to_block_group, free_blocks, out_instructions);

    return release_blocks;
}

void
lpm_core_tcam_allocator_pacific_gb::convert_block_group(tcam_cell_location location,
                                                        const vector_alloc<logical_tcam_type_e>& new_owners_list,
                                                        free_blocks_array& free_blocks,
                                                        allocator_instruction_vec& out_instructions)
{
    log_debug(TABLES,
              "%s: %s  location=%s  new_owners=%s",
              m_name.c_str(),
              __func__,
              location.to_string().c_str(),
              logical_tcam_vector_to_string(new_owners_list).c_str());

    // calculate how many cells we are going to convert
    uint8_t num_cells_in_new_owners_list = get_num_cells_in_block_group(new_owners_list);

    dassert_crit(location.bank + num_cells_in_new_owners_list <= NUM_BANKS_PER_BANKSET);

    // First let's kick the current occupants of these cells out
    tcam_cell_location current_location = location;

    while (current_location.bank < location.bank + num_cells_in_new_owners_list) {
        logical_tcam_type_e current_owner = get_owner_of_location(current_location);
        size_t current_owner_idx = static_cast<size_t>(current_owner);

        atom_give_up_ownership_of_location(current_owner, current_location, true /* update_withdraw_stack */);
        free_blocks[current_owner_idx]--;

        if (current_owner != logical_tcam_type_e::NOBODY) {
            size_t logical_row = translate_location_to_logical_row(current_owner, current_location);
            allocator_instruction instruction;
            instruction.instruction_type = allocator_instruction::instruction_type_e::BLOCK;
            instruction.instruction_data = allocator_instruction::block{.logical_tcam = current_owner, .logical_row = logical_row};

            out_instructions.push_back(instruction);
        }

        current_location.bank += lpm_core_tcam_utils_base::get_num_cells_in_block_type(current_owner);
    }

    dassert_crit(current_location.bank == location.bank + num_cells_in_new_owners_list);

    // Now let's take their place
    current_location = location;
    for (auto new_owner : new_owners_list) {
        dassert_crit(current_location.bank < NUM_BANKS_PER_BANKSET);

        size_t new_owner_idx = static_cast<size_t>(new_owner);
        atom_take_ownership_of_location(new_owner, current_location, true /* update_withdraw_stack */);
        free_blocks[new_owner_idx]++;

        if (new_owner != logical_tcam_type_e::NOBODY) {
            size_t logical_row = translate_location_to_logical_row(new_owner, current_location);
            allocator_instruction instruction;
            instruction.instruction_type = allocator_instruction::instruction_type_e::UNBLOCK;
            instruction.instruction_data = allocator_instruction::unblock{.logical_tcam = new_owner, .logical_row = logical_row};

            out_instructions.push_back(instruction);
        }

        current_location.bank += lpm_core_tcam_utils_base::get_num_cells_in_block_type(new_owner);
    }

    dassert_crit(current_location.bank - location.bank == num_cells_in_new_owners_list);
}

size_t
lpm_core_tcam_allocator_pacific_gb::get_max_quad_blocks() const
{
    return m_max_num_quad_blocks;
}
