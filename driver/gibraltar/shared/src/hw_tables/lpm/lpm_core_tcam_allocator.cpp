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

#include "lpm_core_tcam_allocator.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lpm_core_tcam_utils_base.h"

namespace silicon_one
{

lpm_core_tcam_allocator::lpm_core_tcam_allocator(std::string name, uint8_t num_banksets, uint32_t num_cells_per_bank)
    : m_name(name), m_num_banksets(num_banksets), m_num_cells_per_bank(num_cells_per_bank), m_withdraw_stack_marker_id(0)
{
}

lpm_core_tcam_allocator::~lpm_core_tcam_allocator()
{
    return;
}

void
lpm_core_tcam_allocator::initialize(bool block_last_block_group, allocator_instruction_vec& out_instructions)
{
    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);

    tcam_cell_locations_set& single_tcam_set = m_owned_blocks[static_cast<size_t>(logical_tcam_type_e::SINGLE)];
    for (uint8_t bankset = 0; bankset < m_num_banksets; bankset++) {
        for (uint8_t bank = 0; bank < NUM_BANKS_PER_BANKSET; bank++) {
            for (uint32_t cell = 0; cell < m_num_cells_per_bank; cell++) {
                tcam_cell_location location = {.bankset = bankset, .bank = bank, .cell = cell};
                single_tcam_set.insert(location);
                m_owner_of_block.insert(std::make_pair(location, logical_tcam_type_e::SINGLE));
            }
        }
    }

    // Block all logical rows in DOUBLE and QUAD TCAM
    allocator_instruction instruction;
    for (auto logical_tcam : {logical_tcam_type_e::DOUBLE, logical_tcam_type_e::QUAD}) {
        instruction.instruction_type = allocator_instruction::instruction_type_e::BLOCK_ALL_FREE_ROWS;
        instruction.instruction_data = allocator_instruction::block_all_free_rows{.logical_tcam = logical_tcam};
        out_instructions.push_back(instruction);
    }

    if (block_last_block_group) {
        block_last_blocks(out_instructions);
    }
}

void
lpm_core_tcam_allocator::atom_give_up_ownership_of_location(logical_tcam_type_e current_owner,
                                                            tcam_cell_location location,
                                                            bool update_withdraw_stack)
{
    log_debug(TABLES,
              "%s: %s  current_owner=%s  location=%s  update_withdraw_stack=%d",
              m_name.c_str(),
              __func__,
              logical_tcam_to_string(current_owner).c_str(),
              location.to_string().c_str(),
              update_withdraw_stack);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_GIVE_UP_OWNERSHIP;
        waction.action_data = withdraw_action::withdraw_give_up_ownership{.location = location, .logical_tcam = current_owner};
        m_withdraw_stack.push_back(waction);
    }

    size_t tcam_idx = static_cast<size_t>(current_owner);
    size_t erased = m_owned_blocks[tcam_idx].erase(location);
    dassert_crit(erased == 1);

    auto it = m_owner_of_block.find(location);
    dassert_crit(it != m_owner_of_block.end());
    m_owner_of_block.erase(it);
}

void
lpm_core_tcam_allocator::atom_take_ownership_of_location(logical_tcam_type_e new_owner,
                                                         tcam_cell_location location,
                                                         bool update_withdraw_stack)
{
    log_debug(TABLES,
              "%s: %s  new_owner=%s  location=%s  update_withdraw_stack=%d",
              m_name.c_str(),
              __func__,
              logical_tcam_to_string(new_owner).c_str(),
              location.to_string().c_str(),
              update_withdraw_stack);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TAKE_OWNERSHIP;
        waction.action_data = withdraw_action::withdraw_take_ownership{.location = location, .logical_tcam = new_owner};
        m_withdraw_stack.push_back(waction);
    }

    size_t tcam_idx = static_cast<size_t>(new_owner);
    dassert_slow(!contains(m_owned_blocks[tcam_idx], location));

    m_owned_blocks[tcam_idx].insert(location);
    m_owner_of_block[location] = new_owner;
}

size_t
lpm_core_tcam_allocator::translate_location_to_logical_row(logical_tcam_type_e logical_tcam, tcam_cell_location location) const
{
    size_t cells_per_block = lpm_core_tcam_utils_base::get_num_cells_in_block_type(logical_tcam);
    size_t logical_rows_per_bankset = NUM_BANKS_PER_BANKSET / cells_per_block * m_num_cells_per_bank;
    size_t logical_row
        = location.bankset * logical_rows_per_bankset + (location.bank / cells_per_block) * m_num_cells_per_bank + location.cell;

    log_xdebug(TABLES,
               "%s: %s  logical_tcam=%s  location=%s  logical_row=%zu",
               m_name.c_str(),
               __func__,
               logical_tcam_to_string(logical_tcam).c_str(),
               location.to_string().c_str(),
               logical_row);

    return logical_row;
}

tcam_cell_location
lpm_core_tcam_allocator::translate_logical_row_to_location(logical_tcam_type_e logical_tcam, size_t logical_row) const
{
    size_t cells_per_block = lpm_core_tcam_utils_base::get_num_cells_in_block_type(logical_tcam);
    size_t num_blocks_per_bankset = (NUM_BANKS_PER_BANKSET / cells_per_block) * m_num_cells_per_bank;

    tcam_cell_location location;
    location.bankset = logical_row / num_blocks_per_bankset;
    size_t remainder = logical_row % num_blocks_per_bankset;

    location.bank = (remainder / m_num_cells_per_bank) * cells_per_block;
    remainder = remainder % m_num_cells_per_bank;

    location.cell = remainder;

    log_xdebug(TABLES,
               "%s: %s  logical_tcam=%s  logical_row=%zu  location=%s",
               m_name.c_str(),
               __func__,
               logical_tcam_to_string(logical_tcam).c_str(),
               logical_row,
               location.to_string().c_str());

    return location;
}

void
lpm_core_tcam_allocator::commit()
{
    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);

    m_withdraw_stack.clear();
}

size_t
lpm_core_tcam_allocator::push_marker_to_withdraw_stack()
{
    m_withdraw_stack_marker_id++;
    log_xdebug(TABLES, "%s: %s  marker_id=%zu", m_name.c_str(), __func__, m_withdraw_stack_marker_id);

    withdraw_action waction;
    waction.action_type = withdraw_action::withdraw_action_type_e::MARKER;
    waction.action_data = withdraw_action::marker{.marker_id = m_withdraw_stack_marker_id};
    m_withdraw_stack.push_back(waction);

    return m_withdraw_stack_marker_id;
}

void
lpm_core_tcam_allocator::withdraw()
{
    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);
    withdraw_upto_marker(0 /* marker_id */);
}

void
lpm_core_tcam_allocator::withdraw_upto_marker(size_t marker_id)
{
    log_debug(TABLES, "%s: %s  marker_id=%zu", m_name.c_str(), __func__, marker_id);

    while (!m_withdraw_stack.empty()) {
        const withdraw_action waction = m_withdraw_stack.back();
        m_withdraw_stack.pop_back();

        withdraw_one_action(waction);

        if (waction.action_type == withdraw_action::withdraw_action_type_e::MARKER) {
            auto action_data = boost::get<withdraw_action::marker>(waction.action_data);
            if (action_data.marker_id == marker_id) {
                return;
            }
        }
    }

    dassert_crit(marker_id == 0); // if not zero we shouldn't have reached this point
}

void
lpm_core_tcam_allocator::withdraw_one_action(const withdraw_action& waction)
{
    switch (waction.action_type) {

    case withdraw_action::withdraw_action_type_e::WITHDRAW_GIVE_UP_OWNERSHIP: {
        auto action_data = boost::get<withdraw_action::withdraw_give_up_ownership>(waction.action_data);

        atom_take_ownership_of_location(action_data.logical_tcam, action_data.location, false /* update_withdraw_stack */);
        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TAKE_OWNERSHIP: {
        auto action_data = boost::get<withdraw_action::withdraw_take_ownership>(waction.action_data);

        atom_give_up_ownership_of_location(action_data.logical_tcam, action_data.location, false /* update_withdraw_stack */);
        return;
    }

    case withdraw_action::withdraw_action_type_e::MARKER: {
        return;
    }
    }
}

std::string
lpm_core_tcam_allocator::logical_tcam_to_string(logical_tcam_type_e logical_tcam) const
{
    switch (logical_tcam) {
    case logical_tcam_type_e::SINGLE:
        return std::string("SINGLE");

    case logical_tcam_type_e::DOUBLE:
        return std::string("DOUBLE");

    case logical_tcam_type_e::QUAD:
        return std::string("QUAD");

    case logical_tcam_type_e::NOBODY:
        return std::string("NOBODY");
    }

    dassert_crit(false);
    return std::string("");
}

logical_tcam_type_e
lpm_core_tcam_allocator::get_owner_of_location(tcam_cell_location location) const
{
    auto it = m_owner_of_block.find(location);

    dassert_crit(it != m_owner_of_block.end());

    return it->second;
}

std::string
lpm_core_tcam_allocator::logical_tcam_vector_to_string(const vector_alloc<logical_tcam_type_e>& logical_tcam_vector) const
{
    std::stringstream sstream;
    sstream << "{";
    for (const auto& logical_tcam : logical_tcam_vector) {
        sstream << logical_tcam_to_string(logical_tcam);
        sstream << ",";
    }

    sstream << "}";

    return sstream.str();
}

bool
lpm_core_tcam_allocator::sanity() const
{
    vector_alloc<vector_alloc<bool> > locations_map(m_num_banksets,
                                                    vector_alloc<bool>(m_num_cells_per_bank * NUM_BANKS_PER_BANKSET, false));
    for (const auto& logical_tcam :
         {logical_tcam_type_e::SINGLE, logical_tcam_type_e::DOUBLE, logical_tcam_type_e::QUAD, logical_tcam_type_e::NOBODY}) {
        size_t tcam_idx = static_cast<size_t>(logical_tcam);
        size_t num_banks_for_block = lpm_core_tcam_utils_base::get_num_cells_in_block_type(logical_tcam);
        for (const auto& location : m_owned_blocks[tcam_idx]) {
            size_t bankset = location.bankset;

            if ((location.bank % num_banks_for_block) != 0) {
                log_err(TABLES, "Wrong alignment of location %s.", location.to_string().c_str());
                dassert_crit(false);
                return false;
            }

            const auto& owner_of_block_it = m_owner_of_block.find(location);
            if (owner_of_block_it == m_owner_of_block.end()) {
                log_err(
                    TABLES, "Location %s doesn't exist in owner block for tcam type %lu", location.to_string().c_str(), tcam_idx);
                dassert_crit(false);
                return false;
            }

            if (owner_of_block_it->second != logical_tcam) {
                log_err(TABLES, "Location %s belongs to different owners.", location.to_string().c_str());
                dassert_crit(false);
                return false;
            }

            size_t first_cell = location.bank * m_num_cells_per_bank + location.cell;
            for (size_t bank = 0; bank < num_banks_for_block; bank++) {
                size_t cell = bank * m_num_cells_per_bank + first_cell;
                if (locations_map[bankset][cell] == true) {
                    log_err(TABLES, "Location %s already exists for different owner!", location.to_string().c_str());
                    dassert_crit(false);
                    return false;
                }

                locations_map[bankset][cell] = true;
            }
        }
    }

    for (const auto& locations : locations_map) {
        for (const auto& is_visited_location : locations) {
            if (!is_visited_location) {
                log_err(TABLES, "There is location cell that doesn't belong to anyone.");
                dassert_crit(false);
                return false;
            }
        }
    }

    // Now check that all locations in m_owner_of_block are not overlaping.
    for (const auto& pair : m_owner_of_block) {
        tcam_cell_location location = pair.first;
        size_t first_cell = location.bank * m_num_cells_per_bank + location.cell;
        size_t num_banks_for_block = lpm_core_tcam_utils_base::get_num_cells_in_block_type(pair.second);
        for (size_t bank = 0; bank < num_banks_for_block; bank++) {
            size_t cell = bank * m_num_cells_per_bank + first_cell;
            if (locations_map[location.bankset][cell] == false) {
                log_err(TABLES, "Location %s overlaps with other location!", location.to_string().c_str());
                dassert_crit(false);
                return false;
            }

            locations_map[location.bankset][cell] = false;
        }
    }

    return true;
}

} // namespace silicon_one
