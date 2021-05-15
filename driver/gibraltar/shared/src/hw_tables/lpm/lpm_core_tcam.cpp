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

#include "lpm_core_tcam.h"
#include "common/logger.h"
#include "common/transaction.h"

namespace silicon_one
{

lpm_core_tcam::lpm_core_tcam(std::string name,
                             size_t num_banksets,
                             size_t num_cells_per_bank,
                             size_t num_quad_blocks,
                             const lpm_core_tcam_utils_scptr& core_tcam_utils)
    : m_name(name), m_num_banksets(num_banksets), m_core_tcam_utils(core_tcam_utils)
{
    m_logical_tcams.reserve(lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS);
    m_logical_tcams.emplace_back(name + "::SINGLE logical TCAM",
                                 num_banksets * lpm_core_tcam_allocator::NUM_BANKS_PER_BANKSET * num_cells_per_bank);
    m_logical_tcams.emplace_back(name + "::DOUBLE logical TCAM",
                                 num_banksets * lpm_core_tcam_allocator::NUM_BANKS_PER_BANKSET / 2 * num_cells_per_bank);
    m_logical_tcams.emplace_back(name + "::QUAD logical TCAM", num_quad_blocks);
}

lpm_core_tcam::~lpm_core_tcam()
{
}

la_status
lpm_core_tcam::insert(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions)
{
    log_debug(
        TABLES, "%s: %s: key=0x%s/%zu  payload=%u", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width(), payload);

    hardware_instruction_vec allocator_hw_instructions;

    logical_tcam_type_e logical_tcam = m_core_tcam_utils->get_logical_tcam_type_of_key(key);
    size_t tcam_idx = static_cast<size_t>(logical_tcam);

    withdraw_stack_marker withdraw_marker = push_marker_to_withdraw_stack();
    transaction txn;
    txn.on_fail([=]() { withdraw_upto_marker(withdraw_marker); });

    lpm_logical_tcam::logical_instruction_vec logical_out_instructions;
    txn.status = m_logical_tcams[tcam_idx].insert(key, payload, logical_out_instructions);

    if (txn.status == LA_STATUS_ERESOURCE) {
        std::array<size_t, lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS> free_blocks;
        for (size_t i = 0; i < lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS; i++) {
            free_blocks[i] = m_logical_tcams[i].get_num_free_rows();
        }

        lpm_core_tcam_allocator::allocator_instruction_vec allocator_instructions;
        txn.status = m_tcam_allocator->make_space(logical_tcam, free_blocks, allocator_instructions);
        return_on_error(txn.status);

        for (const auto& allocator_instruction : allocator_instructions) {
            txn.status = perform_allocator_instruction(allocator_instruction, allocator_hw_instructions);
            dassert_crit(txn.status == LA_STATUS_SUCCESS);
        }

        txn.status = m_logical_tcams[tcam_idx].insert(key, payload, logical_out_instructions);
    }

    return_on_error(txn.status);

    out_instructions.insert(out_instructions.end(), allocator_hw_instructions.begin(), allocator_hw_instructions.end());
    translate_logical_to_physical_tcam_instructions(logical_out_instructions, out_instructions);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_tcam::remove(const lpm_key_t& key, hardware_instruction_vec& out_instructions)
{
    log_debug(TABLES, "%s: %s: key=0x%s/%zu", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width());

    lpm_logical_tcam::logical_instruction_vec logical_out_instructions;

    logical_tcam_type_e logical_tcam = m_core_tcam_utils->get_logical_tcam_type_of_key(key);
    size_t tcam_idx = static_cast<size_t>(logical_tcam);

    la_status status = m_logical_tcams[tcam_idx].remove(key, logical_out_instructions);
    return_on_error(status);

    translate_logical_to_physical_tcam_instructions(logical_out_instructions, out_instructions);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_tcam::modify(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions)
{
    log_debug(
        TABLES, "%s: %s: key=0x%s/%zu  payload=%u", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width(), payload);

    lpm_logical_tcam::logical_instruction_vec logical_out_instructions;

    logical_tcam_type_e logical_tcam = m_core_tcam_utils->get_logical_tcam_type_of_key(key);
    size_t tcam_idx = static_cast<size_t>(logical_tcam);

    la_status status = m_logical_tcams[tcam_idx].modify(key, payload, logical_out_instructions);
    return_on_error(status);

    translate_logical_to_physical_tcam_instructions(logical_out_instructions, out_instructions);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_tcam::update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions)
{
    if (updates.empty()) {
        return LA_STATUS_SUCCESS;
    }

    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);

    withdraw_stack_marker withdraw_marker = push_marker_to_withdraw_stack();
    transaction txn;
    txn.on_fail([=]() { withdraw_upto_marker(withdraw_marker); });
    hardware_instruction_vec hw_instructions;

    for (const auto& update : updates) {

        switch (update.m_action) {

        case lpm_implementation_action_e::INSERT: {
            txn.status = insert(update.m_key, update.m_payload, hw_instructions);
            return_on_error(txn.status);
            break;
        }

        case lpm_implementation_action_e::REMOVE: {
            txn.status = remove(update.m_key, hw_instructions);
            return_on_error(txn.status);
            break;
        }

        case lpm_implementation_action_e::MODIFY: {
            txn.status = modify(update.m_key, update.m_payload, hw_instructions);
            return_on_error(txn.status);
            break;
        }

        case lpm_implementation_action_e::REFRESH: {
            break;
        }

        default: {
            dassert_crit(false);
            break;
        }
        }
    }

    out_instructions.insert(out_instructions.end(), hw_instructions.begin(), hw_instructions.end());
    return LA_STATUS_SUCCESS;
}

la_status
lpm_core_tcam::lookup_tcam_tree(const lpm_key_t& key,
                                lpm_key_t& out_hit_key,
                                lpm_payload_t& out_hit_payload,
                                tcam_cell_location& out_hit_location) const
{
    if (key.get_width() == 0) {
        return LA_STATUS_EINVAL;
    }

    size_t hit_row;
    for (auto logical_tcam : {logical_tcam_type_e::QUAD, logical_tcam_type_e::DOUBLE, logical_tcam_type_e::SINGLE}) {
        size_t tcam_idx = static_cast<size_t>(logical_tcam);
        la_status status = m_logical_tcams[tcam_idx].lookup_tcam_tree(key, out_hit_key, out_hit_payload, hit_row);
        if (status == LA_STATUS_SUCCESS) {
            out_hit_location = m_tcam_allocator->translate_logical_row_to_location(logical_tcam, hit_row);
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
lpm_core_tcam::lookup_tcam_table(const lpm_key_t& key,
                                 lpm_key_t& out_hit_key,
                                 lpm_payload_t& out_hit_payload,
                                 tcam_cell_location& out_hit_location) const
{
    if (key.get_width() == 0) {
        return LA_STATUS_EINVAL;
    }

    size_t hit_row;
    for (auto logical_tcam : {logical_tcam_type_e::QUAD, logical_tcam_type_e::DOUBLE, logical_tcam_type_e::SINGLE}) {
        size_t tcam_idx = static_cast<size_t>(logical_tcam);
        la_status status = m_logical_tcams[tcam_idx].lookup_tcam_table(key, out_hit_key, out_hit_payload, hit_row);
        if (status == LA_STATUS_SUCCESS) {
            out_hit_location = m_tcam_allocator->translate_logical_row_to_location(logical_tcam, hit_row);
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

const lpm_logical_tcam_tree_node*
lpm_core_tcam::find(const lpm_key_t& key) const
{
    logical_tcam_type_e logical_tcam = m_core_tcam_utils->get_logical_tcam_type_of_key(key);
    size_t tcam_idx = static_cast<size_t>(logical_tcam);

    const lpm_logical_tcam_tree_node* node = m_logical_tcams[tcam_idx].find(key);

    return node;
}

size_t
lpm_core_tcam::get_num_cells() const
{
    size_t single_blocks = m_logical_tcams[SINGLE_IDX].get_total_num_of_rows();
    return single_blocks;
}

size_t
lpm_core_tcam::get_num_banksets() const
{
    return m_num_banksets;
}

size_t
lpm_core_tcam::get_max_quad_entries() const
{
    return m_tcam_allocator->get_max_quad_blocks();
}

lpm_core_tcam::lpm_core_tcam_occupancy
lpm_core_tcam::get_occupancy() const
{
    lpm_core_tcam_occupancy stats;

    stats.num_single_entries = m_logical_tcams[SINGLE_IDX].get_num_occupied_rows();
    stats.num_double_entries = m_logical_tcams[DOUBLE_IDX].get_num_occupied_rows();
    stats.num_quad_entries = m_logical_tcams[QUAD_IDX].get_num_occupied_rows();

    stats.empty_cells = m_logical_tcams[SINGLE_IDX].get_num_free_rows() + m_logical_tcams[DOUBLE_IDX].get_num_free_rows() * 2
                        + m_logical_tcams[QUAD_IDX].get_num_free_rows() * 4;

    stats.occupied_cells = stats.num_single_entries + stats.num_double_entries * 2 + stats.num_quad_entries * 4;

    dassert_crit(stats.empty_cells + stats.occupied_cells
                 <= get_num_cells()); // Some of the cells are blocked in all TCAMs (e.g. last row / nobody cells)

    return stats;
}

const lpm_logical_tcam&
lpm_core_tcam::get_logical_tcam(logical_tcam_type_e logical_tcam) const
{
    size_t tcam_idx = static_cast<size_t>(logical_tcam);
    return m_logical_tcams[tcam_idx];
}

const lpm_core_tcam_allocator&
lpm_core_tcam::get_core_tcam_allocator() const
{
    return *m_tcam_allocator;
}

void
lpm_core_tcam::commit()
{
    for (size_t i = 0; i < lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS; i++) {
        m_logical_tcams[i].commit();
    }

    m_tcam_allocator->commit();
}

void
lpm_core_tcam::withdraw()
{
    for (size_t i = 0; i < lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS; i++) {
        m_logical_tcams[i].withdraw();
    }

    m_tcam_allocator->withdraw();
}

void
lpm_core_tcam::withdraw_upto_marker(const withdraw_stack_marker& marker)
{
    for (size_t i = 0; i < lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS; i++) {
        m_logical_tcams[i].withdraw_upto_marker(marker.logical_tcam_marker[i]);
    }

    m_tcam_allocator->withdraw_upto_marker(marker.tcam_allocator_marker);
}

lpm_core_tcam::withdraw_stack_marker
lpm_core_tcam::push_marker_to_withdraw_stack()
{
    withdraw_stack_marker marker;

    for (size_t i = 0; i < lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS; i++) {
        marker.logical_tcam_marker[i] = m_logical_tcams[i].push_marker_to_withdraw_stack();
    }

    marker.tcam_allocator_marker = m_tcam_allocator->push_marker_to_withdraw_stack();

    return marker;
}

la_status
lpm_core_tcam::perform_allocator_instruction(const lpm_core_tcam_allocator::allocator_instruction& instruction,
                                             hardware_instruction_vec& out_instructions)
{
    lpm_logical_tcam::logical_instruction_vec logical_out_instructions;

    switch (instruction.instruction_type) {

    case lpm_core_tcam_allocator::allocator_instruction::instruction_type_e::BLOCK: {
        auto instruction_data = boost::get<lpm_core_tcam_allocator::allocator_instruction::block>(instruction.instruction_data);
        size_t tcam_idx = static_cast<size_t>(instruction_data.logical_tcam);
        la_status status = m_logical_tcams[tcam_idx].block(instruction_data.logical_row, logical_out_instructions);
        return_on_error(status);

        translate_logical_to_physical_tcam_instructions(logical_out_instructions, out_instructions);

        return LA_STATUS_SUCCESS;
    }

    case lpm_core_tcam_allocator::allocator_instruction::instruction_type_e::UNBLOCK: {
        auto instruction_data = boost::get<lpm_core_tcam_allocator::allocator_instruction::unblock>(instruction.instruction_data);
        size_t tcam_idx = static_cast<size_t>(instruction_data.logical_tcam);
        la_status status = m_logical_tcams[tcam_idx].unblock(instruction_data.logical_row);
        return status;
    }

    case lpm_core_tcam_allocator::allocator_instruction::instruction_type_e::BLOCK_ALL_FREE_ROWS: {
        auto instruction_data
            = boost::get<lpm_core_tcam_allocator::allocator_instruction::block_all_free_rows>(instruction.instruction_data);
        size_t tcam_idx = static_cast<size_t>(instruction_data.logical_tcam);
        m_logical_tcams[tcam_idx].block_all_free_rows();
        return LA_STATUS_SUCCESS;
    }
    }

    dassert_crit(false);
    return LA_STATUS_EUNKNOWN;
}

void
lpm_core_tcam::translate_logical_to_physical_tcam_instructions(
    const lpm_logical_tcam::logical_instruction_vec& logical_instructions,
    hardware_instruction_vec& out_hardware_instructions) const
{
    for (auto& logical_instruction : logical_instructions) {
        hardware_instruction hw_instruction;

        logical_tcam_type_e logical_tcam = m_core_tcam_utils->get_logical_tcam_type_of_key(logical_instruction.key);
        tcam_cell_location location = m_tcam_allocator->translate_logical_row_to_location(logical_tcam, logical_instruction.row);

        switch (logical_instruction.instruction_type) {
        case lpm_logical_tcam::logical_instruction::type_e::INSERT:
            hw_instruction.instruction_type = hardware_instruction::type_e::INSERT;
            hw_instruction.instruction_data = hardware_instruction::insert{
                .key = logical_instruction.key, .payload = logical_instruction.payload, .location = location};
            break;
        case lpm_logical_tcam::logical_instruction::type_e::REMOVE:
            hw_instruction.instruction_type = hardware_instruction::type_e::REMOVE;
            hw_instruction.instruction_data = hardware_instruction::remove{.key = logical_instruction.key, .location = location};
            break;
        case lpm_logical_tcam::logical_instruction::type_e::MODIFY_PAYLOAD:
            hw_instruction.instruction_type = hardware_instruction::type_e::MODIFY_PAYLOAD;
            hw_instruction.instruction_data = hardware_instruction::modify_payload{
                .key = logical_instruction.key, .payload = logical_instruction.payload, .location = location};
            break;
        default:
            dassert_crit(false);
        }

        out_hardware_instructions.push_back(hw_instruction);
    }
}

vector_alloc<lpm_core_tcam::lpm_core_tcam_entry>
lpm_core_tcam::get_entries() const
{
    vector_alloc<lpm_core_tcam_entry> result;

    for (logical_tcam_type_e logical_tcam : {logical_tcam_type_e::SINGLE, logical_tcam_type_e::DOUBLE, logical_tcam_type_e::QUAD}) {
        size_t tcam_idx = static_cast<size_t>(logical_tcam);
        vector_alloc<lpm_key_payload_row> logical_entries = m_logical_tcams[tcam_idx].get_entries();

        for (auto& logical_entry : logical_entries) {
            lpm_core_tcam_entry core_tcam_entry;
            core_tcam_entry.key = logical_entry.key;
            core_tcam_entry.payload = logical_entry.payload;
            core_tcam_entry.location = m_tcam_allocator->translate_logical_row_to_location(logical_tcam, logical_entry.row);
            result.push_back(core_tcam_entry);
        }
    }

    return result;
}

bool
lpm_core_tcam::sanity() const
{
    bool res = true;
    dassert_slow(res = res && m_tcam_allocator->sanity());
    for (const auto& logical_tcam : m_logical_tcams) {
        dassert_slow(res = res && logical_tcam.sanity());
    }

    return res;
}
} // namespace silicon_one
