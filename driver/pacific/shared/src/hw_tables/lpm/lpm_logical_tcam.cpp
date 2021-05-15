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

#include "lpm_logical_tcam.h"
#include "common/logger.h"
#include "common/transaction.h"

#include <jansson.h>
#include <stack>

namespace silicon_one
{

lpm_logical_tcam::lpm_logical_tcam(std::string name, size_t num_rows)
    : m_name(name), m_table(num_rows), m_num_occupied_rows(0), m_binary_tree(name + "::TCAM Tree"), m_withdraw_stack_marker_id(0)
{
    for (size_t row = 0; row < num_rows; row++) {
        m_free_rows.insert(row);
    }
}

lpm_logical_tcam::~lpm_logical_tcam()
{
    return;
}

la_status
lpm_logical_tcam::insert(const lpm_key_t& key, lpm_payload_t payload, logical_instruction_vec& out_instructions)
{
    log_debug(TABLES,
              "%s: Action=%s: key=0x%s/%zu   payload=%u",
              m_name.c_str(),
              __func__,
              key.to_string().c_str(),
              key.get_width(),
              payload);

    logical_instruction_vec instructions;

    size_t withdraw_marker_id = push_marker_to_withdraw_stack();
    transaction txn;
    txn.on_fail([=]() { withdraw_upto_marker(withdraw_marker_id); });

    // First we try to insert to the tree, even before checking if we have space.
    // This is in order to return EEXISTS and not ERESOURCE if the key already exists in the table.
    lpm_logical_tcam_tree_node* node;
    txn.status = atom_tree_insert(key, true /* update_withdraw_stack */, node);
    return_on_error(txn.status);

    if (m_free_rows.size() == 0) {
        log_debug(TABLES, "%s: %s: No free rows", m_name.c_str(), __func__);
        txn.status = LA_STATUS_ERESOURCE;
        return txn.status;
    }

    dassert_crit(node != nullptr);
    dassert_crit(node->is_valid());

    // Now we want to insert node to TCAM table. It must be above its parent, and below its children.
    // strategy:
    // (1) If there is a free row between parent and bottommost-child, just occupy it.
    // Otherwise:
    //     - (2) If there is a free row below ancestor, relocate ancestor and occupy its place
    //     - (3) Else: if there is a free row above bottommost-child, relocate bottommost-child and occupy its place.

    lpm_logical_tcam_tree_node* ancestor = get_closest_valid_ancestor(node);
    const lpm_logical_tcam_tree_node* bottommost_child = get_child_with_largest_row_number(node);
    size_t ancestor_row = LPM_NULL_ROW;
    if (ancestor != nullptr) {
        const lpm_logical_tcam_tree_data& ancestor_data = ancestor->data();
        ancestor_row = ancestor_data.row;
    }

    size_t bottommost_child_row = LPM_NULL_ROW;
    if (bottommost_child != nullptr) {
        const lpm_logical_tcam_tree_data& bottommost_child_data = bottommost_child->data();
        bottommost_child_row = bottommost_child_data.row;
    }

    size_t found_free_row = LPM_NULL_ROW;

    // option (1): try to find a free row between parent and bottommost child
    size_t free_row_between_child_and_ancestor
        = find_free_row_in_range_exclusive(bottommost_child_row /* lower_bound */, ancestor_row /* upper_bound */);

    if (free_row_between_child_and_ancestor != LPM_NULL_ROW) {
        found_free_row = free_row_between_child_and_ancestor;
    }

    // option (2): if (1), try to find a free row below ancestor.
    if ((found_free_row == LPM_NULL_ROW) && (ancestor != nullptr)) {
        dassert_crit(ancestor_row != LPM_NULL_ROW);

        size_t free_row_below_ancestor
            = find_free_row_in_range_exclusive(ancestor_row /* lower_bound */, LPM_NULL_ROW /* higher bound */);

        if (free_row_below_ancestor != LPM_NULL_ROW) {
            push_rows(ancestor, free_row_below_ancestor, instructions);
            found_free_row = ancestor_row;
        }
    }

    // option (3): if (1) and (2) failed, try to find a free row above bottommost-child
    if ((found_free_row == LPM_NULL_ROW) && (bottommost_child != nullptr)) {
        dassert_crit(bottommost_child_row != LPM_NULL_ROW);

        size_t free_row_above_bottommost_child
            = find_free_row_in_range_exclusive(LPM_NULL_ROW /* lower_bound */, bottommost_child_row /* upper_bound */);

        if (free_row_above_bottommost_child != LPM_NULL_ROW) {
            pull_rows(bottommost_child, free_row_above_bottommost_child, instructions);
            found_free_row = bottommost_child_row;
        }
    }

    // we know there is a free row, we checked everywhere, something is fishy.
    dassert_crit(found_free_row != LPM_NULL_ROW);

    atom_tree_modify_row(const_cast<lpm_logical_tcam_tree_node*>(node), found_free_row, true /* update_withdraw_stack */);

    atom_table_insert(found_free_row, key, payload, true /* update_withdraw_stack */, instructions);

    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
    return LA_STATUS_SUCCESS;
}

la_status
lpm_logical_tcam::remove(const lpm_key_t& key, logical_instruction_vec& out_instructions)
{
    log_debug(TABLES, "%s: Action=%s: key=0x%s/%zu", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width());

    lpm_logical_tcam_tree_node* node = m_binary_tree.find_node(key);
    if (node == nullptr || node->get_key() != key) {
        log_debug(TABLES, "%s: %s: key=0x%s/%zu not found", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width());
        return LA_STATUS_ENOTFOUND;
    }

    dassert_crit(node->is_valid());

    logical_instruction_vec instructions;

    const lpm_logical_tcam_tree_data& node_data = node->data();
    atom_table_remove(node_data.row, true /* update_withdraw_stack */, instructions);

    la_status status = atom_tree_remove(node, true /* update_withdraw_stack */);
    dassert_crit(status == LA_STATUS_SUCCESS);

    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
    return LA_STATUS_SUCCESS;
}

la_status
lpm_logical_tcam::modify(const lpm_key_t& key, lpm_payload_t payload, logical_instruction_vec& out_instructions)
{
    log_debug(TABLES,
              "%s: Action=%s: key=0x%s/%zu   payload=%u",
              m_name.c_str(),
              __func__,
              key.to_string().c_str(),
              key.get_width(),
              payload);

    lpm_logical_tcam_tree_node* node = m_binary_tree.find_node(key);
    if (node == nullptr || node->get_key() != key) {
        log_debug(TABLES, "%s: %s: key=0x%s/%zu not found", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width());
        return LA_STATUS_ENOTFOUND;
    }

    dassert_crit(node->is_valid());

    logical_instruction_vec instructions;
    const lpm_logical_tcam_tree_data& node_data = node->data();
    atom_table_modify_payload(node_data.row, payload, true /* update_withdraw_stack */, instructions);

    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
    return LA_STATUS_SUCCESS;
}

const lpm_logical_tcam_tree_node*
lpm_logical_tcam::find(const lpm_key_t& key) const
{
    return m_binary_tree.find_node(key);
}

la_status
lpm_logical_tcam::block(size_t row, logical_instruction_vec& out_instructions)
{
    log_debug(TABLES, "%s: Action=%s: row=%zu", m_name.c_str(), __func__, row);

    if (row >= m_table.size()) {
        return LA_STATUS_EINVAL;
    }

    dassert_crit(m_table[row].state != table_entry::table_entry_state_e::BLOCKED);

    logical_instruction_vec instructions;

    if (m_table[row].state == table_entry::table_entry_state_e::OCCUPIED) {
        size_t free_row = find_free_row_in_range_exclusive(LPM_NULL_ROW /* lower_bound */, LPM_NULL_ROW /* upper_bound */);

        if (free_row == LPM_NULL_ROW) {
            log_debug(TABLES, "%s: %s: could not find a free row to relocate to", m_name.c_str(), __func__);
            return LA_STATUS_ERESOURCE;
        }

        if (free_row < row) {
            pull_rows(row, free_row, instructions);
        } else if (free_row > row) {
            push_rows(row, free_row, instructions);
        } else {
            dassert_crit(false);
        }
    }

    atom_table_block_row(row, true /* update_withdraw_stack */);

    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
    return LA_STATUS_SUCCESS;
}

void
lpm_logical_tcam::block_all_free_rows()
{
    log_debug(TABLES, "%s: Action=%s", m_name.c_str(), __func__);

    for (size_t row = 0; row < m_table.size(); row++) {
        if (m_table[row].state == table_entry::table_entry_state_e::FREE) {
            atom_table_block_row(row, true /* update_withdraw_stack */);
        }
    }
}

la_status
lpm_logical_tcam::unblock(size_t row)
{
    log_debug(TABLES, "%s: Action=%s: row=%zu", m_name.c_str(), __func__, row);

    if (row >= m_table.size()) {
        return LA_STATUS_EINVAL;
    }

    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::BLOCKED);

    atom_table_unblock_row(row, true /* update_withdraw_stack */);

    return LA_STATUS_SUCCESS;
}

size_t
lpm_logical_tcam::find_free_row_in_range_exclusive(size_t lower_bound, size_t upper_bound) const
{
    set_alloc<size_t>::iterator free_row_it;

    if (lower_bound == LPM_NULL_ROW) {
        free_row_it = m_free_rows.begin();
    } else {
        free_row_it = m_free_rows.upper_bound(lower_bound); // std::set:;upper_bound(x) return smallest item t such that t > x
    }

    if (free_row_it == m_free_rows.end()) {
        return LPM_NULL_ROW;
    }

    size_t free_row = *free_row_it;
    dassert_crit(m_table[free_row].state == table_entry::table_entry_state_e::FREE);

    if ((upper_bound == LPM_NULL_ROW) || (free_row < upper_bound)) {
        return free_row;
    }

    return LPM_NULL_ROW;
}

void
lpm_logical_tcam::push_rows(size_t src_row, size_t dst_row, logical_instruction_vec& out_instructions)
{
    dassert_crit(src_row < m_table.size());
    dassert_crit(dst_row < m_table.size());
    dassert_crit(src_row < dst_row);
    dassert_crit(m_table[src_row].state == table_entry::table_entry_state_e::OCCUPIED);
    dassert_crit(m_table[dst_row].state == table_entry::table_entry_state_e::FREE);
    dassert_slow(m_free_rows.count(dst_row) == 1);

    lpm_key_t src_key = m_table[src_row].key;
    lpm_logical_tcam_tree_node* src_node = m_binary_tree.find_node(src_key);
    dassert_crit(src_node != nullptr);
    dassert_crit(src_node->get_key() == src_key);
    dassert_crit(src_node->is_valid());

    push_rows(src_node, dst_row, out_instructions);
}

void
lpm_logical_tcam::push_rows(const lpm_logical_tcam_tree_node* src_node, size_t dst_row, logical_instruction_vec& out_instructions)
{
    dassert_crit(src_node != nullptr);
    dassert_crit(src_node->is_valid());

    const lpm_logical_tcam_tree_data& src_node_data = src_node->data();
    size_t src_row = src_node_data.row;
    lpm_logical_tcam_tree_node* ancestor = get_closest_valid_ancestor(src_node);
    if (ancestor == nullptr) {
        move_row(src_row, dst_row, out_instructions);
    } else {
        const lpm_logical_tcam_tree_data& ancestor_data = ancestor->data();
        size_t ancestor_row = ancestor_data.row;
        if (ancestor_row > dst_row) {
            move_row(src_row, dst_row, out_instructions);
        } else {
            push_rows(ancestor, dst_row, out_instructions);
            move_row(src_row, ancestor_row, out_instructions);
        }
    }

    dassert_crit(m_table[src_row].state == table_entry::table_entry_state_e::FREE);
}

void
lpm_logical_tcam::pull_rows(size_t src_row, size_t dst_row, logical_instruction_vec& out_instructions)
{
    dassert_crit(src_row < m_table.size());
    dassert_crit(dst_row < m_table.size());
    dassert_crit(src_row > dst_row);
    dassert_crit(m_table[src_row].state == table_entry::table_entry_state_e::OCCUPIED);
    dassert_crit(m_table[dst_row].state == table_entry::table_entry_state_e::FREE);
    dassert_slow(m_free_rows.count(dst_row) == 1);

    lpm_key_t src_key = m_table[src_row].key;
    lpm_logical_tcam_tree_node* src_node = m_binary_tree.find_node(src_key);

    dassert_crit(src_node != nullptr);
    dassert_crit(src_node->get_key() == src_key);
    dassert_crit(src_node->is_valid());

    pull_rows(src_node, dst_row, out_instructions);
}

void
lpm_logical_tcam::pull_rows(const lpm_logical_tcam_tree_node* src_node, size_t dst_row, logical_instruction_vec& out_instructions)
{
    dassert_crit(src_node != nullptr);
    dassert_crit(src_node->is_valid());

    const lpm_logical_tcam_tree_node* bottommost_child = get_child_with_largest_row_number(src_node);

    const lpm_logical_tcam_tree_data& src_node_data = src_node->data();
    size_t src_row = src_node_data.row;

    if (bottommost_child == nullptr) {
        move_row(src_row, dst_row, out_instructions);
    } else {
        const lpm_logical_tcam_tree_data& bottommost_child_data = bottommost_child->data();
        size_t bottommost_child_row = bottommost_child_data.row;
        if (bottommost_child_row < dst_row) {
            move_row(src_row, dst_row, out_instructions);
        } else {
            pull_rows(bottommost_child, dst_row, out_instructions);
            move_row(src_row, bottommost_child_row, out_instructions);
        }
    }

    dassert_crit(m_table[src_row].state == table_entry::table_entry_state_e::FREE);
}

void
lpm_logical_tcam::move_row(size_t src_row, size_t dst_row, logical_instruction_vec& out_instructions)
{
    log_xdebug(TABLES, "%s: %s: src_row=%zu  dst_row=%zu", m_name.c_str(), __func__, src_row, dst_row);

    dassert_crit(m_table[src_row].state == table_entry::table_entry_state_e::OCCUPIED);
    dassert_crit(m_table[dst_row].state == table_entry::table_entry_state_e::FREE);

    lpm_key_t src_key = m_table[src_row].key;

    atom_table_insert(dst_row, m_table[src_row].key, m_table[src_row].payload, true /* update_withdraw_stack */, out_instructions);
    atom_table_remove(src_row, true /* update_withdraw_stack */, out_instructions);

    lpm_logical_tcam_tree_node* src_node = m_binary_tree.find_node(src_key);
    dassert_crit(src_node != nullptr);
    dassert_crit(src_node->get_key() == src_key);
    dassert_crit(src_node->is_valid());

    atom_tree_modify_row(src_node, dst_row, true /* update_withdraw_stack */);

    dassert_crit(m_table[src_row].state == table_entry::table_entry_state_e::FREE);
}

const lpm_logical_tcam_tree_node*
lpm_logical_tcam::get_root_node() const
{
    return m_binary_tree.get_root();
}

lpm_logical_tcam_tree_node*
lpm_logical_tcam::get_closest_valid_ancestor(const lpm_logical_tcam_tree_node* node)
{
    dassert_crit(node != nullptr);
    dassert_crit(node->is_valid());

    const lpm_logical_tcam_tree_node* current = node->get_parent_node();

    while (current != nullptr) {
        if (current->is_valid()) {
            return const_cast<lpm_logical_tcam_tree_node*>(current);
        }

        current = current->get_parent_node();
    }

    return nullptr;
}

const lpm_logical_tcam_tree_node*
lpm_logical_tcam::get_child_with_largest_row_number(const lpm_logical_tcam_tree_node* node)
{
    vector_alloc<const lpm_logical_tcam_tree_node*> wave;

    const lpm_logical_tcam_tree_node* left_child = node->get_left_child();
    const lpm_logical_tcam_tree_node* right_child = node->get_right_child();
    for (const auto& child : {left_child, right_child}) {
        if (child != nullptr) {
            wave.push_back(child);
        }
    }

    size_t max_row = 0;
    const lpm_logical_tcam_tree_node* max_node = nullptr;

    while (!wave.empty()) {
        const lpm_logical_tcam_tree_node* current_node = wave.back();
        wave.pop_back();
        dassert_crit(current_node != nullptr);

        if (current_node->is_valid()) {
            const lpm_logical_tcam_tree_data& current_node_data = current_node->data();
            if (current_node_data.row >= max_row) {
                max_row = current_node_data.row;
                max_node = current_node;
            }
        } else {
            const lpm_logical_tcam_tree_node* current_left_child = current_node->get_left_child();
            const lpm_logical_tcam_tree_node* current_right_child = current_node->get_right_child();
            for (const auto& child : {current_left_child, current_right_child}) {
                dassert_crit(child != nullptr);
                wave.push_back(child);
            }
        }
    }

    return max_node;
}

void
lpm_logical_tcam::atom_table_insert(size_t row,
                                    const lpm_key_t& key,
                                    lpm_payload_t payload,
                                    bool update_withdraw_stack,
                                    logical_instruction_vec& out_instructions)
{
    log_xdebug(TABLES,
               "%s: %s: row=%zu   key=%s/%zu   payload=%u   update_withdraw_stack=%d",
               m_name.c_str(),
               __func__,
               row,
               key.to_string().c_str(),
               key.get_width(),
               payload,
               update_withdraw_stack);

    dassert_crit(row != LPM_NULL_ROW);
    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::FREE);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_INSERT;
        waction.action_data = withdraw_action::withdraw_table_insert{.row = row};
        m_withdraw_stack.push_back(waction);
    }

    m_table[row].state = table_entry::table_entry_state_e::OCCUPIED;
    m_table[row].key = key;
    m_table[row].payload = payload;

    size_t erased = m_free_rows.erase(row);
    dassert_crit(erased == 1);
    m_num_occupied_rows++;

    out_instructions.push_back(
        logical_instruction{.instruction_type = logical_instruction::type_e::INSERT, .key = key, .payload = payload, .row = row});
}

void
lpm_logical_tcam::atom_table_remove(size_t row, bool update_withdraw_stack, logical_instruction_vec& out_instructions)
{
    log_xdebug(TABLES, "%s: %s: row=%zu  update_withdraw_stack=%d", m_name.c_str(), __func__, row, update_withdraw_stack);

    dassert_crit(row != LPM_NULL_ROW);
    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::OCCUPIED);

    lpm_key_t key = m_table[row].key;

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_REMOVE;
        waction.action_data = withdraw_action::withdraw_table_remove{.row = row, .key = key, .payload = m_table[row].payload};
        m_withdraw_stack.push_back(waction);
    }

    m_table[row].state = table_entry::table_entry_state_e::FREE;
    m_table[row].key = lpm_key_t();
    m_table[row].payload = INVALID_PAYLOAD;

    m_free_rows.insert(row);
    m_num_occupied_rows--;

    out_instructions.push_back(logical_instruction{
        .instruction_type = logical_instruction::type_e::REMOVE, .key = key, .payload = INVALID_PAYLOAD, .row = row});
}

void
lpm_logical_tcam::atom_table_modify_payload(size_t row,
                                            lpm_payload_t payload,
                                            bool update_withdraw_stack,
                                            logical_instruction_vec& out_instructions)
{
    log_xdebug(TABLES,
               "%s: %s: row=%zu   payload=%u  update_withdraw_stack=%d",
               m_name.c_str(),
               __func__,
               row,
               payload,
               update_withdraw_stack);

    dassert_crit(row != LPM_NULL_ROW);
    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::OCCUPIED);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_MODIFY_PAYLOAD;
        waction.action_data = withdraw_action::withdraw_table_modify_payload{.row = row, .payload = m_table[row].payload};
        m_withdraw_stack.push_back(waction);
    }

    m_table[row].payload = payload;

    out_instructions.push_back(logical_instruction{
        .instruction_type = logical_instruction::type_e::MODIFY_PAYLOAD, .key = m_table[row].key, .payload = payload, .row = row});
}

void
lpm_logical_tcam::atom_table_unblock_row(size_t row, bool update_withdraw_stack)
{
    log_xdebug(TABLES, "%s: %s: row=%zu  update_withdraw_stack=%d", m_name.c_str(), __func__, row, update_withdraw_stack);

    dassert_crit(row != LPM_NULL_ROW);
    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::BLOCKED);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_UNBLOCK;
        waction.action_data = withdraw_action::withdraw_table_unblock{.row = row};
        m_withdraw_stack.push_back(waction);
    }

    m_table[row].state = table_entry::table_entry_state_e::FREE;
    m_free_rows.insert(row);
}

void
lpm_logical_tcam::atom_table_block_row(size_t row, bool update_withdraw_stack)
{
    log_xdebug(TABLES, "%s: %s: row=%zu  update_withdraw_stack=%d", m_name.c_str(), __func__, row, update_withdraw_stack);

    dassert_crit(row != LPM_NULL_ROW);
    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::FREE);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_BLOCK;
        waction.action_data = withdraw_action::withdraw_table_block{.row = row};
        m_withdraw_stack.push_back(waction);
    }

    m_table[row].state = table_entry::table_entry_state_e::BLOCKED;
    size_t erased = m_free_rows.erase(row);
    dassert_crit(erased == 1);
}

la_status
lpm_logical_tcam::atom_tree_insert(const lpm_key_t& key, bool update_withdraw_stack, lpm_logical_tcam_tree_node*& out_node)
{
    log_xdebug(TABLES,
               "%s: %s: key=%s/%zu  update_withdraw_stack=%d",
               m_name.c_str(),
               __func__,
               key.to_string().c_str(),
               key.get_width(),
               update_withdraw_stack);

    la_status status = m_binary_tree.insert_node_to_tree(key, out_node);
    return_on_error(status);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TREE_INSERT;
        waction.action_data = withdraw_action::withdraw_tree_insert{.key = key};
        m_withdraw_stack.push_back(waction);
    }

    return LA_STATUS_SUCCESS;
}

la_status
lpm_logical_tcam::atom_tree_remove(lpm_logical_tcam_tree_node* node, bool update_withdraw_stack)
{
    dassert_crit(node != nullptr);

    lpm_key_t key = node->get_key();
    log_xdebug(TABLES,
               "%s: %s: key=%s/%zu  update_withdraw_stack=%d",
               m_name.c_str(),
               __func__,
               key.to_string().c_str(),
               key.get_width(),
               update_withdraw_stack);

    dassert_crit(node->is_valid());

    const lpm_logical_tcam_tree_data& node_data = node->data();
    size_t row = node_data.row;

    const lpm_key_t& node_key = node->get_key();
    size_t node_width = node->get_width();
    log_debug(TABLES, "%s: %s: key=%s/%zu", m_name.c_str(), __func__, node_key.to_string().c_str(), node_width);
    m_binary_tree.remove_node_from_tree(node);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TREE_REMOVE;
        waction.action_data = withdraw_action::withdraw_tree_remove{.row = row, .key = key};
        m_withdraw_stack.push_back(waction);
    }

    return LA_STATUS_SUCCESS;
}

void
lpm_logical_tcam::atom_tree_modify_row(lpm_logical_tcam_tree_node* node, size_t row, bool update_withdraw_stack)
{
    dassert_crit(node != nullptr);

    const lpm_key_t& node_key = node->get_key();
    log_xdebug(TABLES,
               "%s: %s: node->get_key()=%s/%zu  row=%zu  update_withdraw_stack=%d",
               m_name.c_str(),
               __func__,
               node_key.to_string().c_str(),
               node_key.get_width(),
               row,
               update_withdraw_stack);

    dassert_crit(node->is_valid());
    lpm_logical_tcam_tree_data& node_data = node->data();
    size_t original_row = node_data.row;
    node_data.row = row;

    log_debug(TABLES,
              "%s: %s: node=%s/%zu    row=%zu",
              m_name.c_str(),
              __func__,
              node->get_key().to_string().c_str(),
              node->get_width(),
              row);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::withdraw_action_type_e::WITHDRAW_TREE_MODIFY_ROW;
        waction.action_data = withdraw_action::withdraw_tree_modify_row{.key = node_key, .row = original_row};
        m_withdraw_stack.push_back(waction);
    }
}

void
lpm_logical_tcam::withdraw()
{
    log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);
    withdraw_upto_marker(0 /* marker_id */);
}

void
lpm_logical_tcam::withdraw_upto_marker(size_t marker_id)
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

size_t
lpm_logical_tcam::push_marker_to_withdraw_stack()
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
lpm_logical_tcam::withdraw_one_action(const withdraw_action& waction)
{
    switch (waction.action_type) {

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_INSERT: {
        auto action_data = boost::get<withdraw_action::withdraw_table_insert>(waction.action_data);
        size_t row = action_data.row;

        logical_instruction_vec dummy_out_instructions;
        atom_table_remove(row, false /* update_withdraw_stack */, dummy_out_instructions);

        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_REMOVE: {
        auto action_data = boost::get<withdraw_action::withdraw_table_remove>(waction.action_data);
        size_t row = action_data.row;

        logical_instruction_vec dummy_out_instructions;
        atom_table_insert(row, action_data.key, action_data.payload, false /* update_withdraw_stack */, dummy_out_instructions);

        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_MODIFY_PAYLOAD: {
        auto action_data = boost::get<withdraw_action::withdraw_table_modify_payload>(waction.action_data);
        size_t row = action_data.row;

        logical_instruction_vec dummy_out_instructions;
        atom_table_modify_payload(row, action_data.payload, false /* update_withdraw_stack */, dummy_out_instructions);

        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_UNBLOCK: {
        auto action_data = boost::get<withdraw_action::withdraw_table_unblock>(waction.action_data);
        size_t row = action_data.row;

        atom_table_block_row(row, false /* update_withdraw_stack */);

        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TABLE_BLOCK: {
        auto action_data = boost::get<withdraw_action::withdraw_table_block>(waction.action_data);
        size_t row = action_data.row;

        atom_table_unblock_row(row, false /* update_withdraw_stack */);

        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TREE_INSERT: {
        auto action_data = boost::get<withdraw_action::withdraw_tree_insert>(waction.action_data);
        const lpm_key_t& key = action_data.key;

        lpm_logical_tcam_tree_node* node = m_binary_tree.find_node(key);
        dassert_crit(node != nullptr);
        dassert_crit(node->get_key() == key);
        dassert_crit(node->is_valid());

        la_status status = atom_tree_remove(node, false /* update_withdraw_stack */);
        dassert_crit(status == LA_STATUS_SUCCESS);

        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TREE_REMOVE: {
        auto action_data = boost::get<withdraw_action::withdraw_tree_remove>(waction.action_data);
        lpm_key_t& key = action_data.key;
        size_t row = action_data.row;

        lpm_logical_tcam_tree_node* node;
        la_status status = atom_tree_insert(key, false /* update_withdraw_stack */, node);
        dassert_crit(status == LA_STATUS_SUCCESS);

        atom_tree_modify_row(node, row, false /* update_withdraw_stack */);

        return;
    }

    case withdraw_action::withdraw_action_type_e::WITHDRAW_TREE_MODIFY_ROW: {
        auto action_data = boost::get<withdraw_action::withdraw_tree_modify_row>(waction.action_data);
        lpm_key_t& key = action_data.key;
        size_t row = action_data.row;
        lpm_logical_tcam_tree_node* node = m_binary_tree.find_node(key);
        dassert_crit(node != nullptr);
        dassert_crit(node->get_key() == key);
        dassert_crit(node->is_valid());

        atom_tree_modify_row(node, row, false /* update_withdraw_stack */);

        return;
    }

    case withdraw_action::withdraw_action_type_e::MARKER: {
        return;
    }
    }
}

void
lpm_logical_tcam::commit()
{
    if (!m_withdraw_stack.empty()) {
        log_debug(TABLES, "%s: %s", m_name.c_str(), __func__);
    }

    m_withdraw_stack.clear();
}

la_status
lpm_logical_tcam::get_payload_of_node(const lpm_logical_tcam_tree_node* node, lpm_payload_t& out_payload) const
{
    if (node == nullptr) {
        log_err(TABLES, "%s: %s: node==nullptr", m_name.c_str(), __func__);
        return LA_STATUS_EINVAL;
    }

    const lpm_logical_tcam_tree_data& node_data = node->data();
    if ((node_data.row == LPM_NULL_ROW) || (node_data.row >= m_table.size())) {
        log_err(TABLES,
                "%s: %s: node_data.row of node with key %s/%zu is invalid (%zu)",
                m_name.c_str(),
                __func__,
                node->get_key().to_string().c_str(),
                node->get_key().get_width(),
                node_data.row);
        return LA_STATUS_EINVAL;
    }

    out_payload = m_table[node_data.row].payload;
    return LA_STATUS_SUCCESS;
}

vector_alloc<lpm_key_payload_row>
lpm_logical_tcam::get_entries() const
{
    vector_alloc<lpm_key_payload_row> res;

    for (size_t row = 0; row < m_table.size(); row++) {
        const table_entry& entry = m_table[row];
        if (entry.state == table_entry::table_entry_state_e::OCCUPIED) {
            lpm_key_payload_row key_payload_row = {.key = entry.key, .payload = entry.payload, .row = row};
            res.push_back(key_payload_row);
        }
    }

    return res;
}

la_status
lpm_logical_tcam::get_entry(size_t row, lpm_key_payload& out_key_payload) const
{
    if (row > m_table.size()) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_table[row].state != table_entry::table_entry_state_e::OCCUPIED) {
        return LA_STATUS_ENOTFOUND;
    }

    out_key_payload = {.key = m_table[row].key, .payload = m_table[row].payload};

    return LA_STATUS_SUCCESS;
}

size_t
lpm_logical_tcam::get_num_occupied_rows() const
{
    return m_num_occupied_rows;
}

size_t
lpm_logical_tcam::get_num_free_rows() const
{
    return m_free_rows.size();
}

size_t
lpm_logical_tcam::get_total_num_of_rows() const
{
    return m_table.size();
}

la_status
lpm_logical_tcam::lookup_tcam_tree(const lpm_key_t& key,
                                   lpm_key_t& out_hit_key,
                                   lpm_payload_t& out_hit_payload,
                                   size_t& out_hit_row) const
{
    log_xdebug(TABLES, "%s: %s: key=%s/%zu", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width());

    const lpm_logical_tcam_tree_node* hit_node = m_binary_tree.longest_prefix_match_lookup(key);
    if (hit_node == nullptr) {
        log_xdebug(TABLES,
                   "%s: %s: no longest prefix match for key=%s/%zu",
                   m_name.c_str(),
                   __func__,
                   key.to_string().c_str(),
                   key.get_width());
        return LA_STATUS_ENOTFOUND;
    }

    dassert_crit(hit_node->is_valid());

    const lpm_logical_tcam_tree_data& hit_node_data = hit_node->data();
    size_t row = hit_node_data.row;
    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::OCCUPIED);
    dassert_crit(m_table[row].key == hit_node->get_key());
    dassert_crit(is_contained(m_table[row].key, key));

    out_hit_key = m_table[row].key;
    out_hit_payload = m_table[row].payload;
    out_hit_row = row;

    log_xdebug(TABLES,
               "%s: %s: key=%s/%zu   hit_key=%s/%zu   hit_payload=%x   hit_row=%zu",
               m_name.c_str(),
               __func__,
               key.to_string().c_str(),
               key.get_width(),
               out_hit_key.to_string().c_str(),
               out_hit_key.get_width(),
               out_hit_payload,
               out_hit_row);

    return LA_STATUS_SUCCESS;
}

la_status
lpm_logical_tcam::lookup_tcam_table(const lpm_key_t& key,
                                    lpm_key_t& out_hit_key,
                                    lpm_payload_t& out_hit_payload,
                                    size_t& out_hit_row) const
{
    log_xdebug(TABLES, "%s: %s: key=%s/%zu", m_name.c_str(), __func__, key.to_string().c_str(), key.get_width());

    for (size_t row = 0; row < m_table.size(); row++) {
        bool row_valid = (m_table[row].state == table_entry::table_entry_state_e::OCCUPIED);
        if (!row_valid) {
            continue;
        }

        const lpm_key_t& entry_key = m_table[row].key;
        bool is_hit = is_contained(entry_key, key);

        if (is_hit) {
            out_hit_key = entry_key;
            out_hit_payload = m_table[row].payload;
            out_hit_row = row;

            log_xdebug(TABLES,
                       "%s: %s: key=%s/%zu   hit_key=%s/%zu   hit_row=%zu   hit_payload=%x",
                       m_name.c_str(),
                       __func__,
                       key.to_string().c_str(),
                       key.get_width(),
                       out_hit_key.to_string().c_str(),
                       out_hit_key.get_width(),
                       out_hit_row,
                       out_hit_payload);

            return LA_STATUS_SUCCESS;
        }
    }

    log_xdebug(TABLES,
               "%s: %s: no longest prefix match for key=%s/%zu",
               m_name.c_str(),
               __func__,
               key.to_string().c_str(),
               key.get_width());
    return LA_STATUS_ENOTFOUND;
}

void
lpm_logical_tcam::insert_and_enforce_line(const lpm_key_t& key,
                                          lpm_payload_t payload,
                                          size_t row,
                                          logical_instruction_vec& out_instructions)
{
    dassert_crit(row < m_table.size());
    lpm_logical_tcam_tree_node* node;
    logical_instruction_vec instructions;
    dassert_crit(m_table[row].state == table_entry::table_entry_state_e::FREE);
    la_status status = atom_tree_insert(key, true /* update_withdraw_stack */, node);
    dassert_crit(status == LA_STATUS_SUCCESS);
    atom_tree_modify_row(node, row, true);
    atom_table_insert(row, key, payload, true /* update_withdraw_stack */, instructions);

    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
}

json_t*
lpm_logical_tcam::save_state() const
{
    const lpm_logical_tcam_tree_node* root = m_binary_tree.get_root();
    dassert_crit(root != nullptr);

    json_t* json_tcam = json_object();
    std::stack<const lpm_logical_tcam_tree_node*> wave;
    wave.push(root);
    while (!wave.empty()) {
        const lpm_logical_tcam_tree_node* node = wave.top();
        wave.pop();
        const lpm_logical_tcam_tree_node* left_child = node->get_left_child();
        const lpm_logical_tcam_tree_node* right_child = node->get_right_child();
        for (auto& child : {left_child, right_child}) {
            if (child != nullptr) {
                wave.push(child);
            }
        }

        if (node->is_valid()) {
            json_t* json_entry = json_object();
            const lpm_logical_tcam_tree_data& node_data = node->data();
            table_entry entry = m_table[node_data.row];
            json_object_set_new(json_entry, JSON_KEY_VALUE, json_string(entry.key.to_string().c_str()));
            json_object_set_new(json_entry, JSON_KEY_WIDTH, json_integer(entry.key.get_width()));
            json_object_set_new(json_entry, JSON_PAYLOAD, json_integer(entry.payload));
            json_object_set_new(json_tcam, std::to_string(node_data.row).c_str(), json_entry);
        }
    }

    return json_tcam;
}

void
lpm_logical_tcam::load_state(json_t* json_tcam, lpm_logical_tcam::logical_instruction_vec& out_instructions)
{
    const char* tcam_row;
    json_t* tcam_row_data;
    json_object_foreach(json_tcam, tcam_row, tcam_row_data)
    {
        size_t row = std::stoi(tcam_row);
        std::string key_value = json_string_value(json_object_get(tcam_row_data, JSON_KEY_VALUE));
        size_t key_width_value = json_integer_value(json_object_get(tcam_row_data, JSON_KEY_WIDTH));
        lpm_payload_t payload_value = json_integer_value(json_object_get(tcam_row_data, JSON_PAYLOAD));
        lpm_key_t key = lpm_key_t(key_value, key_width_value);
        insert_and_enforce_line(key, payload_value, row, out_instructions);
    }
}

void
lpm_logical_tcam::reset_state(logical_instruction_vec& out_instructions)
{
    logical_instruction_vec instructions;
    for (size_t row = 0; row < m_table.size(); row++) {
        if (m_table[row].state == table_entry::table_entry_state_e::BLOCKED) {
            continue;
        }

        if (m_table[row].state == table_entry::table_entry_state_e::OCCUPIED) {
            lpm_logical_tcam_tree_node* node = m_binary_tree.find_node(m_table[row].key);
            dassert_crit(node != nullptr);
            dassert_crit(node->get_key() == m_table[row].key);

            atom_table_remove(row, true /* update_withdraw_stack */, instructions);
            la_status status = atom_tree_remove(node, true /* update_withdraw_stack */);
            dassert_crit(status == LA_STATUS_SUCCESS);
        }

        atom_table_block_row(row, true /* update_withdraw_stack */);
    }

    dassert_crit(m_num_occupied_rows == 0);
    dassert_crit(m_free_rows.size() == 0);
    out_instructions.insert(out_instructions.end(), instructions.begin(), instructions.end());
}

bool
lpm_logical_tcam::sanity() const
{
    map_alloc<size_t, lpm_key_t> tree_data;
    const lpm_logical_tcam_tree_node* root = m_binary_tree.get_root();
    std::stack<const lpm_logical_tcam_tree_node*> wave;
    wave.push(root);
    while (!wave.empty()) {
        const lpm_logical_tcam_tree_node* node = wave.top();
        wave.pop();
        const lpm_logical_tcam_tree_node* left_child = node->get_left_child();
        const lpm_logical_tcam_tree_node* right_child = node->get_right_child();
        for (const auto& child : {left_child, right_child}) {
            if (child != nullptr) {
                wave.push(child);
            }
        }

        if (node->is_valid()) {
            const lpm_key_t& key = node->get_key();
            size_t row = node->data().row;
            if (tree_data.count(row) != 0) {
                log_err(TABLES, "%s::TCAM row %lu already occupied", __func__, row);
                dassert_crit(false);
                return false;
            }

            tree_data[row] = key;
        }
    }

    map_alloc<size_t, lpm_key_t> table_data;
    for (size_t row = 0; row < m_table.size(); row++) {
        if (m_table[row].state == table_entry::table_entry_state_e::OCCUPIED) {
            table_data[row] = m_table[row].key;
        }
    }

    if (table_data != tree_data) {
        log_err(TABLES, "%s::TCAM table and TCAM tree don't match", __func__);
        dassert_crit(false);
        return false;
    }

    return true;
}

} // namespace silicon_one
