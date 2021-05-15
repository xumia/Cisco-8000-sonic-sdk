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

#include "lpm_hw_index_doubles_allocator.h"
#include "common/gen_utils.h"
#include "common/logger.h"

#include <limits.h>
#include <string>

namespace silicon_one
{

lpm_hw_index_doubles_allocator::lpm_hw_index_doubles_allocator(std::string name,
                                                               size_t first_line,
                                                               size_t num_of_sram_lines,
                                                               size_t num_fixed_entries_per_bucket,
                                                               size_t num_shared_entries_per_double_bucket)
    : m_name(name),
      m_num_fixed_entries_per_bucket(num_fixed_entries_per_bucket),
      m_num_shared_entries_per_double_bucket(num_shared_entries_per_double_bucket),
      m_first_index(first_line * 2),
      m_free_lists(num_shared_entries_per_double_bucket + 1, lpm_bucket_index_list())
{
    size_t first_index = 2 * first_line;
    size_t last_index = first_index + 2 * num_of_sram_lines - 1;
    m_num_free_indexes = last_index - first_index + 1;

    m_hw_indexes_state.resize(last_index + 1);
    for (size_t index = m_first_index; index <= last_index; index++) {
        m_free_lists[m_num_shared_entries_per_double_bucket].push_front(index);
        m_hw_indexes_state[index].free_list_iterator = m_free_lists[m_num_shared_entries_per_double_bucket].begin();
        m_hw_indexes_state[index].used_shared_entries = 0;
    }
}

size_t
lpm_hw_index_doubles_allocator::bucket_size_to_shared_entries(size_t bucket_size)
{
    size_t num_shared_entries = std::max(bucket_size, m_num_fixed_entries_per_bucket) - m_num_fixed_entries_per_bucket;
    return num_shared_entries;
}

la_status
lpm_hw_index_doubles_allocator::allocate_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t& out_hw_index)
{
    out_hw_index = LPM_NULL_INDEX;
    size_t num_shared_entries = bucket_size_to_shared_entries(bucket_size);

    for (size_t free_list_index = num_shared_entries; free_list_index <= m_num_shared_entries_per_double_bucket;
         free_list_index++) {
        lpm_bucket_index_list& free_list = m_free_lists[free_list_index];
        if (free_list.empty()) {
            continue;
        }

        for (hw_index_list_it current_hw_index = free_list.begin(); current_hw_index != free_list.end(); current_hw_index++) {
            size_t line = get_line(*current_hw_index);
            if (m_line_dirty_bit.bit(line)) {
                continue;
            }

            out_hw_index = *(current_hw_index);
            atom_allocate_hw_index(free_list, out_hw_index, num_shared_entries, true /* update_withdraw_stack */);

            log_debug(TABLES, "%s lpm_hw_index_doubles_allocator::%s, HW index=%d", m_name.c_str(), __func__, out_hw_index);
            return LA_STATUS_SUCCESS;
        }
    }

    log_debug(TABLES, "%s lpm_hw_index_doubles_allocator::%s, OOR", m_name.c_str(), __func__);
    return LA_STATUS_ERESOURCE;
}

la_status
lpm_hw_index_doubles_allocator::allocate_specific_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t hw_index)
{
    bool is_free = is_hw_index_free(hw_index);
    if (!is_free) {
        log_debug(TABLES, "%s: lpm_hw_index_doubles_allocator::%s, hw index %d occupied", m_name.c_str(), __func__, hw_index);
        return LA_STATUS_EBUSY;
    }

    size_t num_shared_entries = bucket_size_to_shared_entries(bucket_size);
    lpm_bucket_index_t neighbour_hw_index = get_neighbour_hw_index(hw_index);
    size_t num_entries = num_shared_entries + m_hw_indexes_state[neighbour_hw_index].used_shared_entries;
    if (num_entries > m_num_shared_entries_per_double_bucket) {
        return LA_STATUS_ERESOURCE;
    }

    lpm_bucket_index_list& free_list = get_list(hw_index);
    atom_allocate_hw_index(free_list, hw_index, num_shared_entries, true /* update_withdraw_stack */);

    return LA_STATUS_SUCCESS;
}

lpm_bucket_index_list&
lpm_hw_index_doubles_allocator::get_list(lpm_bucket_index_t hw_index)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    lpm_bucket_index_t neighbour_index = get_neighbour_hw_index(hw_index);
    size_t neighbour_num_shared = m_hw_indexes_state[neighbour_index].used_shared_entries;
    size_t list_index = m_num_shared_entries_per_double_bucket - neighbour_num_shared;

    return m_free_lists[list_index];
}

void
lpm_hw_index_doubles_allocator::release_hw_index(lpm_bucket_index_t hw_index)
{
    log_debug(TABLES, "%s lpm_hw_index_doubles_allocator::%s, HW index=%d", m_name.c_str(), __func__, hw_index);
    atom_release_hw_index(hw_index, true /* update_withdraw_stack */);
    atom_mark_hw_index_line(hw_index, true /* is_dirty */, true /* update_withdraw_stack */);
}

void
lpm_hw_index_doubles_allocator::commit()
{
    m_withdraw_stack.clear();
    clear_iteration_members();

    dassert_slow(sanity());
}

void
lpm_hw_index_doubles_allocator::withdraw()
{
    for (auto it = m_withdraw_stack.rbegin(); it != m_withdraw_stack.rend(); it++) {
        withdraw_one_action(*it);
    }

    m_withdraw_stack.clear();
    dassert_slow(sanity());
}

void
lpm_hw_index_doubles_allocator::withdraw_one_action(const withdraw_action& action)
{
    switch (action.action_type) {
    case withdraw_action::action_type_e::ALLOCATE_HW_INDEX: {
        const auto& action_data = boost::get<withdraw_action::allocate_hw_index>(action.action_data);
        lpm_bucket_index_t hw_index = action_data.hw_index;
        atom_release_hw_index(hw_index, false /* update_withdraw_stack */);
        break;
    };
    case withdraw_action::action_type_e::RELEASE_HW_INDEX: {
        const auto& action_data = boost::get<withdraw_action::release_hw_index>(action.action_data);
        lpm_bucket_index_t hw_index = action_data.hw_index;
        size_t old_size = action_data.old_size;
        lpm_bucket_index_list& list = get_list(hw_index);
        atom_allocate_hw_index(list, hw_index, old_size, false /* update_withdraw_stack */);
        break;
    };
    case withdraw_action::action_type_e::CHANGE_HW_INDEX_SIZE: {
        const auto& action_data = boost::get<withdraw_action::change_hw_index>(action.action_data);
        lpm_bucket_index_t hw_index = action_data.hw_index;
        size_t old_size = action_data.old_size;
        atom_change_hw_index_size(hw_index, old_size, false /* update_withdraw_stack */);
        break;
    };
    case withdraw_action::action_type_e::MARK_LINE_FOR_CONSISTENCY: {
        const auto& action_data = boost::get<withdraw_action::mark_line_for_consistency>(action.action_data);
        atom_mark_hw_index_line(action_data.hw_index, action_data.old_is_dirty, false /* update_withdraw_stack */);
        break;
    };
    default:
        dassert_crit(false);
    }
}

void
lpm_hw_index_doubles_allocator::atom_allocate_hw_index(lpm_bucket_index_list& free_list,
                                                       lpm_bucket_index_t hw_index,
                                                       size_t num_shared_entries,
                                                       bool update_withdraw_stack)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    dassert_crit(is_hw_index_free(hw_index));
    dassert_crit(hw_index == *(m_hw_indexes_state[hw_index].free_list_iterator));

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::ALLOCATE_HW_INDEX;
        waction.action_data = withdraw_action::allocate_hw_index{.hw_index = hw_index};
        m_withdraw_stack.push_back(waction);
    }

    hw_index_state& index_data = m_hw_indexes_state[hw_index];
    lpm_bucket_index_t neighbour_hw_index = get_neighbour_hw_index(hw_index);
    hw_index_state& neighbour_state = m_hw_indexes_state[neighbour_hw_index];

    bool is_neighbour_free = is_hw_index_free(neighbour_hw_index);
    if (num_shared_entries > 0 && is_neighbour_free) {
        lpm_bucket_index_list& from_list = m_free_lists[m_num_shared_entries_per_double_bucket];
        hw_index_list_it neighbor_index_it = neighbour_state.free_list_iterator;
        dassert_crit(neighbour_hw_index == (*neighbor_index_it));
        dassert_slow(contains(from_list, neighbour_hw_index));
        from_list.erase(neighbor_index_it);
        size_t list_index = m_num_shared_entries_per_double_bucket - num_shared_entries;
        lpm_bucket_index_list& to_list = m_free_lists[list_index];
        neighbor_index_it = to_list.insert(to_list.end(), neighbour_hw_index);
        neighbour_state.free_list_iterator = neighbor_index_it;
    }

    index_data.used_shared_entries = num_shared_entries;
    free_list.erase(index_data.free_list_iterator);
    index_data.free_list_iterator = m_dummy_list_it;

    m_num_free_indexes--;
}

void
lpm_hw_index_doubles_allocator::atom_release_hw_index(lpm_bucket_index_t hw_index, bool update_withdraw_stack)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    dassert_crit(!is_hw_index_free(hw_index));

    hw_index_state& index_data = m_hw_indexes_state[hw_index];
    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::RELEASE_HW_INDEX;
        waction.action_data = withdraw_action::release_hw_index{.hw_index = hw_index, .old_size = index_data.used_shared_entries};
        m_withdraw_stack.push_back(waction);
    }

    lpm_bucket_index_t neighbour_hw_index = get_neighbour_hw_index(hw_index);
    hw_index_state& neighbour_state = m_hw_indexes_state[neighbour_hw_index];

    size_t hw_index_target_list_idx;
    bool is_neighbour_free = is_hw_index_free(neighbour_hw_index);
    if (is_neighbour_free) {
        size_t neighbor_list_idx = m_num_shared_entries_per_double_bucket - index_data.used_shared_entries;
        lpm_bucket_index_list& from_list = m_free_lists[neighbor_list_idx];
        hw_index_list_it index_it = neighbour_state.free_list_iterator;
        dassert_crit((*index_it) == neighbour_hw_index);
        dassert_slow(contains(from_list, neighbour_hw_index));
        from_list.erase(index_it);
        hw_index_target_list_idx = m_num_shared_entries_per_double_bucket;
        lpm_bucket_index_list& to_list = m_free_lists[hw_index_target_list_idx];
        index_it = to_list.insert(to_list.end(), neighbour_hw_index);
        neighbour_state.free_list_iterator = index_it;
    } else {
        hw_index_target_list_idx = m_num_shared_entries_per_double_bucket - neighbour_state.used_shared_entries;
    }

    lpm_bucket_index_list& target_list = m_free_lists[hw_index_target_list_idx];
    hw_index_list_it hw_index_it = target_list.insert(target_list.end(), hw_index);
    index_data.free_list_iterator = hw_index_it;
    index_data.used_shared_entries = 0;

    m_num_free_indexes++;
}

void
lpm_hw_index_doubles_allocator::atom_change_hw_index_size(lpm_bucket_index_t hw_index,
                                                          size_t num_shared_entries,
                                                          bool update_withdraw_stack)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);

    hw_index_state& index_data = m_hw_indexes_state[hw_index];
    if (index_data.used_shared_entries == num_shared_entries) {
        return;
    }

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::CHANGE_HW_INDEX_SIZE;
        waction.action_data = withdraw_action::change_hw_index{.hw_index = hw_index, .old_size = index_data.used_shared_entries};
        m_withdraw_stack.push_back(waction);
    }

    lpm_bucket_index_t neighbour_hw_index = get_neighbour_hw_index(hw_index);
    bool is_neighbour_free = is_hw_index_free(neighbour_hw_index);
    if (is_neighbour_free) {
        lpm_bucket_index_list& from_list = get_list(neighbour_hw_index);
        hw_index_list_it neighbor_index_it = m_hw_indexes_state[neighbour_hw_index].free_list_iterator;
        dassert_slow(contains(from_list, neighbour_hw_index));
        from_list.erase(neighbor_index_it);
        size_t hw_index_target_idx = m_num_shared_entries_per_double_bucket - num_shared_entries;
        lpm_bucket_index_list& to_list = m_free_lists[hw_index_target_idx];
        neighbor_index_it = to_list.insert(to_list.end(), neighbour_hw_index);
        m_hw_indexes_state[neighbour_hw_index].free_list_iterator = neighbor_index_it;
    }

    index_data.used_shared_entries = num_shared_entries;
}

void
lpm_hw_index_doubles_allocator::atom_mark_hw_index_line(lpm_bucket_index_t hw_index, bool is_dirty, bool update_withdraw_stack)
{
    size_t line = get_line(hw_index);
    bool dirty_bit = m_line_dirty_bit.bit(line);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::MARK_LINE_FOR_CONSISTENCY;
        waction.action_data = withdraw_action::mark_line_for_consistency{.hw_index = hw_index, .old_is_dirty = dirty_bit};
        m_withdraw_stack.push_back(waction);
    }

    m_line_dirty_bit.set_bit(line, is_dirty);
}

const lpm_hw_index_doubles_allocator::hw_index_state_vec&
lpm_hw_index_doubles_allocator::save_m_hw_indexes_state() const
{
    return m_hw_indexes_state;
}

void
lpm_hw_index_doubles_allocator::load_m_hw_indexes_state(const lpm_hw_index_doubles_allocator::hw_index_state_vec& serialized_list)
{
    m_hw_indexes_state = serialized_list;
    for (auto& entry : m_hw_indexes_state) {
        entry.free_list_iterator = m_dummy_list_it;
    }
    for (auto& free_list : m_free_lists) {
        for (auto it = free_list.begin(); it != free_list.end(); it++) {
            dassert_crit((*it >= 0) && (*it < (int)m_hw_indexes_state.size()));
            m_hw_indexes_state[*it].free_list_iterator = it;
        }
    }
}

void
lpm_hw_index_doubles_allocator::notify_hw_index_size_changed(lpm_bucket_index_t hw_index, size_t bucket_size)
{
    dassert_crit(!is_hw_index_free(hw_index));

    size_t num_shared_entries = bucket_size_to_shared_entries(bucket_size);
    atom_change_hw_index_size(hw_index, num_shared_entries, true /* update_withdraw_stack */);
}

bool
lpm_hw_index_doubles_allocator::sanity() const
{
    int num_hw_indexes = m_hw_indexes_state.size();
    for (lpm_bucket_index_t hw_index = m_first_index; hw_index < num_hw_indexes; hw_index++) {
        const hw_index_state& index_data = m_hw_indexes_state[hw_index];

        if (is_hw_index_free(hw_index)) {
            if (hw_index != *index_data.free_list_iterator) {
                log_err(TABLES, "HW index %d doesn't point to proper element in free list", hw_index);
                dassert_crit(false);
                return false;
            }

            if (index_data.used_shared_entries != 0) {
                log_err(TABLES, "Free HW index %d have occupied shared entries", hw_index);
                dassert_crit(false);
                return false;
            }

            lpm_bucket_index_t neighbour_index = get_neighbour_hw_index(hw_index);
            size_t neighbour_num_shared = m_hw_indexes_state[neighbour_index].used_shared_entries;
            size_t list_index = m_num_shared_entries_per_double_bucket - neighbour_num_shared;
            const lpm_bucket_index_list& list = m_free_lists[list_index];
            if (!contains(list, hw_index)) {
                log_err(TABLES, "Free HW index %d doesn't exist in free list with index %lu", hw_index, list_index);
                dassert_crit(false);
                return false;
            }
        }
    }

    vector_alloc<bool> indexes(num_hw_indexes, false);
    for (const auto& free_list_vec : m_free_lists) {
        for (const lpm_bucket_index_t& index : free_list_vec) {
            if (indexes[index]) {
                log_err(TABLES, "HW index %d already found in one of the lists", index);
                dassert_crit(false);
                return false;
            }
        }
    }

    return true;
}

void
lpm_hw_index_doubles_allocator::clear_iteration_members()
{
    m_line_dirty_bit = bit_vector(0, m_line_dirty_bit.get_width());
}

lpm_bucket_index_t
lpm_hw_index_doubles_allocator::get_neighbour_hw_index(lpm_bucket_index_t hw_index) const
{
    return hw_index ^ 1;
}

size_t
lpm_hw_index_doubles_allocator::get_line(lpm_bucket_index_t hw_index) const
{
    return (hw_index) / 2;
}

size_t
lpm_hw_index_doubles_allocator::get_hw_index_size(lpm_bucket_index_t hw_index) const
{
    size_t res = m_hw_indexes_state[hw_index].used_shared_entries;

    return res;
}

size_t
lpm_hw_index_doubles_allocator::get_number_of_free_indices() const
{
    return m_num_free_indexes;
}

bool
lpm_hw_index_doubles_allocator::is_hw_index_free(lpm_bucket_index_t hw_index) const
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    return m_hw_indexes_state[hw_index].free_list_iterator != m_dummy_list_it;
}

} // namespace silicon_one
