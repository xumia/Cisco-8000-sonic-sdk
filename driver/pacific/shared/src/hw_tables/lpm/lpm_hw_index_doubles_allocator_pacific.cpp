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

#include "lpm/lpm_hw_index_doubles_allocator_pacific.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "common/math_utils.h"
#include "lpm/lpm_internal_types.h"
#include "lpm_string.h"

namespace silicon_one
{

lpm_hw_index_doubles_allocator_pacific::lpm_hw_index_doubles_allocator_pacific(std::string name,
                                                                               size_t num_sram_hw_lines,
                                                                               size_t num_fixed_entries_per_bucket,
                                                                               size_t num_shared_entries_per_double_bucket)
    : m_name(name),
      m_num_fixed_entries_per_bucket(num_fixed_entries_per_bucket),
      m_num_shared_entries_per_double_bucket(num_shared_entries_per_double_bucket),
      m_num_free_indexes(num_sram_hw_lines * 2),
      m_singles_free_lists(get_max_shared_entries(false /* has_doubles */), lpm_bucket_index_list()),
      m_doubles_free_lists(get_max_shared_entries(true /* has_doubles */), lpm_bucket_index_list()),
      m_undetermined_free_list(lpm_bucket_index_list())
{
    size_t last_index = m_num_free_indexes - 1;
    m_hw_line_to_state = hw_line_state_vec((last_index / 2) + 1, shared_entries_type_e::UNDETERMINED);

    size_t index = 0;
    m_hw_indexes_state.resize(last_index + 1);

    for (size_t i = 0; i < m_num_free_indexes; i++) {
        dassert_crit(index < m_hw_indexes_state.size());
        m_undetermined_free_list.push_front(index);
        m_hw_indexes_state[index].free_list_iterator = m_undetermined_free_list.begin();
        m_hw_indexes_state[index].used_shared_entries = 0;
        index++;
    }
}

lpm_bucket_index_t
lpm_hw_index_doubles_allocator_pacific::get_neighbour_hw_index(lpm_bucket_index_t hw_index) const
{
    return hw_index ^ 1;
}

size_t
lpm_hw_index_doubles_allocator_pacific::get_line(lpm_bucket_index_t hw_index) const
{
    return (hw_index) / 2;
}

size_t
lpm_hw_index_doubles_allocator_pacific::get_number_of_free_indices() const
{
    return m_num_free_indexes;
}

bool
lpm_hw_index_doubles_allocator_pacific::is_hw_index_free(lpm_bucket_index_t hw_index) const
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    return m_hw_indexes_state[hw_index].free_list_iterator != m_dummy_list_it;
}

lpm_hw_index_doubles_allocator_pacific::shared_entries_descriptor
lpm_hw_index_doubles_allocator_pacific::bucket_occupancy_to_shared_entries_descriptor(
    const lpm_bucket::occupancy_data& occupancy_data) const
{
    shared_entries_descriptor res;
    bool has_doubles = (occupancy_data.double_entries > 0);
    size_t num_single_shared_entries
        = (std::max(occupancy_data.single_entries, m_num_fixed_entries_per_bucket)) - m_num_fixed_entries_per_bucket;

    // Since this allocator assumes that each SRAM line has either all of its shared entries single, or all of them double (A
    // Pacific limitation), for chips which do allow mixing between single and double entries in the shared part (GB+), we trick the
    // allocator by counting each 2 single entries as 1 double entry and telling it that all entries are double.
    // This is a temporary hack. Will be addresses later.
    if (has_doubles) {
        num_single_shared_entries = div_round_up(num_single_shared_entries, 2);
    }
    res.num_shared_entries = occupancy_data.double_entries + num_single_shared_entries;

    if (res.num_shared_entries == 0) {
        res.line_state = shared_entries_type_e::UNDETERMINED;
    } else if (has_doubles) {
        res.line_state = shared_entries_type_e::DOUBLE_ENTRIES;
    } else {
        res.line_state = shared_entries_type_e::SINGLE_ENTRIES;
    }

    return res;
}

la_status
lpm_hw_index_doubles_allocator_pacific::allocate_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                                     lpm_bucket_index_t& out_hw_index)
{
    out_hw_index = LPM_NULL_INDEX;
    shared_entries_descriptor occ = bucket_occupancy_to_shared_entries_descriptor(occupancy_data);
    bool has_doubles = (occ.line_state == shared_entries_type_e::DOUBLE_ENTRIES);

    hw_index_lists_vec& valid_lists_to_search(get_lists(occ.line_state));
    size_t last_free_list = get_max_shared_entries(has_doubles);

    for (size_t current_list_index = occ.num_shared_entries; current_list_index < last_free_list; current_list_index++) {
        lpm_bucket_index_list& current_list = valid_lists_to_search[current_list_index];
        if (current_list.empty()) {
            continue;
        }

        allocate_hw_index_from_list(current_list, occ, out_hw_index);
        if (out_hw_index != LPM_NULL_INDEX) {
            return LA_STATUS_SUCCESS;
        }
    }

    if (!m_undetermined_free_list.empty()) {
        allocate_hw_index_from_list(m_undetermined_free_list, occ, out_hw_index);
        if (out_hw_index != LPM_NULL_INDEX) {
            return LA_STATUS_SUCCESS;
        }
    }

    log_debug(TABLES, "%s: %s, OOR", m_name.c_str(), __func__);
    return LA_STATUS_ERESOURCE;
}

void
lpm_hw_index_doubles_allocator_pacific::allocate_hw_index_from_list(lpm_bucket_index_list& free_list,
                                                                    const shared_entries_descriptor& occ,
                                                                    lpm_bucket_index_t& out_allocated_index)
{
    dassert_crit(!free_list.empty());
    for (hw_index_list_it item_to_erase = free_list.begin(); item_to_erase != free_list.end(); item_to_erase++) {
        lpm_bucket_index_t hw_index = *item_to_erase;
        dassert_crit(hw_index != LPM_NULL_INDEX);
        size_t line = get_line(hw_index);
        if (m_line_dirty_bit.bit(line)) {
            continue;
        }

        out_allocated_index = *item_to_erase;
        atom_allocate_hw_index(free_list, item_to_erase, occ, true /* update_withdraw_stack */);
        log_debug(
            TABLES, "%s lpm_hw_index_doubles_allocator_pacific::%s, HW index=%d", m_name.c_str(), __func__, out_allocated_index);
        return;
    }
}

void
lpm_hw_index_doubles_allocator_pacific::atom_allocate_hw_index(lpm_bucket_index_list& free_list,
                                                               hw_index_list_it item_to_erase,
                                                               const shared_entries_descriptor& occ,
                                                               bool update_withdraw_stack)
{
    lpm_bucket_index_t hw_index = *item_to_erase;

    dassert_crit(hw_index != LPM_NULL_INDEX);
    dassert_crit(m_hw_indexes_state[hw_index].free_list_iterator == item_to_erase);

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::ALLOCATE_HW_INDEX;
        waction.action_data = withdraw_action::allocate_hw_index{.hw_index = hw_index};
        m_withdraw_stack.push_back(waction);
    }

    m_hw_indexes_state[hw_index].free_list_iterator = m_dummy_list_it;
    m_hw_indexes_state[hw_index].used_shared_entries = occ.num_shared_entries;
    free_list.erase(item_to_erase);
    m_num_free_indexes--;

    // Now check if neighbor/line should be affected
    if (occ.num_shared_entries > 0) {
        lpm_bucket_index_t neighbour_hw_index = get_neighbour_hw_index(hw_index);
        bool is_neighbour_free = is_hw_index_free(neighbour_hw_index);
        if (is_neighbour_free) {
            // Neighbour handling. Remove from undetermined and copy to the relevant free_list.
            bool has_doubles = (occ.line_state == shared_entries_type_e::DOUBLE_ENTRIES);
            hw_index_lists_vec& valid_lists(get_lists(occ.line_state));
            size_t max_shared = get_max_shared_entries(has_doubles);
            size_t num_free_shared = max_shared - occ.num_shared_entries;
            dassert_slow(contains(m_undetermined_free_list, neighbour_hw_index));
            m_undetermined_free_list.erase(m_hw_indexes_state[neighbour_hw_index].free_list_iterator);
            m_hw_indexes_state[neighbour_hw_index].free_list_iterator
                = insert_to_list(valid_lists[num_free_shared], neighbour_hw_index);
        }

        // Line
        size_t line = get_line(hw_index);
        m_hw_line_to_state[line] = occ.line_state;
    }
}

void
lpm_hw_index_doubles_allocator_pacific::atom_release_hw_index(lpm_bucket_index_t hw_index, bool update_withdraw_stack)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);

    hw_index_state& index_data = m_hw_indexes_state[hw_index];
    size_t line = get_line(hw_index);

    lpm_bucket_index_t neighbour_hw_index = get_neighbour_hw_index(hw_index);
    hw_index_state& neighbour_data = m_hw_indexes_state[neighbour_hw_index];

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::RELEASE_HW_INDEX;
        waction.action_data = withdraw_action::release_hw_index{
            .hw_index = hw_index,
            .old_occupancy = {.line_state = m_hw_line_to_state[line], .num_shared_entries = index_data.used_shared_entries}};
        m_withdraw_stack.push_back(waction);
    }

    m_num_free_indexes++;

    bool is_neighbour_free = is_hw_index_free(neighbour_hw_index);
    if (is_neighbour_free) {
        // Move the neighbour to m_undetermined_free_list and line becomes undetermined.
        lpm_bucket_index_list& free_list = get_list(neighbour_hw_index);
        dassert_slow(contains(free_list, neighbour_hw_index));
        hw_index_list_it neighbour_it = neighbour_data.free_list_iterator;
        free_list.erase(neighbour_it);
        neighbour_data.free_list_iterator = insert_to_list(m_undetermined_free_list, neighbour_hw_index);

        // Insert hw_index to m_undetermined_free_list
        index_data.free_list_iterator = insert_to_list(m_undetermined_free_list, hw_index);
        index_data.used_shared_entries = 0;
        m_hw_line_to_state[line] = shared_entries_type_e::UNDETERMINED;
    } else {
        // insert the HW index to the correct free_list.
        index_data.used_shared_entries = 0;
        if (neighbour_data.used_shared_entries == 0) {
            index_data.free_list_iterator = insert_to_list(m_undetermined_free_list, hw_index);
            m_hw_line_to_state[line] = shared_entries_type_e::UNDETERMINED;
        } else {
            hw_index_lists_vec& valid_lists = get_lists(m_hw_line_to_state[line]);
            bool has_doubles = (m_hw_line_to_state[line] == shared_entries_type_e::DOUBLE_ENTRIES);
            size_t max_shared_entries = get_max_shared_entries(has_doubles);
            size_t free_shared_entries = max_shared_entries - neighbour_data.used_shared_entries;
            lpm_bucket_index_list& free_list = valid_lists[free_shared_entries];
            m_hw_indexes_state[hw_index].free_list_iterator = insert_to_list(free_list, hw_index);
        }
    }
}

hw_index_list_it
lpm_hw_index_doubles_allocator_pacific::insert_to_list(lpm_bucket_index_list& list, lpm_bucket_index_t hw_index)
{
    list.push_back(hw_index);
    hw_index_list_it ret = list.end();
    --ret;
    dassert_crit(*ret == hw_index);
    return ret;
}

size_t
lpm_hw_index_doubles_allocator_pacific::get_max_shared_entries(bool has_doubles) const
{
    size_t res = has_doubles ? m_num_shared_entries_per_double_bucket / 2 : m_num_shared_entries_per_double_bucket;
    return res;
}

const lpm_bucket_index_list&
lpm_hw_index_doubles_allocator_pacific::get_list(lpm_bucket_index_t hw_index) const
{
    size_t line = get_line(hw_index);
    if (m_hw_line_to_state[line] == shared_entries_type_e::UNDETERMINED) {
        return m_undetermined_free_list;
    }

    const hw_index_lists_vec& free_lists = get_lists(m_hw_line_to_state[line]);
    lpm_bucket_index_t neighbour_index = get_neighbour_hw_index(hw_index);
    size_t neighbour_num_shared = m_hw_indexes_state[neighbour_index].used_shared_entries;

    bool has_doubles = (m_hw_line_to_state[line] == shared_entries_type_e::DOUBLE_ENTRIES);
    size_t free_shared_entries = get_max_shared_entries(has_doubles);
    size_t list_index = free_shared_entries - neighbour_num_shared;

    return free_lists[list_index];
}

lpm_bucket_index_list&
lpm_hw_index_doubles_allocator_pacific::get_list(lpm_bucket_index_t hw_index)
{
    const lpm_hw_index_doubles_allocator_pacific& const_allocator = *this;
    return const_cast<lpm_bucket_index_list&>(const_allocator.get_list(hw_index));
}

la_status
lpm_hw_index_doubles_allocator_pacific::allocate_specific_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                                              lpm_bucket_index_t hw_index)
{
    bool is_free = is_hw_index_free(hw_index);
    if (!is_free) {
        return LA_STATUS_EBUSY;
    }

    shared_entries_descriptor occ = bucket_occupancy_to_shared_entries_descriptor(occupancy_data);
    bool does_fit = does_occupancy_fit_space(occ, hw_index);
    if (!does_fit) {
        return LA_STATUS_ERESOURCE;
    }

    lpm_bucket_index_list& free_list = get_list(hw_index);
    hw_index_list_it item_to_erase = m_hw_indexes_state[hw_index].free_list_iterator;

    atom_allocate_hw_index(free_list, item_to_erase, occ, true /* update_withdraw_stack */);
    return LA_STATUS_SUCCESS;
}

bool
lpm_hw_index_doubles_allocator_pacific::does_occupancy_fit_space(const shared_entries_descriptor& occupancy_data,
                                                                 lpm_bucket_index_t hw_index) const
{
    lpm_bucket_index_t neighbour_index = get_neighbour_hw_index(hw_index);
    size_t neighbour_num_shared_entries = m_hw_indexes_state[neighbour_index].used_shared_entries;
    bool has_doubles = (occupancy_data.line_state == shared_entries_type_e::DOUBLE_ENTRIES);
    if ((occupancy_data.num_shared_entries > 0) && (neighbour_num_shared_entries > 0)) {
        // Check if there are shared entries from both types:
        size_t line = get_line(hw_index);
        bool line_already_contains_doubles = (m_hw_line_to_state[line] == shared_entries_type_e::DOUBLE_ENTRIES);
        if (line_already_contains_doubles != has_doubles) {
            return false;
        }
    }

    // Check the total number of shared entries:
    size_t max_shared = get_max_shared_entries(has_doubles);
    if (occupancy_data.num_shared_entries + neighbour_num_shared_entries > max_shared) {
        return false;
    }

    return true;
}

void
lpm_hw_index_doubles_allocator_pacific::release_hw_index(lpm_bucket_index_t hw_index)
{
    log_debug(TABLES, "%s lpm_hw_index_doubles_allocator_pacific::%s, HW index=%d", m_name.c_str(), __func__, hw_index);

    size_t line = get_line(hw_index);

    atom_release_hw_index(hw_index, true /* update_withdraw_stack */);
    atom_mark_line(line, true /* is_dirty */, true /* update_withdraw_stack */);
}

void
lpm_hw_index_doubles_allocator_pacific::commit()
{
    m_withdraw_stack.clear();
    clear_iteration_members();

    dassert_slow(sanity());
}

void
lpm_hw_index_doubles_allocator_pacific::withdraw()
{
    for (auto it = m_withdraw_stack.rbegin(); it != m_withdraw_stack.rend(); it++) {
        withdraw_one_action(*it);
    }

    m_withdraw_stack.clear();
    dassert_slow(sanity());
}

void
lpm_hw_index_doubles_allocator_pacific::withdraw_one_action(const withdraw_action& waction)
{
    switch (waction.action_type) {
    case withdraw_action::action_type_e::RELEASE_HW_INDEX: {
        const auto& action_data = boost::get<withdraw_action::release_hw_index>(waction.action_data);
        lpm_bucket_index_t hw_index = action_data.hw_index;
        lpm_bucket_index_list& free_list = get_list(hw_index);
        atom_allocate_hw_index(free_list,
                               m_hw_indexes_state[hw_index].free_list_iterator,
                               action_data.old_occupancy,
                               false /* update_withdraw_stack */);
        break;
    };
    case withdraw_action::action_type_e::ALLOCATE_HW_INDEX: {
        const auto& action_data = boost::get<withdraw_action::allocate_hw_index>(waction.action_data);
        lpm_bucket_index_t hw_index = action_data.hw_index;
        atom_release_hw_index(hw_index, false /* update_withdraw_stack */);
        break;
    };
    case withdraw_action::action_type_e::CHANGE_HW_INDEX_OCCUPANCY: {
        const auto& action_data = boost::get<withdraw_action::change_hw_index>(waction.action_data);
        lpm_bucket_index_t hw_index = action_data.hw_index;
        atom_change_hw_index_occupancy(hw_index, action_data.old_occupancy, false /* update_withdraw_stack */);
        break;
    };
    case withdraw_action::action_type_e::MARK_LINE_FOR_CONSISTENCY: {
        const auto& action_data = boost::get<withdraw_action::mark_line_for_consistency>(waction.action_data);
        atom_mark_line(action_data.line, action_data.old_is_dirty, false /* update_withdraw_stack */);
        break;
    };

    default:
        dassert_crit(false);
    }
}

lpm_hw_index_doubles_allocator_pacific::hw_index_lists_vec&
lpm_hw_index_doubles_allocator_pacific::get_lists(shared_entries_type_e line_state) const
{
    const hw_index_lists_vec& lists
        = (line_state == shared_entries_type_e::DOUBLE_ENTRIES) ? m_doubles_free_lists : m_singles_free_lists;
    return const_cast<hw_index_lists_vec&>(lists);
}

void
lpm_hw_index_doubles_allocator_pacific::notify_hw_index_occupancy_changed(lpm_bucket_index_t hw_index,
                                                                          const lpm_bucket::occupancy_data& occupancy_data)
{
    dassert_crit(!is_hw_index_free(hw_index));

    shared_entries_descriptor occ = bucket_occupancy_to_shared_entries_descriptor(occupancy_data);
    dassert_slow(does_occupancy_fit_space(occ, hw_index));

    atom_change_hw_index_occupancy(hw_index, occ, true /* update_withdraw_stack */);
}

void
lpm_hw_index_doubles_allocator_pacific::atom_mark_line(size_t line, bool is_dirty, bool update_withdraw_stack)
{
    bool old_is_dirty = m_line_dirty_bit.bit(line);
    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::MARK_LINE_FOR_CONSISTENCY;
        waction.action_data = withdraw_action::mark_line_for_consistency{.line = line, .old_is_dirty = old_is_dirty};
        m_withdraw_stack.push_back(waction);
    }

    m_line_dirty_bit.set_bit(line, is_dirty);
}

void
lpm_hw_index_doubles_allocator_pacific::atom_change_hw_index_occupancy(lpm_bucket_index_t hw_index,
                                                                       const shared_entries_descriptor& occ,
                                                                       bool update_withdraw_stack)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);

    hw_index_state& index_data = m_hw_indexes_state[hw_index];
    size_t line = get_line(hw_index);

    if ((occ.line_state == m_hw_line_to_state[line]) && (occ.num_shared_entries == index_data.used_shared_entries)) {
        return;
    }

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::CHANGE_HW_INDEX_OCCUPANCY;
        waction.action_data = withdraw_action::change_hw_index{
            .hw_index = hw_index,
            .old_occupancy = {.line_state = m_hw_line_to_state[line], .num_shared_entries = index_data.used_shared_entries}};
        m_withdraw_stack.push_back(waction);
    }

    lpm_bucket_index_t neighbour_hw_index = get_neighbour_hw_index(hw_index);
    bool is_neighbour_free = is_hw_index_free(neighbour_hw_index);
    if (is_neighbour_free) {
        // Remove neighbour from old list
        lpm_bucket_index_list& from_list = get_list(neighbour_hw_index);
        dassert_slow(contains(from_list, neighbour_hw_index));
        from_list.erase(m_hw_indexes_state[neighbour_hw_index].free_list_iterator);

        m_hw_line_to_state[line] = occ.line_state;
        index_data.used_shared_entries = occ.num_shared_entries;

        // Insert to new list:
        lpm_bucket_index_list& to_list = get_list(neighbour_hw_index);
        dassert_slow(!contains(to_list, neighbour_hw_index));
        m_hw_indexes_state[neighbour_hw_index].free_list_iterator = insert_to_list(to_list, neighbour_hw_index);
    } else {
        index_data.used_shared_entries = occ.num_shared_entries;
        if (occ.line_state != shared_entries_type_e::UNDETERMINED) {
            m_hw_line_to_state[line] = occ.line_state;
        }
    }
}

lpm_hw_index_doubles_allocator_pacific::shared_entries_descriptor
lpm_hw_index_doubles_allocator_pacific::get_hw_index_occupancy(lpm_bucket_index_t hw_index) const
{
    size_t line = get_line(hw_index);
    const hw_index_state& index_data = m_hw_indexes_state[hw_index];

    shared_entries_descriptor res;
    res.line_state = m_hw_line_to_state[line];
    res.num_shared_entries = index_data.used_shared_entries;

    return res;
}

void
lpm_hw_index_doubles_allocator_pacific::clear_iteration_members()
{
    m_line_dirty_bit = bit_vector(0, m_line_dirty_bit.get_width());
}

const lpm_hw_index_doubles_allocator_pacific::hw_index_state_vec&
lpm_hw_index_doubles_allocator_pacific::save_m_hw_indexes_state() const
{
    return m_hw_indexes_state;
}

void
lpm_hw_index_doubles_allocator_pacific::load_m_hw_indexes_state(
    const lpm_hw_index_doubles_allocator_pacific::hw_index_state_vec& serialized_list)
{
    m_hw_indexes_state = serialized_list;
    for (auto& entry : m_hw_indexes_state) {
        entry.free_list_iterator = m_dummy_list_it;
    }
    restore_free_iterators_from_index_list(m_undetermined_free_list);
    restore_free_iterators_from_vector_of_index_list(m_singles_free_lists);
    restore_free_iterators_from_vector_of_index_list(m_doubles_free_lists);
}

void
lpm_hw_index_doubles_allocator_pacific::restore_free_iterators_from_index_list(lpm_bucket_index_list& free_list)
{
    for (auto it = free_list.begin(); it != free_list.end(); it++) {
        dassert_crit((*it >= 0) && (*it < (int)m_hw_indexes_state.size()));
        m_hw_indexes_state[*it].free_list_iterator = it;
    }
}

void
lpm_hw_index_doubles_allocator_pacific::restore_free_iterators_from_vector_of_index_list(hw_index_lists_vec& free_lists)
{
    for (auto& free_list : free_lists) {
        restore_free_iterators_from_index_list(free_list);
    }
}

bool
lpm_hw_index_doubles_allocator_pacific::sanity() const
{
    int hw_indexes = m_hw_indexes_state.size();
    for (lpm_bucket_index_t hw_index = 0; hw_index < hw_indexes; hw_index++) {
        const hw_index_state& index_data = m_hw_indexes_state[hw_index];
        // Check that allocated index has null iterator.
        if (index_data.used_shared_entries > 0) {
            if (is_hw_index_free(hw_index)) {
                dassert_crit(false);
                return false;
            }

            // Check integrity of the line containing the current HW-index.
            size_t line = get_line(hw_index);
            if (m_hw_line_to_state[line] == shared_entries_type_e::UNDETERMINED) {
                dassert_crit(false);
                return false;
            }
        }

        if (is_hw_index_free(hw_index)) {
            // Check the iterator points to the correct element of the correct list
            if (static_cast<lpm_bucket_index_t>(hw_index) != *index_data.free_list_iterator) {
                dassert_crit(false);
                return false;
            }

            const lpm_bucket_index_list& list = get_list(hw_index);
            if (!contains(list, hw_index)) {
                dassert_crit(false);
                return false;
            }
        }
    }

    // Make sure each index appears at most once in all free lists.
    vector_alloc<bool> indexes(m_hw_indexes_state.size(), false);
    for (const auto& index : m_undetermined_free_list) {
        if (indexes[index]) {
            dassert_crit(false);
            return false;
        }

        indexes[index] = true;
    }

    for (const auto& list_vec : {m_singles_free_lists, m_doubles_free_lists}) {
        for (const auto& list : list_vec) {
            for (const auto& index : list) {
                if (indexes[index]) {
                    dassert_crit(false);
                    return false;
                }
                indexes[index] = true;
            }
        }
    }

    // Make sure we cleaned m_line_dirty_bit.
    bool is_zero = m_line_dirty_bit.is_zero();
    if (!is_zero) {
        dassert_crit(false);
        return false;
    }

    return true;
}

} // namespace silicon_one
