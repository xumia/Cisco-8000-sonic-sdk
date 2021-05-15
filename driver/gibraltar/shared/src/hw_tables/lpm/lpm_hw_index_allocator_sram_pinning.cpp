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

#include "lpm_hw_index_allocator_sram_pinning.h"
#include "common/gen_utils.h"
#include "common/logger.h"

#include <string>

namespace silicon_one
{

lpm_hw_index_allocator_sram_pinning::lpm_hw_index_allocator_sram_pinning(std::string name, size_t first_line, size_t num_lines)
    : m_name(name), m_first_index(first_line * 2), m_free_indexes_for_hbm_caching(num_lines)
{
    for (size_t line = first_line; line < first_line + num_lines; line++) {
        lpm_bucket_index_t index = line * 2;
        m_hbm_caching_indexes.push_back(index);
        index++;
        m_sram_pinned_indexes.push_back(index);
    }
}

la_status
lpm_hw_index_allocator_sram_pinning::allocate_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t& out_hw_index)
{
    dassert_crit(false);
    return LA_STATUS_EINVAL;
}

la_status
lpm_hw_index_allocator_sram_pinning::allocate_hw_index_for_bucket(index_type type, lpm_bucket_index_t& out_hw_index)
{
    lpm_bucket_index_list& free_list = (type == index_type::SRAM_PINNED) ? m_sram_pinned_indexes : m_hbm_caching_indexes;

    for (auto it = free_list.begin(); it != free_list.end(); it++) {
        lpm_bucket_index_t hw_index = *it;
        size_t line = get_line(hw_index);
        if (m_line_dirty_bit.bit(line)) {
            continue;
        }

        out_hw_index = hw_index;
        log_debug(TABLES, "%s lpm_hw_index_allocator_sram_pinning::%s, HW index=%d", m_name.c_str(), __func__, out_hw_index);
        atom_allocate_hw_index(free_list, it, true /* update_withdraw_stack */);
        return LA_STATUS_SUCCESS;
    }

    log_debug(TABLES, "%s: %s, OOR", m_name.c_str(), __func__);
    return LA_STATUS_ERESOURCE;
}

la_status
lpm_hw_index_allocator_sram_pinning::allocate_specific_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t hw_index)
{
    lpm_bucket_index_list& index_list = get_list(hw_index);
    auto it = std::find(index_list.begin(), index_list.end(), hw_index);

    if (it == index_list.end()) {
        log_debug(TABLES, "%s: lpm_hw_index_allocator_sram_pinning::%s, hw index %d occupied", m_name.c_str(), __func__, hw_index);
        return LA_STATUS_EBUSY;
    }

    atom_allocate_hw_index(index_list, it, true /* update_withdraw_stack */);

    return LA_STATUS_SUCCESS;
}

bool
lpm_hw_index_allocator_sram_pinning::is_hw_index_is_sram_pinned(lpm_bucket_index_t hw_index) const
{
    return (hw_index % 2 == 1);
}

lpm_bucket_index_list&
lpm_hw_index_allocator_sram_pinning::get_list(lpm_bucket_index_t hw_index) const
{
    bool is_pinned = is_hw_index_is_sram_pinned(hw_index);
    const lpm_bucket_index_list& ret = is_pinned ? m_sram_pinned_indexes : m_hbm_caching_indexes;
    return const_cast<lpm_bucket_index_list&>(ret);
}

void
lpm_hw_index_allocator_sram_pinning::release_hw_index(lpm_bucket_index_t hw_index)
{
    log_debug(TABLES, "%s lpm_hw_index_allocator_sram_pinning::%s, HW index=%d", m_name.c_str(), __func__, hw_index);
    atom_release_hw_index(hw_index, true /* update_withdraw_stack */);
    atom_mark_hw_index_line(hw_index, true /* is_dirty */, true /* update_withdraw_stack */);
}

void
lpm_hw_index_allocator_sram_pinning::commit()
{
    log_debug(TABLES, "%s lpm_hw_index_allocator_sram_pinning::%s", m_name.c_str(), __func__);
    m_withdraw_stack.clear();
    clear_iteration_members();

    dassert_slow(sanity());
}

void
lpm_hw_index_allocator_sram_pinning::withdraw()
{
    for (auto it = m_withdraw_stack.rbegin(); it != m_withdraw_stack.rend(); it++) {
        withdraw_one_action(*it);
    }

    m_withdraw_stack.clear();
    dassert_slow(sanity());
}

void
lpm_hw_index_allocator_sram_pinning::withdraw_one_action(const withdraw_action& action)
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
        lpm_bucket_index_list& index_list = get_list(hw_index);
        auto it = std::find(index_list.begin(), index_list.end(), hw_index);
        atom_allocate_hw_index(index_list, it, false /* update_withdraw_stack */);
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
lpm_hw_index_allocator_sram_pinning::atom_allocate_hw_index(lpm_bucket_index_list& free_list,
                                                            hw_index_list_it hw_index_it,
                                                            bool update_withdraw_stack)
{
    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::ALLOCATE_HW_INDEX;
        waction.action_data = withdraw_action::allocate_hw_index{.hw_index = *hw_index_it};
        m_withdraw_stack.push_back(waction);
    }

    if (!is_hw_index_is_sram_pinned(*hw_index_it)) {
        m_free_indexes_for_hbm_caching--;
    }

    free_list.erase(hw_index_it);
}

void
lpm_hw_index_allocator_sram_pinning::atom_release_hw_index(lpm_bucket_index_t hw_index, bool update_withdraw_stack)
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    dassert_slow(!is_hw_index_free(hw_index));

    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::RELEASE_HW_INDEX;
        waction.action_data = withdraw_action::release_hw_index{.hw_index = hw_index};
        m_withdraw_stack.push_back(waction);
    }

    lpm_bucket_index_list& index_list = get_list(hw_index);
    index_list.push_back(hw_index);
    if (!is_hw_index_is_sram_pinned(hw_index)) {
        m_free_indexes_for_hbm_caching++;
    }
}

void
lpm_hw_index_allocator_sram_pinning::atom_mark_hw_index_line(lpm_bucket_index_t hw_index, bool is_dirty, bool update_withdraw_stack)
{
    size_t line = get_line(hw_index);

    if (update_withdraw_stack) {
        bool dirty_bit = m_line_dirty_bit.bit(line);
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::MARK_LINE_FOR_CONSISTENCY;
        waction.action_data = withdraw_action::mark_line_for_consistency{.hw_index = hw_index, .old_is_dirty = dirty_bit};
        m_withdraw_stack.push_back(waction);
    }

    m_line_dirty_bit.set_bit(line, is_dirty);
}

void
lpm_hw_index_allocator_sram_pinning::notify_hw_index_size_changed(lpm_bucket_index_t hw_index, size_t bucket_size)
{
    return;
}

bool
lpm_hw_index_allocator_sram_pinning::sanity() const
{
    dassert_crit(m_line_dirty_bit.is_zero());

    // Make sure each index appears at most once in the free list.
    bit_vector index_map = bit_vector();
    for (const auto& free_list : {m_sram_pinned_indexes, m_hbm_caching_indexes}) {
        for (const auto& index : free_list) {
            if (index_map.bit(index)) {
                dassert_crit(false);
                return false;
            }
            index_map.set_bit(index, true);
        }
    }

    return true;
}

void
lpm_hw_index_allocator_sram_pinning::clear_iteration_members()
{
    m_line_dirty_bit = bit_vector(0, m_line_dirty_bit.get_width());
}

size_t
lpm_hw_index_allocator_sram_pinning::get_line(lpm_bucket_index_t hw_index) const
{
    return (hw_index) / 2;
}

size_t
lpm_hw_index_allocator_sram_pinning::get_number_of_free_indices() const
{
    return m_hbm_caching_indexes.size() + m_sram_pinned_indexes.size();
}

size_t
lpm_hw_index_allocator_sram_pinning::get_number_of_free_indices_for_hbm_caching() const
{
    return m_free_indexes_for_hbm_caching;
}

bool
lpm_hw_index_allocator_sram_pinning::is_hw_index_free(lpm_bucket_index_t hw_index) const
{
    dassert_crit(hw_index != LPM_NULL_INDEX);
    lpm_bucket_index_list& index_list = get_list(hw_index);
    bool is_free = contains(index_list, hw_index);
    return is_free;
}

} // namespace silicon_one
