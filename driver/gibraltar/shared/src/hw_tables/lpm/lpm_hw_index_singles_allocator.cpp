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

#include "lpm/lpm_hw_index_singles_allocator.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lpm/lpm_internal_types.h"

#include <algorithm>

namespace silicon_one
{

lpm_hw_index_singles_allocator::lpm_hw_index_singles_allocator(std::string name, size_t first_line, size_t num_lines, size_t step)
    : m_name(name), m_num_free_indexes(num_lines)
{
    size_t index = first_line;
    for (size_t i = 0; i < num_lines; i++) {
        m_free_list.push_back(index);
        index += step;
    }
}

la_status
lpm_hw_index_singles_allocator::allocate_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t& out_hw_index)
{
    if (m_free_list.empty()) {
        log_debug(TABLES, "%s: %s, OOR", m_name.c_str(), __func__);
        return LA_STATUS_ERESOURCE;
    }

    hw_index_list_it item_to_erase = m_free_list.begin();
    out_hw_index = *item_to_erase;
    log_debug(TABLES, "%s lpm_hw_index_singles_allocator::%s, HW index=%d", m_name.c_str(), __func__, out_hw_index);

    atom_remove_index_from_list(m_free_list, item_to_erase, true /* update_withdraw_stack */);
    return LA_STATUS_SUCCESS;
}

la_status
lpm_hw_index_singles_allocator::allocate_specific_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t hw_index)
{
    auto item_to_erase = std::find(m_free_list.begin(), m_free_list.end(), hw_index);
    if (item_to_erase == m_free_list.end()) {
        return LA_STATUS_EBUSY;
    }

    log_debug(TABLES, "%s lpm_hw_index_singles_allocator::%s, HW index=%d", m_name.c_str(), __func__, hw_index);
    atom_remove_index_from_list(m_free_list, item_to_erase, true /* update_withdraw_stack */);
    return LA_STATUS_SUCCESS;
}

void
lpm_hw_index_singles_allocator::release_hw_index(lpm_bucket_index_t hw_index)
{
    dassert_slow(!contains(m_free_list, hw_index));
    log_debug(TABLES, "%s lpm_hw_index_singles_allocator::%s, HW index=%d", m_name.c_str(), __func__, hw_index);
    atom_insert_index_to_list(m_dirty_list /* to_list */, hw_index, true /* update_withdraw_stack */);
}

void
lpm_hw_index_singles_allocator::commit()
{
    log_debug(TABLES, "%s lpm_hw_index_singles_allocator::%s", m_name.c_str(), __func__);
    m_free_list.splice(m_free_list.end(), m_dirty_list);
    m_withdraw_stack.clear();
    clear_iteration_members();

    dassert_slow(sanity());
}

void
lpm_hw_index_singles_allocator::withdraw()
{
    log_debug(TABLES, "%s lpm_hw_index_singles_allocator::%s", m_name.c_str(), __func__);
    for (auto it = m_withdraw_stack.rbegin(); it != m_withdraw_stack.rend(); it++) {
        withdraw_one_action(*it);
    }

    m_withdraw_stack.clear();

    dassert_slow(sanity());
}

void
lpm_hw_index_singles_allocator::clear_iteration_members()
{
    m_dirty_list.clear();
}

void
lpm_hw_index_singles_allocator::withdraw_one_action(const withdraw_action& waction)
{
    switch (waction.action_type) {
    case withdraw_action::action_type_e::RELEASE_HW_INDEX: {
        const auto& action_data = boost::get<withdraw_action::release_hw_index>(waction.action_data);
        hw_index_list_it item_to_erase = m_dirty_list.begin();
        dassert_crit(*item_to_erase == action_data.hw_index);
        atom_remove_index_from_list(m_dirty_list /* to_list */, item_to_erase, false /* update_withdraw_stack */);
        break;
    };
    case withdraw_action::action_type_e::ALLOCATE_HW_INDEX: {
        const auto& action_data = boost::get<withdraw_action::allocate_hw_index>(waction.action_data);
        lpm_bucket_index_t hw_index = action_data.hw_index;
        dassert_slow(!(contains(m_free_list, hw_index)));
        atom_insert_index_to_list(m_free_list /* to_list */, hw_index, false /* update_withdraw_stack */);
        break;
    };
    default:
        dassert_crit(false);
    }
}

bool
lpm_hw_index_singles_allocator::is_hw_index_free(lpm_bucket_index_t hw_index) const
{
    bool is_free = contains(m_free_list, hw_index);
    return is_free;
}

size_t
lpm_hw_index_singles_allocator::get_number_of_free_indices() const
{
    return m_num_free_indexes;
}

void
lpm_hw_index_singles_allocator::notify_hw_index_size_changed(lpm_bucket_index_t hw_index, size_t bucket_size)
{
    return;
}

void
lpm_hw_index_singles_allocator::atom_insert_index_to_list(lpm_bucket_index_list& to_list,
                                                          lpm_bucket_index_t hw_index,
                                                          bool update_withdraw_stack)
{
    if (update_withdraw_stack) {
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::RELEASE_HW_INDEX;
        waction.action_data = withdraw_action::release_hw_index{.hw_index = hw_index};
        m_withdraw_stack.push_back(waction);
    }

    m_num_free_indexes++;
    to_list.push_front(hw_index);
}

void
lpm_hw_index_singles_allocator::atom_remove_index_from_list(lpm_bucket_index_list& from_list,
                                                            hw_index_list_it item_to_erase,
                                                            bool update_withdraw_stack)
{
    if (update_withdraw_stack) {
        lpm_bucket_index_t hw_index = *item_to_erase;
        withdraw_action waction;
        waction.action_type = withdraw_action::action_type_e::ALLOCATE_HW_INDEX;
        waction.action_data = withdraw_action::allocate_hw_index{.hw_index = hw_index};
        m_withdraw_stack.push_back(waction);
    }

    m_num_free_indexes--;
    from_list.erase(item_to_erase);
}

bool
lpm_hw_index_singles_allocator::sanity() const
{
    dassert_crit(m_dirty_list.empty());

    // Make sure each index appears at most once in the free list.
    bit_vector index_map = bit_vector();
    for (const auto& index : m_free_list) {
        if (index_map.bit(index)) {
            dassert_crit(false);
            return false;
        }
        index_map.set_bit(index, true);
    }

    return true;
}

} // namespace silicon_one
