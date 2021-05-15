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

#ifndef __LEABA_LPM_HW_INDEX_SINGLES_ALLOCATOR_H__
#define __LEABA_LPM_HW_INDEX_SINGLES_ALLOCATOR_H__
#include "lpm/lpm_hw_index_allocator.h"
#include "lpm/lpm_internal_types.h"
#include "lpm_bucket.h"
#include <boost/variant.hpp>

namespace silicon_one
{

class lpm_hw_index_singles_allocator : public lpm_hw_index_allocator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct and initialize lpm_hw_index_singles_allocator
    ///
    /// @param[in]      name                                Name of the HW index allocator.
    /// @param[in]      first_line                          First available HW index.
    /// @param[in]      num_lines                           Number of HW indexes.
    /// @param[in]      step                                Jump between each 2 consecutive HW indexes.
    lpm_hw_index_singles_allocator(std::string name, size_t first_line, size_t num_lines, size_t step);

    // lpm_hw_index_allocator API-s
    la_status allocate_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t& out_hw_index) override;
    la_status allocate_specific_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t hw_index) override;
    void release_hw_index(lpm_bucket_index_t hw_index) override;
    void commit() override;
    void withdraw() override;
    bool is_hw_index_free(lpm_bucket_index_t hw_index) const override;
    size_t get_number_of_free_indices() const override;
    void notify_hw_index_size_changed(lpm_bucket_index_t hw_index, size_t bucket_size) override;
    bool sanity() const override;

private:
    ///@brief Struct describing a withdraw stack entry.
    struct withdraw_action {

        ///@brief type of withdraw action.
        enum class action_type_e {
            RELEASE_HW_INDEX,  ///< Insert to free list operation.
            ALLOCATE_HW_INDEX, ///< Remove from free list operation.
        };

        struct release_hw_index {
            lpm_bucket_index_t hw_index;
        };

        struct allocate_hw_index {
            lpm_bucket_index_t hw_index;
        };

        action_type_e action_type;
        boost::variant<boost::blank, release_hw_index, allocate_hw_index> action_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::release_hw_index)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::allocate_hw_index)

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_hw_index_singles_allocator() = default;

    /// @name Data structure handling
    /// @{

    /// @brief Actual release HW index.
    ///
    /// @param[in]      to_list                     List to push the given HW index.
    /// @param[in]      hw_index                    HW index to release.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_insert_index_to_list(lpm_bucket_index_list& to_list, lpm_bucket_index_t hw_index, bool update_withdraw_stack);

    /// @brief Actual allocate a given HW index.
    ///
    /// @param[in]      from_list                   List to erase the given iterator from.
    /// @param[in]      item_to_erase               Iterator to the member we want to allocate.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_remove_index_from_list(lpm_bucket_index_list& from_list, hw_index_list_it item_to_erase, bool update_withdraw_stack);

    /// @}

    /// @name Commit/Withdraw API.
    /// @{

    /// @brief Clear all data needed for the current iteration.
    void clear_iteration_members();

    /// @brief Withdraw a single action.
    ///
    /// @param[in]        waction              Action to withdraw.
    void withdraw_one_action(const withdraw_action& waction);

    /// @}

    // Properties
    std::string m_name; ///< HW index allocator's name.

    // Members
    lpm_bucket_index_list m_free_list;              ///< List containing the pool of free HW indexes.
    lpm_bucket_index_list m_dirty_list;             ///< List of HW indexes to be freed once commit() is called.
    size_t m_num_free_indexes;                      ///< Track number of free indexes. std::list size() has performance bug O(n).
    vector_alloc<withdraw_action> m_withdraw_stack; ///< Withdraw stack.
};
} // namespace silicon_one

#endif
