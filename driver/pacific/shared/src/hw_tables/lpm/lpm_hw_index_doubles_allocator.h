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

#ifndef __LEABA_LPM_HW_INDEX_DOUBLES_ALLOCATOR_H__
#define __LEABA_LPM_HW_INDEX_DOUBLES_ALLOCATOR_H__

#include "hw_tables/hw_tables_fwd.h"
#include "lpm/lpm_hw_index_allocator.h"
#include "lpm/lpm_internal_types.h"

#include <boost/variant.hpp>

namespace silicon_one
{

class lpm_hw_index_doubles_allocator : public lpm_hw_index_allocator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct and initialize lpm_hw_index_doubles_allocator
    ///
    /// @param[in]      name                                    Name of the HW index allocator.
    /// @param[in]      first_index                             First available HW index.
    /// @param[in]      num_indexes                             Number of HW indexes.
    /// @param[in]      num_fixed_entries_per_bucket            Number of fixed entries in each HW index.
    /// @param[in]      num_shared_entries_per_double_bucket    Number of shared entries between 2 complementary indexes.
    lpm_hw_index_doubles_allocator(std::string name,
                                   size_t first_line,
                                   size_t num_of_sram_lines,
                                   size_t num_fixed_entries_per_bucket,
                                   size_t num_shared_entries_per_double_bucket);

    // lpm_hw_index_allocator API-s
    la_status allocate_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t& out_hw_index) override;
    la_status allocate_specific_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t hw_index) override;
    void release_hw_index(lpm_bucket_index_t hw_index) override;
    void commit() override;
    void withdraw() override;
    void notify_hw_index_size_changed(lpm_bucket_index_t hw_index, size_t bucket_size) override;
    size_t get_number_of_free_indices() const override;
    bool is_hw_index_free(lpm_bucket_index_t hw_index) const override;
    bool sanity() const override;

    /// @name Getter functions
    /// @{

    /// @brief Get the complementary index of a given index.
    ///
    /// @param[in]      hw_index        HW index to find its complementary.
    ///
    /// @return The complementary index.
    lpm_bucket_index_t get_neighbour_hw_index(lpm_bucket_index_t hw_index) const;

    /// @brief Get number of used shared entries for a give hw_index.
    ///
    /// @param[in]      hw_index        HW index to get its size.
    ///
    /// @return Number of shared entries.
    size_t get_hw_index_size(lpm_bucket_index_t hw_index) const;

    /// @}

private:
    /// @brief Index current state.
    struct hw_index_state {
        hw_index_list_it free_list_iterator; ///< Pointer to free_list node that contains the index.
        size_t used_shared_entries;          ///< Number of shared entries used by the index.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(hw_index_state)

    using hw_index_lists_vec = vector_alloc<lpm_bucket_index_list>;
    using hw_index_state_vec = vector_alloc<hw_index_state>;

    ///@brief Struct describing a withdraw stack entry.
    struct withdraw_action {

        ///@brief type of withdraw action.
        enum class action_type_e {
            RELEASE_HW_INDEX,          ///< Insert to free list operation.
            ALLOCATE_HW_INDEX,         ///< Remove from free list operation.
            CHANGE_HW_INDEX_SIZE,      ///< Change HW index size.
            MARK_LINE_FOR_CONSISTENCY, ///< Mark line as allocatable or non-allocatable.
        };

        struct allocate_hw_index {
            lpm_bucket_index_t hw_index;
        };

        struct release_hw_index {
            lpm_bucket_index_t hw_index;
            size_t old_size;
        };

        struct change_hw_index {
            lpm_bucket_index_t hw_index;
            size_t old_size;
        };

        struct mark_line_for_consistency {
            lpm_bucket_index_t hw_index;
            bool old_is_dirty;
        };

        action_type_e action_type;
        boost::variant<boost::blank, release_hw_index, change_hw_index, allocate_hw_index, mark_line_for_consistency> action_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::allocate_hw_index)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::release_hw_index)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::change_hw_index)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::mark_line_for_consistency)

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_hw_index_doubles_allocator()
        : m_num_fixed_entries_per_bucket(), m_num_shared_entries_per_double_bucket(), m_first_index(), m_dummy_list_it()
    {
    }

    /// @name Helper functions
    /// @{

    /// @brief Get the line of a given index.
    ///
    /// @param[in]      hw_index        HW index to find its line.
    ///
    /// @return The line of the index.
    size_t get_line(lpm_bucket_index_t hw_index) const;

    /// @brief Get the free list containing a given index.
    ///
    /// @param[in]      hw_index        HW index to find its list.
    ///
    /// @return The list containing the index.
    lpm_bucket_index_list& get_list(lpm_bucket_index_t hw_index);

    /// @brief Translate size to number of shared entries.
    ///
    /// @param[in]      bucket_size         Physical size of the bucket.
    ///
    /// @return Number of shared entries that size_data contains.
    size_t bucket_size_to_shared_entries(size_t bucket_size);

    /// @}

    /// @name Commit/Withdraw handling
    /// @{

    /// @brief Clear all data needed for the current iteration.
    void clear_iteration_members();

    /// @brief Withdraw one action.
    ///
    /// @param[in]      action                      Action to perform.
    void withdraw_one_action(const withdraw_action& action);

    /// @}

    /// @name Data structure handling
    /// @{

    /// @brief Actual allocate HW index.
    ///
    /// @param[in]      free_list                    Free list that contains HW index.
    /// @param[in]      hw_index                     HW index to allocate.
    /// @param[in]      num_shared_entries           Number of shared entries to be allocated.
    /// @param[in]      update_withdraw_stack        Predicate instruct whether to note this action for withdraw.
    void atom_allocate_hw_index(lpm_bucket_index_list& free_list,
                                lpm_bucket_index_t hw_index,
                                size_t num_shared_entries,
                                bool update_withdraw_stack);

    /// @brief Actual release HW index.
    ///
    /// @param[in]      hw_index                    HW index to release.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_release_hw_index(lpm_bucket_index_t hw_index, bool update_withdraw_stack);

    /// @brief Actual change HW index size.
    ///
    /// @param[in]      hw_index                    HW index to change.
    /// @param[in]      num_shared_entries          New size.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_change_hw_index_size(lpm_bucket_index_t hw_index, size_t num_shared_entries, bool update_withdraw_stack);

    /// @brief Actual mark line that HW index belongs.
    ///
    /// @param[in]      hw_index                    HW index to release.
    /// @param[in]      is_dirty                    Predicate instruct whether to enable/disable allocation from this line.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_mark_hw_index_line(lpm_bucket_index_t hw_index, bool is_dirty, bool update_withdraw_stack);

    /// @}

    /// @brief Manually serialize m_hw_indexes_state.
    ///
    /// @return m_hw_indexes_state to be partially automatically serialized.
    const hw_index_state_vec& save_m_hw_indexes_state() const;

    /// @brief Manually deserialize of the data in m_hw_indexes_state.
    ///
    /// @param[in]    Partially deserialized m_hw_indexes_state.
    void load_m_hw_indexes_state(const hw_index_state_vec& serialized_list);

    // Properties
    std::string m_name;                                  ///< HW index allocator's name.
    const size_t m_num_fixed_entries_per_bucket;         ///< Number of fixed entries per bucket
    const size_t m_num_shared_entries_per_double_bucket; ///< Number of shared entries between buckets
    const size_t m_first_index;                          ///< First HW index
    size_t m_num_free_indexes;                           ///< Number of free hw indexes - std::list size() has performance bug O(n)

    // Members
    // serialize: manual serailization
    hw_index_state_vec m_hw_indexes_state; ///< Hw index to state vector
    bit_vector m_line_dirty_bit;           ///< Vector of bit per line
    const hw_index_list_it m_dummy_list_it;

    // Stats
    hw_index_lists_vec m_free_lists; ///< Lists of free hw indexes

    // Withdraw
    vector_alloc<withdraw_action> m_withdraw_stack; ///< Withdraw stack.

}; // class lpm_hw_index_doubles_allocator

} // namespace silicon_one

#endif
