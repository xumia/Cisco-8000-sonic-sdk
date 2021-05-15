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

#ifndef __LEABA_LPM_HW_INDEX_DOUBLES_ALLOCATOR_PACIFIC_H__
#define __LEABA_LPM_HW_INDEX_DOUBLES_ALLOCATOR_PACIFIC_H__

#include "lpm/lpm_hw_index_allocator_adapter.h"
#include "lpm/lpm_internal_types.h"
#include "lpm_bucket.h"
#include <boost/variant.hpp>

namespace silicon_one
{

class lpm_hw_index_doubles_allocator_pacific : public lpm_hw_index_allocator_adapter
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Line shared entries type.
    enum class shared_entries_type_e {
        SINGLE_ENTRIES = 0, ///< All shared entries are singles.
        DOUBLE_ENTRIES,     ///< All shared entries are doubles.
        UNDETERMINED        ///< There are no shared entries.
    };

    /// @brief Shared entries usage descriptor.
    struct shared_entries_descriptor {
        shared_entries_type_e line_state; ///< Shared entries type.
        size_t num_shared_entries;        ///< Number of shared entries.
    };

    /// @brief Construct and initialize lpm_hw_index_doubles_allocator_pacific
    ///
    /// @param[in]      name                                    Name of the HW index allocator.
    /// @param[in]      num_sram_hw_lines
    /// @param[in]      num_fixed_entries_per_bucket            Number of fixed entries in each HW index.
    /// @param[in]      num_shared_entries_per_double_bucket    Number of shared entries between 2 complementary indexes.
    lpm_hw_index_doubles_allocator_pacific(std::string name,
                                           size_t num_sram_hw_lines,
                                           size_t num_fixed_entries_per_bucket,
                                           size_t num_shared_entries_per_double_bucket);

    // lpm_hw_index_allocator API-s
    la_status allocate_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                           lpm_bucket_index_t& out_hw_index) override;
    la_status allocate_specific_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                    lpm_bucket_index_t hw_index) override;
    void release_hw_index(lpm_bucket_index_t hw_index) override;
    void commit() override;
    void withdraw() override;
    void notify_hw_index_occupancy_changed(lpm_bucket_index_t hw_index, const lpm_bucket::occupancy_data& occupancy_data) override;
    bool sanity() const override;
    bool is_hw_index_free(lpm_bucket_index_t hw_index) const override;
    size_t get_number_of_free_indices() const override;

    // Getters

    /// @brief Translate bucket occupancy to shared_entries_descriptor.
    ///
    /// @param[in]      occupancy_data          Data contains the physical size to be written to HW.
    ///
    /// @return Descriptor of the shared entries occupancy_data contains.
    shared_entries_descriptor bucket_occupancy_to_shared_entries_descriptor(const lpm_bucket::occupancy_data& occupancy_data) const;

    /// @brief Get shared_entries_descriptor of a give hw_index.
    ///
    /// @param[in]      hw_index        HW index to allocate.
    ///
    /// @return Descriptor of the shared entries it contains.
    shared_entries_descriptor get_hw_index_occupancy(lpm_bucket_index_t hw_index) const;

private:
    /// @brief Index current state.
    struct hw_index_state {
        hw_index_list_it free_list_iterator; ///< Pointer to free_list node that contains the index.
        size_t used_shared_entries;          ///< Number of shared entries used by the index.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(hw_index_state);

    using hw_line_state_vec = vector_alloc<shared_entries_type_e>;
    using hw_index_lists_vec = vector_alloc<lpm_bucket_index_list>;
    using hw_index_state_vec = vector_alloc<hw_index_state>;

    ///@brief Struct describing a withdraw stack entry.
    struct withdraw_action {

        ///@brief type of withdraw action.
        enum class action_type_e {
            RELEASE_HW_INDEX,          ///< Insert to free list operation.
            ALLOCATE_HW_INDEX,         ///< Remove from free list operation.
            CHANGE_HW_INDEX_OCCUPANCY, ///< Change HW index occupancy.
            MARK_LINE_FOR_CONSISTENCY, ///< Mark line as allocatable or non-allocatable.
        };

        struct release_hw_index {
            lpm_bucket_index_t hw_index;
            shared_entries_descriptor old_occupancy;
        };

        struct change_hw_index {
            lpm_bucket_index_t hw_index;
            shared_entries_descriptor old_occupancy;
        };

        struct allocate_hw_index {
            lpm_bucket_index_t hw_index;
        };

        struct mark_line_for_consistency {
            size_t line;
            bool old_is_dirty;
        };

        action_type_e action_type;
        boost::variant<boost::blank, release_hw_index, change_hw_index, allocate_hw_index, mark_line_for_consistency> action_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action);
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::release_hw_index);
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::change_hw_index);
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::allocate_hw_index);
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::mark_line_for_consistency);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_hw_index_doubles_allocator_pacific()
        : m_num_fixed_entries_per_bucket(), m_num_shared_entries_per_double_bucket(), m_dummy_list_it()
    {
    }

    /// @name Data structure handling
    /// @{

    /// @brief Actual release HW index.
    ///
    /// @param[in]      hw_index                    HW index to release.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_release_hw_index(lpm_bucket_index_t hw_index, bool update_withdraw_stack);

    /// @brief Actual allocate a given HW index.
    ///
    /// @param[in]      free_list                   Free list the item_to_erase belongs to.
    /// @param[in]      item_to_erase               Iterator to the member we want to allocate.
    /// @param[in]      occ                         Shared entries descriptor of the allocated index.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_allocate_hw_index(lpm_bucket_index_list& free_list,
                                hw_index_list_it item_to_erase,
                                const shared_entries_descriptor& occ,
                                bool update_withdraw_stack);

    /// @brief Actual change HW index occupancy.
    ///
    /// @param[in]      hw_index                    HW index to change its occupancy.
    /// @param[in]      occ                         The new occupancy of the index.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_change_hw_index_occupancy(lpm_bucket_index_t hw_index,
                                        const shared_entries_descriptor& occ,
                                        bool update_withdraw_stack);

    /// @brief Mark the line as temporary allocatable or not.
    ///
    /// @param[in]      line                    Line to mark.
    /// @param[in]      is_dirty                Predicate instruct whether to enable/disable allocation from this line.
    /// @param[in]      update_withdraw_stack   Predicate instruct whether to note this action for withdraw.
    void atom_mark_line(size_t line, bool is_dirty, bool update_withdraw_stack);

    /// @}

    /// @name Helper functions
    /// @{

    /// @brief Allocate HW index for bucket with given occupancy from specific free_list.
    ///
    /// @param[in]      free_list                   Free list to allocate from.
    /// @param[in]      occ                         Shared entries descriptor of the allocated index.
    /// @param[out]     out_allocated_index         Allocated HW index.
    void allocate_hw_index_from_list(lpm_bucket_index_list& free_list,
                                     const shared_entries_descriptor& occ,
                                     lpm_bucket_index_t& out_allocated_index);

    /// @brief Check whether given occupancy fits to a give HW location.
    ///
    /// @param[in]      occupancy_data  New shared entries descriptor to the index.
    /// @param[in]      hw_index        HW index to allocate.
    ///
    /// @return True, if change is legal.
    bool does_occupancy_fit_space(const shared_entries_descriptor& occupancy_data, lpm_bucket_index_t hw_index) const;

    /// @name Common helper calculations
    /// @{

    /// @brief Get maximum number of shared entries.
    ///
    /// @param[in]      has_doubles        Type of the shared entries.
    ///
    /// @return The maximum number of shared entries.
    size_t get_max_shared_entries(bool has_doubles) const;

    /// @brief Get the complementary index of a given index.
    ///
    /// @param[in]      hw_index        HW index to find its complementary.
    ///
    /// @return The complementary index.
    lpm_bucket_index_t get_neighbour_hw_index(lpm_bucket_index_t hw_index) const;

    /// @brief Get the line of a given index.
    ///
    /// @param[in]      hw_index        HW index to find its line.
    ///
    /// @return The line of the index.
    size_t get_line(lpm_bucket_index_t hw_index) const;

    /// @brief Get the vector of lists fits to the corresponding line state.
    ///
    /// @param[in]      line_state        Type of the shared entries.
    ///
    /// @return Member vector containing the free lists of the line_state.
    hw_index_lists_vec& get_lists(shared_entries_type_e line_state) const;

    /// @brief Get the free list containing a given index.
    ///
    /// @param[in]      hw_index        HW index to find its list.
    ///
    /// @return The list containing the index.
    const lpm_bucket_index_list& get_list(lpm_bucket_index_t hw_index) const;

    /// @brief Get the free list containing a given index.
    ///
    /// @param[in]      hw_index        HW index to find its list.
    ///
    /// @return The list containing the index.
    lpm_bucket_index_list& get_list(lpm_bucket_index_t hw_index);

    /// @}

    hw_index_list_it insert_to_list(lpm_bucket_index_list& list, lpm_bucket_index_t hw_index);

    /// @brief Withdraw a single action.
    ///
    /// @param[in]        waction              Action to withdraw.
    void withdraw_one_action(const withdraw_action& waction);

    /// @brief Clear all data needed for the current iteration.
    void clear_iteration_members();

    /// @brief Manually serialize m_hw_indexes_state.
    ///
    /// @return m_hw_indexes_state to be partially automatically serialized.
    const hw_index_state_vec& save_m_hw_indexes_state() const;

    /// @brief Manually deserialize of the data in m_hw_indexes_state.
    ///
    /// @param[in]    Partially deserialized m_hw_indexes_state.
    void load_m_hw_indexes_state(const hw_index_state_vec& serialized_list);

    /// @brief Restore free_list_iterator in m_hw_indexes_state's elelments.
    ///
    /// @param[in]    List of free elements to point the iterators to.
    void restore_free_iterators_from_index_list(lpm_bucket_index_list& free_list);

    /// @brief Restore free_list_iterator in m_hw_indexes_state's elelments.
    ///
    /// @param[in]    Vector of lists of free elements to point the iterators to.
    void restore_free_iterators_from_vector_of_index_list(hw_index_lists_vec& free_lists);

    // Properties
    std::string m_name;                                  ///< HW index allocator's name.
    const size_t m_num_fixed_entries_per_bucket;         ///< Number of fixed entries per bucket
    const size_t m_num_shared_entries_per_double_bucket; ///< Number of shared entries between buckets

    // Stats
    size_t m_num_free_indexes; ///< Number of free hw indexes - std::list size() has performance bug O(n)
    const hw_index_list_it m_dummy_list_it;

    // Members
    hw_index_state_vec m_hw_indexes_state; ///< Hw index to state vector
    bit_vector m_line_dirty_bit;           ///< Vector of bit per line
    hw_index_lists_vec m_singles_free_lists;
    hw_index_lists_vec m_doubles_free_lists;
    lpm_bucket_index_list m_undetermined_free_list;
    hw_line_state_vec m_hw_line_to_state;

    // Withdraw
    vector_alloc<withdraw_action> m_withdraw_stack; ///< Withdraw stack.
};

} // namespace silicon_one

#endif
