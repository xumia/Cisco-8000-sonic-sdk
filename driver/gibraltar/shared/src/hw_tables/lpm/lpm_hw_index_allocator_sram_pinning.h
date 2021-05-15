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

#ifndef __leaba_LPM_HW_INDEX_ALLOCATOR_SRAM_PINNING_h__
#define __leaba_LPM_HW_INDEX_ALLOCATOR_SRAM_PINNING_h__

#include "hw_tables/hw_tables_fwd.h"
#include "lpm/lpm_hw_index_allocator.h"
#include "lpm/lpm_internal_types.h"

#include <boost/variant.hpp>

namespace silicon_one
{

class lpm_hw_index_allocator_sram_pinning : public lpm_hw_index_allocator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    enum class index_type {
        SRAM_PINNED, ///< Index for permanent SRAM bucket.
        NORMAL,      ///< Index taking part of the HBM caching.
    };

    /// @brief Construct and initialize lpm_hw_index_allocator_sram_pinning
    ///
    /// @param[in]      name                                    Name of the HW index allocator.
    /// @param[in]      first_line                              First HW line.
    /// @param[in]      num_of_lines                            Number of HW lines.
    lpm_hw_index_allocator_sram_pinning(std::string name, size_t first_line, size_t num_of_lines);

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

    /// @brief Get number of free indices taking part of the HBM caching.
    ///
    /// @return Number of free indicess.
    size_t get_number_of_free_indices_for_hbm_caching() const;

    /// @brief Allocate a HW index for a bucket with a given constraint.
    ///
    /// @param[in]      type                Type of index to return SRAM_PINNED/NORMAL.
    /// @param[out]     out_hw_index        Allocated HW index for bucket.
    ///
    /// @return #la_status.
    la_status allocate_hw_index_for_bucket(index_type type, lpm_bucket_index_t& out_hw_index);

    /// @brief Check whether HW index is sram pinned.
    ///
    /// @param[in]      hw_index            HW index to check.
    ///
    /// @return if HW index is SRAM pinned or not.
    bool is_hw_index_is_sram_pinned(lpm_bucket_index_t hw_index) const;

    /// @}

private:
    ///@brief Struct describing a withdraw stack entry.
    struct withdraw_action {

        ///@brief type of withdraw action.
        enum class action_type_e {
            RELEASE_HW_INDEX,          ///< Insert to free list operation.
            ALLOCATE_HW_INDEX,         ///< Remove from free list operation.
            MARK_LINE_FOR_CONSISTENCY, ///< Mark line as allocatable or non-allocatable.
        };

        struct allocate_hw_index {
            lpm_bucket_index_t hw_index;
        };

        struct release_hw_index {
            lpm_bucket_index_t hw_index;
        };

        struct mark_line_for_consistency {
            lpm_bucket_index_t hw_index;
            bool old_is_dirty;
        };

        action_type_e action_type;
        boost::variant<boost::blank, release_hw_index, allocate_hw_index, mark_line_for_consistency> action_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::allocate_hw_index)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::release_hw_index)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::mark_line_for_consistency)

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_hw_index_allocator_sram_pinning() : m_first_index()
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
    lpm_bucket_index_list& get_list(lpm_bucket_index_t hw_index) const;

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
    void atom_allocate_hw_index(lpm_bucket_index_list& free_list, hw_index_list_it hw_index_it, bool update_withdraw_stack);

    /// @brief Actual release HW index.
    ///
    /// @param[in]      hw_index                    HW index to release.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_release_hw_index(lpm_bucket_index_t hw_index, bool update_withdraw_stack);

    /// @brief Actual mark line that HW index belongs.
    ///
    /// @param[in]      hw_index                    HW index to release.
    /// @param[in]      is_dirty                    Predicate instruct whether to enable/disable allocation from this line.
    /// @param[in]      update_withdraw_stack       Predicate instruct whether to note this action for withdraw.
    void atom_mark_hw_index_line(lpm_bucket_index_t hw_index, bool is_dirty, bool update_withdraw_stack);

    /// @}

    // Properties
    std::string m_name;                    ///< HW index allocator's name.
    const size_t m_first_index;            ///< First HW index
    size_t m_free_indexes_for_hbm_caching; ///< Number of free hw indexes taking part of the HBM caching - std::list size() has
                                           /// performance bug O(n)

    // Members
    bit_vector m_line_dirty_bit;                 ///< Vector of bit per line
    lpm_bucket_index_list m_hbm_caching_indexes; ///< List containing the pool of regular HW indexes.
    lpm_bucket_index_list m_sram_pinned_indexes; ///< List containing the pool of SRAM-pinned HW indexes.

    // Withdraw
    vector_alloc<withdraw_action> m_withdraw_stack; ///< Withdraw stack.

}; // class lpm_hw_index_allocator_sram_pinning

} // namespace silicon_one

#endif
