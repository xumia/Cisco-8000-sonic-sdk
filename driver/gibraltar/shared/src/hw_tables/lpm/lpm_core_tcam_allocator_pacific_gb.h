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

#ifndef __LEABA_LPM_CORE_TCAM_ALLOCATOR_PACIFIC_GB_H__
#define __LEABA_LPM_CORE_TCAM_ALLOCATOR_PACIFIC_GB_H__

#include "lpm_core_tcam_allocator.h"

namespace silicon_one
{

class lpm_core_tcam_allocator_pacific_gb : public lpm_core_tcam_allocator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @name Resource creation and initialization
    /// @{

    /// @brief Construct a LPM TCAM allocator object.
    ///
    /// @param[in]     name                          Name of TCAM allocator.
    /// @param[in]     num_banksets                  Number of banksets.
    /// @param[in]     num_cells_per_bank            Number of cells in each bank.
    /// @param[in]     max_num_quad_blocks           Maximum number of QUAD blocks in TCAM.
    lpm_core_tcam_allocator_pacific_gb(std::string name,
                                       uint8_t num_banksets,
                                       uint32_t num_cells_per_bank,
                                       uint32_t max_num_quad_blocks);

    // lpm core tcam allocator API-s
    la_status make_space(logical_tcam_type_e logical_tcam,
                         const free_blocks_array& free_blocks,
                         allocator_instruction_vec& out_instructions) override;
    size_t get_max_quad_blocks() const override;

protected:
    // lpm core tcam allocator virtual functions
    void block_last_blocks(allocator_instruction_vec& out_instructions) override;

private:
    /// @brief Region in TCAM.
    enum class tcam_region_e {
        QUAD,          ///< Region allocated for QUAD entries.
        HARDWARE_QUAD, ///< Region not allocated for QUAD entries but configured in hardware as QUAD.
        BANKSET0,      ///< Remainder of Bankset 0.
        BANKSETN,      ///< Any bankset other that banksets 0.
    };

    /// @brief Search direction.
    enum class search_direction_e {
        TOP,    ///< Start search from the top.
        BOTTOM, ///< Start search from the bottom.
    };

    /// @brief Default c'tor - shouldn't be used, allowed only for serialization purposes.
    lpm_core_tcam_allocator_pacific_gb() = default;

    /// @brief Get the region of a given location.
    ///
    /// @param[in]   location                     Location to find region of.
    ///
    /// @return TCAM region of location.
    tcam_region_e get_tcam_region_of_location(tcam_cell_location location) const;

    /// @brief Make space for a block of type SINGLE.
    ///
    /// @param[in,out]   free_blocks                   Number of free blocks in each logical TCAM.
    /// @param[out]      out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return Number of blocks given.
    size_t make_space_for_a_single_block(free_blocks_array& free_blocks, allocator_instruction_vec& out_instructions);

    /// @brief Make space for a block of type DOUBLE.
    ///
    /// @param[in,out]   free_blocks                   Number of free blocks in each logical TCAM.
    /// @param[out]      out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return Number of blocks given.
    size_t make_space_for_a_double_block(free_blocks_array& free_blocks, allocator_instruction_vec& out_instructions);

    /// @brief Make space for a block of type QUAD.
    ///
    /// @param[in,out]   free_blocks                   Number of free blocks in each logical TCAM.
    /// @param[out]      out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return Number of blocks given.
    size_t make_space_for_a_quad_block(free_blocks_array& free_blocks, allocator_instruction_vec& out_instructions);

    /// @brief Get bottommost block of a logical TCAM.
    ///
    /// @param[in]   logical_tcam                  Logical TCAM.
    /// @param[out]  out_location                  Location of found block.
    ///
    /// @return #la_status.
    la_status get_bottommost_block(logical_tcam_type_e logical_tcam, tcam_cell_location& out_location) const;

    /// @brief Get topmost block of a logical TCAM.
    ///
    /// @param[in]   logical_tcam                  Logical TCAM.
    /// @param[out]  out_location                  Location of found block.
    ///
    /// @return #la_status.
    la_status get_topmost_block(logical_tcam_type_e logical_tcam, tcam_cell_location& out_location) const;

    /// @brief Compare the content of a block group to a vector of blocks.
    ///
    /// @param[in]   location                      Location of block group.
    /// @param[in]   query                         Block types to compare to.
    ///
    /// @return whether block group contains blocks in query.
    bool is_block_group_equal_to(tcam_cell_location location, const vector_alloc<logical_tcam_type_e>& query) const;

    /// @brief Get number of cells in a block group.
    ///
    /// @param[in]   block_group                   Block group.
    ///
    /// @return Number of cells in block group.
    uint8_t get_num_cells_in_block_group(const vector_alloc<logical_tcam_type_e>& block_group) const;

    /// @brief Search for a location obeying given constraints, and if found, convert it into specified block group.
    ///
    /// @param[in]     current_owner                 Logical TCAM which we're going to steal blocks from.
    /// @param[in]     search_direction              Search order.
    /// @param[in]     region_to_search_in           Which region the block group should be currently in.
    /// @param[in]     convert_from_block_group      Current content of block group.
    /// @param[in]     convert_to_block_group        New content of block group.
    /// @param[in]     alignment                     Alignment requirement for searched block.
    /// @param[in]     release_blocks                How many blocks to report as freed.
    /// @param[in,out] free_blocks                   Free blocks in each logical TCAM.
    /// @param[out]    out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return Number of released blocks (0 if failed).
    size_t try_convert(logical_tcam_type_e current_owner,
                       search_direction_e search_direction,
                       tcam_region_e region_to_search_in,
                       const vector_alloc<logical_tcam_type_e>& convert_from_block_group,
                       const vector_alloc<logical_tcam_type_e>& convert_to_block_group,
                       size_t alignment,
                       size_t release_blocks,
                       free_blocks_array& free_blocks,
                       allocator_instruction_vec& out_instructions);

    /// @brief Convert (part of) a block group into new logical TCAM types.
    ///
    /// @param[in]     location                      Location of block group to convert.
    /// @param[in]     new_owners_list               New types to convert into.
    /// @param[in,out] free_blocks                   Free blocks in each logical TCAM.
    /// @param[out]    out_instructions              Instructions to perform on logical TCAMs.
    void convert_block_group(tcam_cell_location location,
                             const vector_alloc<logical_tcam_type_e>& new_owners_list,
                             free_blocks_array& free_blocks,
                             allocator_instruction_vec& out_instructions);

    // Properties
    uint32_t m_max_num_quad_blocks; ///< Maxium number of QUAD blocks.
};

} // namespace silicon_one

#endif // __LEABA_LPM_CORE_TCAM_ALLOCATOR_PACIFIC_GB_H__
