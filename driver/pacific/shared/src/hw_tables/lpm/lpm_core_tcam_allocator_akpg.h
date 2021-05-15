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

#ifndef __LEABA_LPM_CORE_TCAM_ALLOCATOR_AKPG_H__
#define __LEABA_LPM_CORE_TCAM_ALLOCATOR_AKPG_H__

#include "lpm_core_tcam_allocator.h"

namespace silicon_one
{

class lpm_core_tcam_allocator_akpg : public lpm_core_tcam_allocator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @name Resource construction and initialization
    /// @{

    /// @brief Construct a LPM TCAM allocator object.
    ///
    /// @param[in]     name                          Name of TCAM allocator.
    /// @param[in]     num_banksets                  Number of banksets.
    /// @param[in]     num_cells_per_bank            Number of cells in each bank.
    lpm_core_tcam_allocator_akpg(std::string name, uint8_t num_banksets, uint32_t num_cells_per_bank);

    /// @}

    // lpm core tcam allocator API-s
    la_status make_space(logical_tcam_type_e logical_tcam,
                         const free_blocks_array& free_blocks,
                         allocator_instruction_vec& out_instructions) override;
    size_t get_max_quad_blocks() const override;

protected:
    /// @brief Default c'tor - shouldn't be used, allowed only for serialization purposes.
    lpm_core_tcam_allocator_akpg() = default;

    // lpm core tcam allocator virtual functions
    void block_last_blocks(allocator_instruction_vec& out_instructions) override;

private:
    /// @brief Make space for a logical TCAM.
    ///
    /// @param[in]     dst_logical_tcam              Logical TCAM that needs space.
    /// @param[in]     free_blocks                   Free blocks in each logical TCAM.
    /// @param[out]    out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return #la_status.
    la_status make_space_for_a_block(logical_tcam_type_e dst_logical_tcam,
                                     free_blocks_array& free_blocks,
                                     allocator_instruction_vec& out_instructions);

    /// @brief Try to find a block with required alignment to convert.
    ///
    /// @param[in]     owner_logical_tcam            Current owner of blocks which are checked to get one with correct aligment.
    /// @param[in]     dst_logical_tcam              Logical TCAM which needs space.
    /// @param[in]     free_blocks                   Free blocks in each logical TCAM.
    /// @param[in]     alignment                     Alignment requirement for searched block.
    /// @param[out]    out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return #la_status.
    la_status try_convert(logical_tcam_type_e owner_logical_tcam,
                          const logical_tcam_type_e& dst_logical_tcam,
                          free_blocks_array& free_blocks,
                          size_t alignment,
                          allocator_instruction_vec& out_instructions);

    /// @brief Convert block group starting from location to the new owner.
    ///
    /// @param[in]      location                      Location of a block group.
    /// @param[in]      new_owner                     New owner of block.
    /// @param[in,out]  free_blocks                   Free blocks in each logical TCAM.
    /// @param[out]     out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return #la_status.
    la_status convert_block_group(const tcam_cell_location& location,
                                  logical_tcam_type_e new_owner,
                                  free_blocks_array& free_blocks,
                                  allocator_instruction_vec& out_instructions);

    // Data member
    size_t m_last_portable_line; ///< Last line in TCAM that can be used for converting between owners.
};

} // namespace silicon_one

#endif // __LEABA_LPM_CORE_TCAM_ALLOCATOR_AKPG_H__
