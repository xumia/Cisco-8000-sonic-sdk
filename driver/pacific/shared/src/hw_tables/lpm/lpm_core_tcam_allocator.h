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

#ifndef __LEABA_LPM_CORE_TCAM_ALLOCATOR_H__
#define __LEABA_LPM_CORE_TCAM_ALLOCATOR_H__

#include "common/la_status.h"
#include "hw_tables/lpm_types.h"
#include "lpm_common.h"

#include "lpm/lpm_internal_types.h"

#include <sstream>
#include <string>

#include <boost/functional/hash.hpp>
#include <boost/variant.hpp>

namespace silicon_one
{

///@brief Struct describing the location of a TCAM cell.
struct tcam_cell_location {
    uint8_t bankset; ///< Bankset.
    uint8_t bank;    ///< Bank.
    uint32_t cell;   ///< Cell.

    bool operator==(const tcam_cell_location& other) const
    {
        return (bankset == other.bankset) && (bank == other.bank) && (cell == other.cell);
    }

    std::string to_string() const
    {
        std::stringstream sstream;
        sstream << "bankset=" << std::to_string(bankset) << "  bank=" << std::to_string(bank) << "  cell=" << std::to_string(cell);
        return sstream.str();
    }
};

class lpm_core_tcam_allocator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // Terminology:
    // - Cell: An entry of a single bank.
    // - Block: A slot for a logical entry, composed of one or more cells in different banks.
    // - Block group: Any number of neighboring cells.
    // - Full Block group: 4 neighboring cells (each in a different bank).
    //     Can host e.g 1 QUAD block, 2 DOUBLE blocks, 1 DOUBLE and 2 SINGLE blocks, 4 SINGLE blocks, etc..
    // - Logical Row: Meaningless unless given in the context of a specific Logical TCAM. It is the row number as viewed by a
    // logical TCAM.
    //
    // - We describe the location of a block/block group by specifying the location of their leftmost cell.
    //
    // - We will avoid using the generic term "row" as it can be confusing to which one of the above we are referring.

    static constexpr size_t NUM_BANKS_PER_BANKSET = 4; ///< Number of banks in each bankset.
    static constexpr size_t NUM_LOGICAL_TCAMS = 3;

    /// @brief Instruction from allocator to logical TCAMs
    struct allocator_instruction {

        /// @brief Type of instruction.
        enum class instruction_type_e {
            BLOCK,               ///< Block a logical row.
            BLOCK_ALL_FREE_ROWS, ///< Block all free rows.
            UNBLOCK              ///< Unblock a logical row.
        };

        struct block {
            logical_tcam_type_e logical_tcam;
            size_t logical_row;
        };

        struct block_all_free_rows {
            logical_tcam_type_e logical_tcam;
        };

        struct unblock {
            logical_tcam_type_e logical_tcam;
            size_t logical_row;
        };

        instruction_type_e instruction_type;
        boost::variant<block, block_all_free_rows, unblock> instruction_data;
    };

    using allocator_instruction_vec = vector_alloc<allocator_instruction>;
    using free_blocks_array = std::array<size_t, NUM_LOGICAL_TCAMS>;

    /// @name Resource destruction
    /// @{

    /// @brief Destructor of LPM TCAM allocator object.
    virtual ~lpm_core_tcam_allocator();

    /// @}

    /// @name Resource initialization
    /// @{

    /// @brief Initialize LPM TCAM allocator object.
    ///
    /// @param[in]     block_last_block_group        Whether to block the last blocks for default entries and never use it.
    /// @param[out]    out_instruction               Instruction to perform on logical TCAMs.
    void initialize(bool block_last_block_group, allocator_instruction_vec& out_instructions);

    /// @}

    /// @name Main APIs
    /// @{

    /// @brief Make a space for a single block in a logical TCAM.
    /// Will immediately return if space is already available.
    ///
    /// @param[in]     logical_tcam                  Logical TCAM to make space for.
    /// @param[in]     free_blocks                   Free blocks in each logical TCAM.
    /// @param[out]    out_instructions              Instructions to perform on logical TCAMs.
    ///
    /// @return #la_status.
    virtual la_status make_space(logical_tcam_type_e logical_tcam,
                                 const free_blocks_array& free_blocks,
                                 allocator_instruction_vec& out_instructions)
        = 0;

    /// @}

    /// @name Commit/Withdraw API.
    /// @{

    /// @brief Commit previous updates. They cannot be withdrawn after calling this function.
    void commit();

    /// @brief Push a marker to withdraw stack.
    /// Marker is a special entry in the withdraw stack which allows to withdraw all entries upto it.
    ///
    /// @return Marker ID.
    size_t push_marker_to_withdraw_stack();

    /// @brief Withdraw previous updates which haven't been comitted yet and return TCAM allocator to its previous state.
    void withdraw();

    /// @brief Withdraw previous updates upto marker with given marker ID.
    ///
    /// @param[in]      marker_id           Marker ID to stop at.
    void withdraw_upto_marker(size_t marker_id);

    /// @}

    /// @name Translation services
    /// @{

    /// @brief Translate a TCAM location to a logical row of a given TCAM.
    ///
    /// @param[in]     logical_tcam                   Logical TCAM to translate for.
    /// @param[in]     location                       Location to translate.
    ///
    /// @return Logical row.
    size_t translate_location_to_logical_row(logical_tcam_type_e logical_tcam, tcam_cell_location location) const;

    /// @brief Translate a logical row to a TCAM location.
    ///
    /// @param[in]     logical_tcam                   Logical TCAM to translate from.
    /// @param[in]     logical_row                    Logical row to translate.
    ///
    /// @return TCAM location.
    tcam_cell_location translate_logical_row_to_location(logical_tcam_type_e logical_tcam, size_t logical_row) const;

    /// @}

    /// @brief Get logical TCAM which owns a block at given location.
    ///
    /// @param[in]     location                        Location of block.
    ///
    /// @return Owner of block.
    logical_tcam_type_e get_owner_of_location(tcam_cell_location location) const;

    /// @brief Convert logical TCAM enum to string.
    ///
    /// @param[in]     logical_tcam                    Logical TCAM.
    ///
    /// @return String of logical TCAM type.
    std::string logical_tcam_to_string(logical_tcam_type_e logical_tcam) const;

    /// @brief Get the max QUAD blocks that can be allocated.
    ///
    /// @return Max number of QUAD blocks.
    virtual size_t get_max_quad_blocks() const = 0;

    /// @brief Perform sanity checks on allocator.
    ///
    /// @return Whether sanity checks passed.
    bool sanity() const;

    /// @brief less operator for tcam_cell_location. Used to create set of tcam_cell_location
    struct tcam_cell_location_less_operator {
        bool operator()(const tcam_cell_location& llocation, const tcam_cell_location& rlocation) const
        {
            if (llocation.bankset != rlocation.bankset) {
                return llocation.bankset < rlocation.bankset;
            }

            if (llocation.bank != rlocation.bank) {
                return llocation.bank < rlocation.bank;
            }

            return llocation.cell < rlocation.cell;
        }
    };

protected:
    /// @brief Hash of tcam_cell_location. Used for unordered_map.
    struct tcam_cell_location_hash_function {
        size_t operator()(const tcam_cell_location& location) const
        {
            size_t seed = 0;
            boost::hash_combine(seed, location.bankset);
            boost::hash_combine(seed, location.bank);
            boost::hash_combine(seed, location.cell);
            return seed;
        }
    };

    using tcam_cell_locations_set = set_alloc<tcam_cell_location, tcam_cell_location_less_operator>;

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_core_tcam_allocator() = default;

    /// @brief Construct a LPM TCAM allocator object.
    ///
    /// @param[in]     name                          Name of TCAM allocator.
    /// @param[in]     num_banksets                  Number of banksets.
    /// @param[in]     num_cells_per_bank            Number of cells in each bank.
    lpm_core_tcam_allocator(std::string name, uint8_t num_banksets, uint32_t num_cells_per_bank);

    /// @brief Block last TCAM blocks for default entries and never use it.
    ///
    /// @param[out]   out_instructions             Instructions to perform on logical TCAMs..
    virtual void block_last_blocks(allocator_instruction_vec& out_instructions) = 0;

    /// @name Atoms: only operations which are allowed to directly modify the TCAM's data structures.
    /// @{

    /// @brief Give up ownership of a location.
    ///
    /// @param[in]   current_owner                Logical TCAM which will give up location.
    /// @param[in]   location                     Location to give up.
    /// @param[in]   update_withdraw_stack        Save action in withdraw stack to allow withdraw later.
    void atom_give_up_ownership_of_location(logical_tcam_type_e current_owner,
                                            tcam_cell_location location,
                                            bool update_withdraw_stack);

    /// @brief Take ownership of a location.
    ///
    /// @param[in]   new_owner                    Logical TCAM which will take location.
    /// @param[in]   location                     Location to take.
    /// @param[in]   update_withdraw_stack        Save action in withdraw stack to allow withdraw later.
    void atom_take_ownership_of_location(logical_tcam_type_e new_owner, tcam_cell_location location, bool update_withdraw_stack);

    /// @}

    /// @brief Convert logical TCAM vector to string.
    ///
    /// @param[in]     logical_tcam_vector             Logical TCAM Vector.
    ///
    /// @return String of logical TCAM types in vector.
    std::string logical_tcam_vector_to_string(const vector_alloc<logical_tcam_type_e>& logical_tcam_vector) const;

    // Properties
    std::string m_name;            ///< TCAM allocator's name.
    uint8_t m_num_banksets;        ///< Number of banksets.
    uint32_t m_num_cells_per_bank; ///< Number of cells per bank.

    // Core data structure
    tcam_cell_locations_set m_owned_blocks[NUM_LOGICAL_TCAMS + 1]; ///< Owned blocks of each logical TCAM (including NOBODY).
    unordered_map_alloc<tcam_cell_location, logical_tcam_type_e, tcam_cell_location_hash_function>
        m_owner_of_block; ///< Owner of each block.

private:
    /// @brief Struct describing a withdraw stack entry.
    struct withdraw_action {

        /// @brief type of withdraw action.
        enum class withdraw_action_type_e {
            WITHDRAW_GIVE_UP_OWNERSHIP, ///< Withdraw a give up ownership operation.
            WITHDRAW_TAKE_OWNERSHIP,    ///< Withdraw a take ownership operation.
            MARKER,                     ///< A Marker entry with a unique ID.
        };

        struct withdraw_give_up_ownership {
            tcam_cell_location location;
            logical_tcam_type_e logical_tcam;
        };

        struct withdraw_take_ownership {
            tcam_cell_location location;
            logical_tcam_type_e logical_tcam;
        };

        struct marker {
            size_t marker_id;
        };

        withdraw_action_type_e action_type;
        boost::variant<boost::blank, withdraw_give_up_ownership, withdraw_take_ownership, marker> action_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_give_up_ownership)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_take_ownership)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::marker)

    /// @brief Withdraw a single action.
    ///
    /// @param[in]   waction                      Action to withdraw.
    void withdraw_one_action(const withdraw_action& waction);

    // Withdraw
    vector_alloc<withdraw_action> m_withdraw_stack; ///< Withdraw stack.
    size_t m_withdraw_stack_marker_id;              ///< Withdraw stack marker ID.
};

} // namespace silicon_one

#endif // __LEABA_LPM_CORE_TCAM_ALLOCATOR_H__
