// BEGIN_LEGAL
//
// Copyright (c) 2019-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_LPM_CORE_TCAM_H__
#define __LEABA_LPM_CORE_TCAM_H__

#include "common/la_status.h"
#include "hw_tables/lpm_types.h"
#include "lpm_common.h"

#include "lpm/lpm_internal_types.h"
#include "lpm_core_tcam_allocator.h"
#include "lpm_core_tcam_utils_base.h"
#include "lpm_logical_tcam.h"

#include <string>

namespace silicon_one
{

class lpm_core_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static constexpr size_t CELL_WIDTH = 40; ///< Width of TCAM cell.

    /// @brief Struct containing key, payload, location of TCAM entry.
    struct lpm_core_tcam_entry {
        lpm_key_t key;               ///< Key.
        lpm_payload_t payload;       ///< Payload.
        tcam_cell_location location; ///< Cell location.
    };

    /// @brief Struct representing intstruction for hardware update.
    struct hardware_instruction {
        enum class type_e {
            INSERT,         ///< Insert a new TCAM entry.
            REMOVE,         ///< Remove an existing TCAM entry.
            MODIFY_PAYLOAD, ///< Modify the payload of an existing TCAM entry.
        };

        struct insert {
            lpm_key_t key;
            lpm_payload_t payload;
            tcam_cell_location location;
        };

        struct remove {
            lpm_key_t key;
            tcam_cell_location location;
        };

        struct modify_payload {
            lpm_key_t key;
            lpm_payload_t payload;
            tcam_cell_location location;
        };

        type_e instruction_type;
        boost::variant<boost::blank, insert, remove, modify_payload> instruction_data;
    };

    using hardware_instruction_vec = vector_alloc<hardware_instruction>;

    /// @brief Struct containing TCAM occupancy.
    struct lpm_core_tcam_occupancy {
        size_t num_single_entries = 0;
        size_t num_double_entries = 0;
        size_t num_quad_entries = 0;
        size_t empty_cells = 0;
        size_t occupied_cells = 0;
    };

    /// @brief Struct containing markers for withdraw.
    struct withdraw_stack_marker {
        size_t logical_tcam_marker[lpm_core_tcam_allocator::NUM_LOGICAL_TCAMS]; ///< Withdraw markers per logical TCAM.
        size_t tcam_allocator_marker;                                           ///< Withdraw marker for TCAM allocator.
    };

    /// @brief Destructor of LPM Core TCAM Object.
    virtual ~lpm_core_tcam();

    /// @name Update APIs
    /// @{

    /// @brief Insert a key/payload into core TCAM.
    ///
    /// @param[in]    key                   Key to insert.
    /// @param[in]    payload               Payload to attach to key.
    /// @param[out]   out_instructions      Resulting instructions to perform on hardware.
    ///
    /// @return #la_status.
    la_status insert(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions);

    /// @brief Remvoe a key from core TCAM.
    ///
    /// @param[in]    key                   Key to remove.
    /// @param[out]   out_instructions      Resulting instructions to perform on hardware.
    ///
    /// @return #la_status.
    la_status remove(const lpm_key_t& key, hardware_instruction_vec& out_instructions);

    /// @brief Modify a payload of a key in core TCAM.
    ///
    /// @param[in]    key                   Key to modify.
    /// @param[in]    payload               New payload to attach to key.
    /// @param[out]   out_instructions      Resulting instructions to perform on hardware.
    ///
    /// @return #la_status.
    la_status modify(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions);

    /// @brief Perform a list of updates on core TCAM.
    ///
    /// @param[in]    updates               Vector of updates.
    /// @param[out]   out_instructions      Resulting instructions to perform on hardware.
    ///
    /// @return #la_status.
    la_status update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions);

    /// @}

    /// @name Find/Lookup APIs.
    /// @{

    /// @brief Lookup a key in core TCAM by walking the TCAM tree.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_key          Hit key (key with longest prefix match).
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_hit_location     Hit location.
    ///
    /// @return #la_status.
    la_status lookup_tcam_tree(const lpm_key_t& key,
                               lpm_key_t& out_hit_key,
                               lpm_payload_t& out_hit_payload,
                               tcam_cell_location& out_hit_location) const;

    /// @brief Lookup a key in core TCAM by walking the TCAM table.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_key          Hit key (topmost key in table which gives a hit).
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_hit_location     Hit location.
    ///
    /// @return #la_status.
    la_status lookup_tcam_table(const lpm_key_t& key,
                                lpm_key_t& out_hit_key,
                                lpm_payload_t& out_hit_payload,
                                tcam_cell_location& out_hit_location) const;

    /// @}

    /// @brief Get total number of cells in core TCAM.
    ///
    /// @return Number of cells in core TCAM.
    size_t get_num_cells() const;

    /// @brief Get number of banksets in core TCAM.
    ///
    /// @return Number of banksets in core TCAM.
    size_t get_num_banksets() const;

    /// @brief Get max number of QUAD entries in core TCAM.
    ///
    /// @return Max number of QUAD entries in core TCAM.
    size_t get_max_quad_entries() const;

    /// @brief Get occupancy of core TCAM.
    ///
    /// @return Occupancy.
    lpm_core_tcam_occupancy get_occupancy() const;

    /// @brief Get a reference to an internal logical TCAM object.
    ///
    /// @note Use only for testing/debug.
    ///
    /// @param[in]        logical_tcam         Logical TCAM to return.
    ///
    /// @return a reference to internal logical TCAM.
    const lpm_logical_tcam& get_logical_tcam(logical_tcam_type_e logical_tcam) const;

    /// @brief Get a reference to internal TCAM allocator object.
    ///
    /// @note Use only for testing/debug.
    ///
    /// @return a reference to internal TCAM allocator.
    const lpm_core_tcam_allocator& get_core_tcam_allocator() const;

    /// @name Commit/Withdraw API.
    /// @{

    /// @brief Commit previous updates.
    /// The changes cannot be withdrawn after calling this function.
    void commit();

    /// @brief Push a marker to withdraw stack.
    /// Marker is a special entry in the withdraw stack which allows to withdraw all entries upto it.
    ///
    /// @return Marker ID.
    withdraw_stack_marker push_marker_to_withdraw_stack();

    /// @brief Withdraw previous updates which haven't been comitted yet and return core TCAM to its previous state.
    void withdraw();

    /// @brief Withdraw previous updates upto marker with given marker ID.
    ///
    /// @param[in]      marker_id           Marker ID to stop at.
    void withdraw_upto_marker(const withdraw_stack_marker& marker_id);

    /// @}

    /// @brief Return key/payload/location of valid entries in TCAM.
    ///
    /// @return Entries in TCAM.
    vector_alloc<lpm_core_tcam_entry> get_entries() const;

    /// @brief Perform sanity checks on TCAM.
    ///
    /// @return Whether sanity checks passed.
    bool sanity() const;

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_core_tcam() = default;

    /// @brief Construct a LPM Core TCAM object.
    ///
    /// @param[in]    name                          Name of core TCAM.
    /// @param[in]    num_banksets                  Number of banksets in TCAM.
    /// @param[in]    num_cells_per_bank            Number of cells in each bank.
    /// @param[in]    num_quad_blocks               Number of quad blocks.
    /// @param[in]    core_tcam_utils               Pointer to TCAM utils object.
    lpm_core_tcam(std::string name,
                  size_t num_banksets,
                  size_t num_cells_per_bank,
                  size_t num_quad_blocks,
                  const lpm_core_tcam_utils_scptr& core_tcam_utils);

    /// @brief Perform a TCAM allocator instruction (block/unblock) on the relevant logical TCAM.
    ///
    /// @param[in]     instruction                           TCAM allocator instruction.
    /// @param[out]    out_instructions                      Resulting instructions to perform on hardware.
    ///
    /// @return #la_status.
    la_status perform_allocator_instruction(const lpm_core_tcam_allocator::allocator_instruction& logical_instruction,
                                            hardware_instruction_vec& out_instructions);

    /// @brief Translate the row numbers in a list of TCAM instructions from logical to physical.
    ///
    /// @param[in]      logical_instructions                  Instruction to translate.
    /// @param[out]     out_hardware_instructions             Hardware instructions.
    void translate_logical_to_physical_tcam_instructions(const lpm_logical_tcam::logical_instruction_vec& logical_instructions,
                                                         hardware_instruction_vec& out_hardware_instructions) const;

    /// @brief Find a valid node with given key.
    /// @note The returned node should not be used to traverse the core TCAM's
    /// tree, as the core TCAM is composed of multiple trees rather than one.
    ///
    /// @param[in]      key                  Key to find.
    ///
    /// @return node with given key, or nullptr if not found.
    const lpm_logical_tcam_tree_node* find(const lpm_key_t& key) const;

    // Properties
    std::string m_name;                          ///< TCAM allocator's name.
    size_t m_num_banksets;                       ///< Number of banksets in TCAM.
    lpm_core_tcam_utils_wcptr m_core_tcam_utils; ///< TCAM utils object.

    // Core data structures
    vector_alloc<lpm_logical_tcam> m_logical_tcams; ///< Vector containing logical TCAMs.
    lpm_core_tcam_allocator_sptr m_tcam_allocator;  ///< TCAM allocator.
};

} // namespace silicon_one

#endif
