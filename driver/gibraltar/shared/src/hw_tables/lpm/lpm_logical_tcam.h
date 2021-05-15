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

#ifndef __LEABA_LPM_LOGICAL_TCAM_H__
#define __LEABA_LPM_LOGICAL_TCAM_H__

#include "common/la_status.h"
#include "hw_tables/lpm_types.h"
#include "lpm_common.h"

#include "lpm/lpm_internal_types.h"

#include "binary_lpm_tree.h"

#include <boost/variant.hpp>

namespace silicon_one
{

/// @brief TCAM tree data.
struct lpm_logical_tcam_tree_data {
    size_t row = LPM_NULL_ROW;
};

class lpm_logical_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    struct logical_instruction {
        enum class type_e {
            INSERT,         ///< Insert a new TCAM entry.
            REMOVE,         ///< Remove an existing TCAM entry.
            MODIFY_PAYLOAD, ///< Modify the payload of an existing TCAM entry.
        };

        type_e instruction_type;

        lpm_key_t key;
        lpm_payload_t payload;
        size_t row;
    };

    using logical_instruction_vec = vector_alloc<logical_instruction>;

    /// @brief Construct a LPM logical TCAM object.
    ///
    /// @param[in]     name                 Name of TCAM.
    /// @param[in]     num_rows             Number of TCAM rows.
    lpm_logical_tcam(std::string name, size_t num_rows);

    /// @brief Default c'tor - shouldn't be used, allowed only for serialization purposes.
    lpm_logical_tcam() = default;

    /// @brief Destructor of LPM logical TCAM.
    ~lpm_logical_tcam();

    /// @name Update APIs.
    /// @{

    /// @brief Insert a new key/payload to TCAM.
    ///
    /// @param[in]      key                  Key to insert.
    /// @param[in]      payload              Payload to insert.
    /// @param[out]     out_instructions     Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    la_status insert(const lpm_key_t& key, lpm_payload_t payload, logical_instruction_vec& out_instructions);

    /// @brief Remove a key from TCAM.
    ///
    /// @param[in]      key                  Key to remove.
    /// @param[out]     out_instructions     Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    la_status remove(const lpm_key_t& key, logical_instruction_vec& out_instructions);

    /// @brief Modify the payload of an existing key in TCAM.
    ///
    /// @param[in]      key                  Key which its payload we want to modify.
    /// @param[in]      payload              Payload to modify.
    /// @param[out]     out_instructions     Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    la_status modify(const lpm_key_t& key, lpm_payload_t payload, logical_instruction_vec& out_instructions);

    /// @brief Block a row in TCAM to prevent TCAM from using it. If already used, relocate its contents first.
    ///
    /// @param[in]      row                  Row to block
    /// @param[out]     out_instructions     Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    la_status block(size_t row, logical_instruction_vec& out_instructions);

    /// @brief Block all free rows.
    void block_all_free_rows();

    /// @brief Unblock a blocked row in TCAM to allow TCAM to use it again.
    ///
    /// @param[in]      row                  Row to block
    ///
    /// @return #la_status.
    la_status unblock(size_t row);

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

    /// @brief Withdraw previous updates which haven't been comitted yet and return TCAM object to its previous state.
    void withdraw();

    /// @brief Withdraw previous updates upto marker with given marker ID.
    ///
    /// @param[in]      marker_id           Marker ID to stop at.
    void withdraw_upto_marker(size_t marker_id);

    /// @}

    /// @name Find/Lookup APIs.
    /// @{

    /// @brief Lookup a key in TCAM by walking the TCAM tree.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_key          Hit key (key with longest prefix match).
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_hit_row          Hit row.
    ///
    /// @return #la_status.
    la_status lookup_tcam_tree(const lpm_key_t& key,
                               lpm_key_t& out_hit_key,
                               lpm_payload_t& out_hit_payload,
                               size_t& out_hit_row) const;

    /// @brief Lookup a key in TCAM by walking the TCAM table.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_key          Hit key (topmost key in table which gives a hit).
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_hit_row          Hit row.
    ///
    /// @return #la_status.
    la_status lookup_tcam_table(const lpm_key_t& key,
                                lpm_key_t& out_hit_key,
                                lpm_payload_t& out_hit_payload,
                                size_t& out_hit_row) const;

    /// @brief Find a valid node with given key.
    ///
    /// @param[in]      key                  Key to find.
    ///
    /// @return node with given key, or nullptr if not found.
    const lpm_logical_tcam_tree_node* find(const lpm_key_t& key) const;

    /// @}

    /// @name Getters of TCAM's content.
    /// @{

    /// @brief Get root node of TCAM tree.
    ///
    /// @return TCAM's root node.
    const lpm_logical_tcam_tree_node* get_root_node() const;

    /// @brief Get payload associated with a TCAM tree node.
    ///
    /// @param[in]        node                 Node to retreive its payload.
    /// @param[out]       out_payload          Payload of node.
    ///
    /// @return #la_status.
    la_status get_payload_of_node(const lpm_logical_tcam_tree_node* node, lpm_payload_t& out_payload) const;

    /// @brief Get entry at given row.
    ///
    /// @param[in]        row                  Row to read.
    /// @param[out]       out_key_payload      Key/payload
    ///
    /// @return #la_status.
    la_status get_entry(size_t row, lpm_key_payload& out_key_payload) const;

    /// @brief Get all valid entries in TCAM.
    ///
    /// @return vector of key,payload,row of valid TCAM entries.
    vector_alloc<lpm_key_payload_row> get_entries() const;

    /// @}

    /// @name Occupancy APIs.
    /// @{

    /// @brief Get number of occupied rows in TCAM.
    ///
    /// @return Number of occupied rows.
    size_t get_num_occupied_rows() const;

    /// @brief Get number of free rows in TCAM.
    ///
    /// @return Number of free rows.
    size_t get_num_free_rows() const;

    /// @brief Get total number of rows in TCAM.
    ///
    /// @return Total number of rows.
    size_t get_total_num_of_rows() const;

    /// @}

    /// @brief Save current tcam's state.
    ///
    /// @return Json representation of tcam.
    json_t* save_state() const;

    /// @brief Load tcam's state.
    ///
    /// @param[in]     json_tcam          Json object of the tcam.
    /// @param[out]    out_instructions   Instructions to pass to next stage to reflect the logical update.
    void load_state(json_t* json_tcam, lpm_logical_tcam::logical_instruction_vec& out_instructions);

    /// @brief Reset tcam's state.
    ///
    /// @param[out]     out_instructions   Instructions to pass to next stage to reflect the logical update.
    void reset_state(logical_instruction_vec& out_instructions);

    /// @brief Utility to check integrity of internal data structures.
    bool sanity() const;

private:
    /// @brief TCAM's entry descriptor
    struct table_entry {

        /// @brief State of TCAM entry.
        enum class table_entry_state_e {
            FREE,     ///< Entry is free.
            OCCUPIED, ///< Entry is occupied.
            BLOCKED,  ///< Entry is blocked.
        };

        table_entry_state_e state = table_entry_state_e::FREE;
        lpm_key_t key;
        lpm_payload_t payload;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(table_entry)

    ///@brief Struct describing a withdraw stack entry.
    struct withdraw_action {

        ///@brief type of withdraw action.
        enum class withdraw_action_type_e {
            WITHDRAW_TABLE_INSERT,         ///< Withdraw a table insert operation.
            WITHDRAW_TABLE_REMOVE,         ///< Withdraw a table remove operation.
            WITHDRAW_TABLE_MODIFY_PAYLOAD, ///< Withdraw a table modify payload operation.
            WITHDRAW_TABLE_UNBLOCK,        ///< Withdraw a table unblock operation.
            WITHDRAW_TABLE_BLOCK,          ///< Withdraw a table block operation.
            WITHDRAW_TREE_INSERT,          ///< Withdraw a tree insert operation.
            WITHDRAW_TREE_REMOVE,          ///< Withdraw a tree remove operation.
            WITHDRAW_TREE_MODIFY_ROW,      ///< Withdraw a tree modify row operation.
            MARKER,                        ///< A Marker entry with a unique ID.
        };

        struct withdraw_table_insert {
            size_t row;
        };

        struct withdraw_table_remove {
            size_t row;
            lpm_key_t key;
            lpm_payload_t payload;
        };

        struct withdraw_table_modify_payload {
            size_t row;
            lpm_payload_t payload;
        };

        struct withdraw_table_unblock {
            size_t row;
        };

        struct withdraw_table_block {
            size_t row;
        };

        struct withdraw_tree_insert {
            lpm_key_t key;
        };

        struct withdraw_tree_remove {
            size_t row;
            lpm_key_t key;
        };

        struct withdraw_tree_modify_row {
            lpm_key_t key;
            size_t row;
        };

        struct marker {
            size_t marker_id;
        };

        withdraw_action_type_e action_type;
        boost::variant<boost::blank,
                       withdraw_table_insert,
                       withdraw_table_remove,
                       withdraw_table_modify_payload,
                       withdraw_table_unblock,
                       withdraw_table_block,
                       withdraw_tree_insert,
                       withdraw_tree_remove,
                       withdraw_tree_modify_row,
                       marker>
            action_data;
    };

    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_table_insert)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_table_remove)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_table_modify_payload)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_table_unblock)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_table_block)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_tree_insert)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_tree_remove)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::withdraw_tree_modify_row)
    CEREAL_SUPPORT_PRIVATE_CLASS(withdraw_action::marker)

    /// @name Row relocation helper functions.
    /// @{

    /// @brief Make a row empty by efficiently pushing TCAM rows toward a given row while keeping the tree order of the keys.
    ///
    /// @param[in]        src_row              Row to vacant.
    /// @param[in]        dst_row              Empty row to push rows towards.
    /// @param[out]       out_instructions     Instructions to pass to next stage to reflect the logical update.
    void push_rows(size_t src_row, size_t dst_row, logical_instruction_vec& out_instructions);

    /// @brief Make a row empty by efficiently pulling TCAM rows toward a given row while keeping the tree order of the keys.
    ///
    /// @param[in]        src_row              Row to vacant.
    /// @param[in]        dst_row              Empty row to pull rows towards.
    /// @param[out]       out_instructions     Instructions to pass to next stage to reflect the logical update.
    void pull_rows(size_t src_row, size_t dst_row, logical_instruction_vec& out_instructions);

    /// @brief Vacant a node's row by efficiently pushing TCAM rows toward a given row while keeping the tree order of the keys.
    ///
    /// @param[in]        src_node             Node to relocate.
    /// @param[in]        dst_row              Empty row to push rows towards.
    /// @param[out]       out_instructions     Instructions to pass to next stage to reflect the logical update.
    void push_rows(const lpm_logical_tcam_tree_node* src_node, size_t dst_row, logical_instruction_vec& out_instructions);

    /// @brief Vacant a node's row by efficiently pulling TCAM rows toward a given row while keeping the tree order of the keys.
    ///
    /// @param[in]        src_node             Node to relocate.
    /// @param[in]        dst_row              Empty row to pull rows towards.
    /// @param[out]       out_instructions     Instructions to pass to next stage to reflect the logical update.
    void pull_rows(const lpm_logical_tcam_tree_node* src_node, size_t dst_row, logical_instruction_vec& out_instructions);

    /// @brief Move entry in given row to another free row.
    ///
    /// @param[in]        src_row              Row which its content we want to move.
    /// @param[in]        dst_row              New place of entry.
    /// @param[out]       out_instructions     Instructions to pass to next stage to reflect the logical update.
    void move_row(size_t src_row, size_t dst_row, logical_instruction_vec& out_instructions);

    /// @}

    /// @name Find/Lookup/Walk helpers
    /// @{

    ///@brief Get closest ancestor node which is valid.
    ///
    /// @param[in]        node                 Node to find ancestor of.
    ///
    ///@return Closest valid ancestor of node.
    lpm_logical_tcam_tree_node* get_closest_valid_ancestor(const lpm_logical_tcam_tree_node* node);

    ///@brief Get child which has the largest row number (bottommost in TCAM table).
    ///
    /// @param[in]        node                 Node to start search from (exclusive).
    ///
    ///@return Child with largest row number.
    const lpm_logical_tcam_tree_node* get_child_with_largest_row_number(const lpm_logical_tcam_tree_node* node);

    /// @}

    /// @name Atoms: only operations which are allowed to directly modify the TCAM's data structures.
    /// @{

    /// @brief Insert a key/payload to the TCAM table in a given row.
    ///
    /// @param[in]        row                      Row to insert key to.
    /// @param[in]        key                      Key to insert.
    /// @param[in]        payload                  Payload to insert.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    /// @param[out]       out_instructions         Instructions to pass to next stage to reflect the logical update.
    void atom_table_insert(size_t row,
                           const lpm_key_t& key,
                           lpm_payload_t payload,
                           bool update_withdraw_stack,
                           logical_instruction_vec& out_instructions);

    /// @brief Remove content of row from TCAM table.
    ///
    /// @param[in]        row                      Row to remove.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    /// @param[out]       out_instructions         Instructions to pass to next stage to reflect the logical update.
    void atom_table_remove(size_t row, bool update_withdraw_stack, logical_instruction_vec& out_instructions);

    /// @brief Modify payload of given TCAM row.
    ///
    /// @param[in]        row                      Row to modify.
    /// @param[in]        payload                  New payload.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    /// @param[out]       out_instructions         Instructions to pass to next stage to reflect the logical update.
    void atom_table_modify_payload(size_t row,
                                   lpm_payload_t payload,
                                   bool update_withdraw_stack,
                                   logical_instruction_vec& out_instructions);

    /// @brief Mark a TCAM row as unblocked (free).
    ///
    /// @param[in]        row                      Row to unblock.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    void atom_table_unblock_row(size_t row, bool update_withdraw_stack);

    /// @brief Mark a TCAM row as blocked.
    ///
    /// @param[in]        row                      Row to block.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    void atom_table_block_row(size_t row, bool update_withdraw_stack);

    /// @brief Insert a Key to the tree.
    ///
    /// @param[in]        key                      Key to insert.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    /// @param[out]       out_node                 Inserted node.
    ///
    /// @return #la_status.
    la_status atom_tree_insert(const lpm_key_t& key, bool update_withdraw_stack, lpm_logical_tcam_tree_node*& out_node);

    /// @brief Remove a node from the tree.
    ///
    /// @param[in]        node                     Node to remove.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    ///
    /// @return #la_status.
    la_status atom_tree_remove(lpm_logical_tcam_tree_node* node, bool update_withdraw_stack);

    /// @brief Modify the row associated with a node in the tree.
    ///
    /// @param[in]        node                     Node to modify.
    /// @param[in]        row                      Row to set.
    /// @param[in]        update_withdraw_stack    Save action in withdraw stack to allow withdraw later.
    void atom_tree_modify_row(lpm_logical_tcam_tree_node* node, size_t row, bool update_withdraw_stack);

    /// @}

    /// @name Withdraw helpers.
    /// @{

    /// @brief Withdraw a single action.
    ///
    /// @param[in]        waction              Action to withdraw.
    void withdraw_one_action(const withdraw_action& waction);

    /// @brief Insert key and group at given row.
    ///
    /// @param[in]      key                Key to insert.
    /// @param[in]      payload            Payload for the key.
    /// @param[in]      row                Row to write.
    /// @param[out]     out_instructions   Instructions to pass to next stage to reflect the logical update.
    void insert_and_enforce_line(const lpm_key_t& key,
                                 lpm_payload_t payload,
                                 size_t row,
                                 logical_instruction_vec& out_instructions);
    /// @}

    /// @brief Find a free row in a given range (exclusive).
    ///
    /// @param[in]        lower_bound          Lower bound of search (ignored if set to LPM_NULL_ROW).
    /// @param[in]        upper_bound          Upper bound of search (ignored if set to LPM_NULL_ROW).
    ///
    /// @return A free row in the given range.
    size_t find_free_row_in_range_exclusive(size_t lower_bound, size_t upper_bound) const;

    // Properties
    std::string m_name; ///< TCAM's name.

    // Core data structures
    vector_alloc<table_entry> m_table;                         ///< TCAM table.
    set_alloc<size_t> m_free_rows;                             ///< Free rows.
    size_t m_num_occupied_rows;                                ///< Total number of occupied rows.
    binary_lpm_tree<lpm_logical_tcam_tree_data> m_binary_tree; ///< Binary TCAM tree.

    // Withdraw
    vector_alloc<withdraw_action> m_withdraw_stack; ///< Withdraw stack.
    size_t m_withdraw_stack_marker_id;              ///< Withdraw stack marker ID.
};

} // namespace silicon_one

#endif
