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

#ifndef __LEABA_LPM_DISTRIBUTOR_H__
#define __LEABA_LPM_DISTRIBUTOR_H__

#if __GNUC__ == 7 && __GNUC_MINOR__ == 5
#define GCC_7_5
#endif

#include "common/la_status.h"
#include "lpm_internal_types.h"
#include "lpm_logical_tcam.h"

#ifdef GCC_7_5
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wmaybe-uninitialized"
#endif

#include <boost/variant.hpp>
#include <sstream>

namespace silicon_one
{

///@brief Struct describing the location of a distributor cell.
struct distributor_cell_location {
    uint8_t bank; ///< Bank id.
    size_t cell;  ///< Cell inside the bank.

    bool operator==(const distributor_cell_location& other) const
    {
        return (bank == other.bank) && (cell == other.cell);
    }

    std::string to_string() const
    {
        std::stringstream sstream;
        sstream << "bank=" << std::to_string(bank) << "  cell=" << std::to_string(cell);
        return sstream.str();
    }
};

///@brief Struct describing key, payload, location of distributor entry.
struct lpm_key_payload_location {
    lpm_key_t key;                      ///< Key.
    lpm_payload_t payload;              ///< Payload
    distributor_cell_location location; ///< Cell location.
};

class lpm_distributor
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static constexpr const char* JSON_IPV4_TCAM = "ipv4_tcam";
    static constexpr const char* JSON_IPV6_TCAM = "ipv6_tcam";

    ///@brief Struct describing the distributor hardware instruction.
    struct distributor_hw_instruction {

        enum class type_e {
            INSERT,               ///< Insert a new distributor entry.
            REMOVE,               ///< Remove an existing distributor entry.
            MODIFY_PAYLOAD,       ///< Modify the payload of an existing distributor entry.
            UPDATE_GROUP_TO_CORE, ///< Update group to core hardware map (relevant for Pacific/GB).
            EMPTY                 ///< used in the visitor for boost::blank
        };

        struct insert_data {
            lpm_key_t key;
            lpm_payload_t payload;
            distributor_cell_location location;
        };

        struct remove_data {
            lpm_key_t key;
            distributor_cell_location location;
        };

        struct modify_payload_data {
            lpm_key_t key;
            lpm_payload_t payload;
            distributor_cell_location location;
        };

        struct update_group_to_core_data {
            size_t group_id;
            size_t core_id;
        };

        boost::variant<boost::blank, insert_data, remove_data, modify_payload_data, update_group_to_core_data> instruction_data;
    };

    class visitor_distributor_hw_instruction : public boost::static_visitor<distributor_hw_instruction::type_e>
    {
    public:
        distributor_hw_instruction::type_e operator()(const distributor_hw_instruction::insert_data& data) const
        {
            return distributor_hw_instruction::type_e::INSERT;
        }

        distributor_hw_instruction::type_e operator()(const distributor_hw_instruction::remove_data& data) const
        {
            return distributor_hw_instruction::type_e::REMOVE;
        }

        distributor_hw_instruction::type_e operator()(const distributor_hw_instruction::modify_payload_data& data) const
        {
            return distributor_hw_instruction::type_e::MODIFY_PAYLOAD;
        }

        distributor_hw_instruction::type_e operator()(const distributor_hw_instruction::update_group_to_core_data& data) const
        {
            return distributor_hw_instruction::type_e::UPDATE_GROUP_TO_CORE;
        }

        distributor_hw_instruction::type_e operator()(boost::blank x) const
        {
            return distributor_hw_instruction::type_e::EMPTY;
        }
    };

    using hardware_instruction_vec = vector_alloc<distributor_hw_instruction>;

    /// @brief Destructor of LPM distributor.
    virtual ~lpm_distributor();

    /// @name Update APIs.
    /// @{

    /// @brief Insert a new key/payload to distributor.
    ///
    /// @param[in]      key                  Key to insert.
    /// @param[in]      payload              Payload to insert.
    /// @param[out]     out_instructions     Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    virtual la_status insert(const lpm_key_t& key, lpm_payload_t payload, hardware_instruction_vec& out_instructions);

    /// @brief Remove a key from distributor.
    ///
    /// @param[in]      key                  Key to remove.
    /// @param[out]     out_instructions     Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    virtual la_status remove(const lpm_key_t& key, hardware_instruction_vec& out_instructions);

    /// @brief Perform a list of updates to distributor.
    ///
    /// @param[in]      update               Updates to perform.
    /// @param[out]     out_instructions     Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    virtual la_status update(const lpm_implementation_desc_vec& updates, hardware_instruction_vec& out_instructions) = 0;

    /// @}

    /// @name Find/Lookup APIs.
    /// @{

    /// @brief Lookup a key in distributor by walking the TCAM tree.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_key          Hit key (key with longest prefix match).
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_hit_location     Hit location.
    ///
    /// @return #la_status.
    virtual la_status lookup_tcam_tree(const lpm_key_t& key,
                                       lpm_key_t& out_hit_key,
                                       lpm_payload_t& out_hit_payload,
                                       distributor_cell_location& out_hit_location) const;

    /// @brief Lookup a key in distributor by walking the TCAM table.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_key          Hit key (topmost key in table which gives a hit).
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_hit_location     Hit location.
    ///
    /// @return #la_status.
    virtual la_status lookup_tcam_table(const lpm_key_t& key,
                                        lpm_key_t& out_hit_key,
                                        lpm_payload_t& out_hit_payload,
                                        distributor_cell_location& out_hit_location) const;

    /// @brief Find a valid node with given key.
    ///
    /// @param[in]      key                  Key to find.
    ///
    /// @return node with given key, or nullptr if not found.
    virtual const lpm_logical_tcam_tree_node* find(const lpm_key_t& key) const;

    /// @}

    /// @name Getters of Distributor's content.
    /// @{

    /// @brief Get root node of distributor IPv4/IPv6 tree.
    ///
    /// @param[in]        is_ipv6             Get the root of the IPv6 tree.
    ///
    /// @return Distributor's root node.
    virtual const lpm_logical_tcam_tree_node* get_root_node(bool is_ipv6) const;

    /// @brief Get payload associated with a distributor node.
    ///
    /// @param[in]        node                 Node to retreive its payload.
    /// @param[out]       out_payload          Payload of node.
    ///
    /// @return #la_status.
    virtual la_status get_payload_of_node(const lpm_logical_tcam_tree_node* node, lpm_payload_t& out_payload) const;

    /// @brief Get entry at the given physical location.
    ///
    /// @param[in]        location             Cell location to read.
    /// @param[out]       out_key_payload      Key/payload
    ///
    /// @return #la_status.
    virtual la_status get_entry(distributor_cell_location location, lpm_key_payload& out_key_payload) const = 0;

    /// @brief Get all valid entries in distributor.
    ///
    /// @return vector of key, payload, location of valid entries.
    virtual vector_alloc<lpm_key_payload_location> get_entries() const;

    /// @}

    /// @name Commit/Withdraw API.
    /// @{

    /// @brief Commit previous updates.
    ///
    /// The changes cannot be withdrawn after calling this function.
    virtual void commit() = 0;

    /// @brief Withdraw previous updates which haven't been comitted yet and return distributor object to its previous state.
    virtual void withdraw() = 0;

    /// @}

    /// @brief Save current disributor's state.
    ///
    /// @return JSON representation of the distributer.
    virtual json_t* save_state() const = 0;

    /// @brief Load distrbutor state from json object.
    ///
    /// @param[in]        json_distributor     Json object of distributor.
    /// @param[out]       out_instructions     Instructions to pass to next stage to reflect the logical update.
    virtual void load_state(json_t* json_distributor, hardware_instruction_vec& out_instructions) = 0;

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_distributor() : m_num_cells_per_bank()
    {
    }

    /// @brief Construct a LPM distributor object.
    ///
    /// @param[in]     name                 Name of distibutor.
    /// @param[in]     num_hw_lines         Number of HW lines in distributor TCAM.
    /// @param[in]     max_key_width        Max supported key width.
    /// @param[in]     num_ipv4_rows        Number of logical rows for IPv4 logical TCAM.
    /// @param[in]     num_ipv6_rows        Number of logical rows for IPv6 logical TCAM.
    lpm_distributor(std::string name, size_t num_hw_lines, size_t max_key_width, size_t num_ipv4_rows, size_t num_ipv6_rows);

    /// @brief Make room for an entry of a given type (IPv4/IPv6).
    ///
    /// @param[in]      is_ipv6             Make room for an IPv6 entry
    /// @param[out]     out_instructions    Instructions to pass to next stage to reflect the logical update.
    ///
    /// @return #la_status.
    virtual la_status make_space_for_logical_tcam(bool is_ipv6, lpm_logical_tcam::logical_instruction_vec& out_instructions) = 0;

    /// @brief Translate logical row to cell location.
    ///
    /// @param[in]     logical_row          Logical row to translate.
    /// @param[in]     is_ipv6              Boolean that represents owner of row.
    ///
    /// @return Cell location.
    virtual distributor_cell_location translate_logical_row_to_cell_location(size_t logical_row, bool is_ipv6) const = 0;

    /// @brief Translate the list of logical instructions to a list of distributor hardware instructions.
    ///
    /// @param[in]      logical_instructions                  Instructions to translate.
    /// @param[out]     out_instructions                      List of hardware instructions.
    void translate_logical_to_physical_instructions(lpm_logical_tcam::logical_instruction_vec logical_instructions,
                                                    hardware_instruction_vec& out_instructions) const;

    /// @brief Reset current state of distributor.
    ///
    /// @param[out]   out_instructions    Instructions to pass to next stage to reflect the logical update.      .
    void reset_state(hardware_instruction_vec& out_instructions);

    // Properties
    std::string m_name;                ///< Distributor's name.
    const size_t m_num_cells_per_bank; ///< Number of HW lines in distributor TCAM.
    size_t m_max_key_width;            ///< Max supported key width.

    // Core data structures
    vector_alloc<lpm_logical_tcam> m_logical_tcams; ///< Vector containing logical TCAMs (IPv4 + IPv6)

}; // class lpm_distributor

} // namespace silicon_one

#ifdef GCC_7_5
#pragma GCC diagnostic pop
#endif
#endif // __LEABA_LPM_DISTRIBUTOR_H__
