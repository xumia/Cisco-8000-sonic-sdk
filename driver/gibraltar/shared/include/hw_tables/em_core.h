// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LEABA_EM_CORE_H__
#define __LEABA_EM_CORE_H__

#include "common/bit_vector.h"
#include "common/la_status.h"

#include "lld/lld_fwd.h"

#include "hw_tables/em_common.h"
#include "hw_tables/em_hasher.h"
#include "hw_tables/logical_em.h"
#include "hw_tables/physical_locations.h"

/// @file

namespace silicon_one
{

class em_hasher;
class ll_device;

/// @brief EM core.
///
/// An exact match core representation. Implements the EM table and its interface.
class em_core : public logical_em
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct an empty EM core.
    ///
    /// @param[in]      ldevice                  Low Level device. If NULL, no writes will be done to HW.
    /// @param[in]      em                       Physical EM representation.
    /// @param[in]      max_moving_depth         Number of entry movings allowed.
    /// @param[in]      flex_entry_enabled       Set if EM supports flexible entries(default = false)
    em_core(const ll_device_sptr& ldevice, const physical_em& em, size_t max_moving_depth, bool flex_entry_enabled = false);

    // D'tor
    ~em_core() = default;

    // forbid copy
    em_core(const em_core& o) = delete;
    em_core& operator=(const em_core& o) = delete;

    /// @name Update API-s
    /// @{

    /// @brief Insert entry to EM.
    ///
    /// @param[in]      key                     Key of entry to insert.
    /// @param[in]      payload                 Payload of entry to insert.
    ///
    /// @retval         LA_STATUS_SUCCESS       Insertion completed successfully.
    /// @retval         LA_STATUS_EINVAL        Given key width is unsupported or doesn't match given payload's width.
    /// @retval         LA_STATUS_EEXIST        Given key already exists.
    /// @retval         LA_STATUS_ERESOURCE     No free slot found for given entry.
    la_status insert(const bit_vector& key, const bit_vector& payload) override;

    /// @brief Remove entry from EM.
    ///
    /// @param[in]      key                     Key of entry to remove.
    ///
    /// @retval         LA_STATUS_SUCCESS       Removal completed successfully.
    /// @retval         LA_STATUS_EINVAL        Given key width is unsupported.
    /// @retval         LA_STATUS_ENOTFOUND     Given key wasn't found.
    la_status erase(const bit_vector& key) override;

    /// @brief Remove entry from EM that supports flexible entries
    ///
    /// EMs with flexible entry options could have same key but different payload sizes
    ///
    /// @param[in]      key                     Key of entry to remove.
    ///
    /// @param[in]      payload_width           Width of payload
    ///
    /// @retval         LA_STATUS_SUCCESS       Removal completed successfully.
    /// @retval         LA_STATUS_EINVAL        Given key width is unsupported.
    /// @retval         LA_STATUS_ENOTFOUND     Given key wasn't found.
    la_status erase(const bit_vector& key, size_t payload_width) override;

    /// @brief Returns if EM supports flexible entry
    ///
    /// @retval true if flexible entry supported
    bool is_flexible_entry_supported() const override;

    /// @brief Update an entry's payload.
    ///
    /// @param[in]      key                     Key of entry to update.
    /// @param[in]      payload                 New payload.
    ///
    /// @retval         LA_STATUS_SUCCESS       Update completed successfully.
    /// @retval         LA_STATUS_EINVAL        Given key width is unsupported or doesn't match given payload's width.
    /// @retval         LA_STATUS_ENOTFOUND     Given key wasn't found.
    la_status update(const bit_vector& key, const bit_vector& payload) override;

    /// @}

    /// @name Data access
    /// @{

    /// @brief Get a payload of an entry according to key.
    ///
    /// @param[in]      key             Key of entry to lookup.
    /// @param[out]     out_payload     Payload of found entry.
    ///
    /// @retval         LA_STATUS_SUCCESS       Lookup completed successfully.
    /// @retval         LA_STATUS_EINVAL        Given key width is unsupported.
    /// @retval         LA_STATUS_ENOTFOUND     Given key wasn't found.
    la_status lookup(const bit_vector& key, bit_vector& out_payload) const;

    /// @}

    /// @brief Returns physical EM.
    ///
    /// @retval pointer to physical EM.
    const physical_em* get_physical_em() const;

    // logical_em API-s
    size_t max_size() const override;

    la_status get_physical_usage(size_t num_of_table_logical_entries, size_t& out_physical_usage) const override;

    la_status get_available_entries(size_t& out_available_entries) const override;

    /// @brief Set resource monitor.
    ///
    /// @param[in]  resource_monitor           Resource monitor.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    la_status set_resource_monitor(const resource_monitor_sptr& monitor) override;

    /// @brief Get resource monitor.
    ///
    /// @param[out] out_resource_monitor        Resource monitor to populate.
    ///
    /// @retval     LA_STATUS_SUCCESS           Success.
    /// @retval     LA_STATUS_EUNKONWN          Internal error.
    la_status get_resource_monitor(resource_monitor_sptr& out_monitor) const override;

    /// @brief Retrieve the number of entries in the table.
    ///
    /// @retval Number of entries.
    size_t size() const override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    em_core();

    typedef em::key_t em_verifier_t;

    /// @brief EM bank entry.
    struct em_bank_entry {
        bool m_valid;             ///< Boolean specifing whether entry is valid.
        size_t line_cfg_index;    ///< Line configuration option index.
        em::key_t m_key;          ///< Bank entry's key.
        em_verifier_t m_verifier; ///< Bank entry's verifier.
        em::payload_t m_payload;  ///< Bank entry's payload.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(em_bank_entry)

    /// @brief EM CAM entry.
    struct em_cam_entry {
        bool m_valid;            ///< Boolean specifing whether entry is valid.
        em::key_t m_key;         ///< CAM entry's key.
        em::payload_t m_payload; ///< CAM entry's payload.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(em_cam_entry)

    /// @brief EM hashed value.
    ///
    /// The result of the hashing process is an index and a verifier.
    struct em_hashed_value {
        size_t m_entry_index;     ///< Entry's index.
        em_verifier_t m_verifier; ///< Entry's verifier.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(em_hashed_value)

    // Vector of entries representing an EM bank, and an EM CAM.
    typedef std::vector<em_bank_entry> em_bank_t;
    typedef std::vector<em_cam_entry> em_cam_t;

    enum { EM_NULL_INDEX = (size_t)-1 };

    // HW entry to write.
    struct hw_entry {
        size_t bank_index;     ///< Entry bank index.
        size_t entry_index;    ///< Entry index in bank.
        em::key_t key;         ///< Verifier to write.
        size_t line_cfg_index; ///< Line configuration option index.
        em::key_t verifier;    ///< Verifier to write.
        em::payload_t payload; ///< Payload to write.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(hw_entry)

    // List of HW entries to write.
    typedef std::vector<hw_entry> hw_entries_vec_t;

    /// @brief Check inputs key and payload parameters are valid.
    ///
    /// @param[in]      key                     Key to check for correctness.
    /// @param[in]      payload                 Payload to check for correctness.
    ///
    /// @return true if parameters valid, false otherwise.
    bool check_key_payload_inputs(const em::key_t& key, const em::payload_t& payload) const;

    /// @brief Check input key.
    ///
    /// @param[in]      key                     Key to check for correctness.
    ///
    /// @return true if parameter valid, false otherwise.
    bool check_key_input(const em::key_t& key) const;

    /// @brief Calculate hash function according to specified bank and key.
    ///
    /// @param[in]      bank_index              Index of bank to calculate hash for.
    /// @param[in]      key                     Key to calculate hash from.
    ///
    /// @return Hash result.
    em_hashed_value calc_hash(size_t bank_index, const em::key_t& key) const;

    /// @brief Find the bank index and the line number of an entry.
    ///
    /// Bank index that equals number of banks implies CAM.
    /// If entry wasn't found, return false, and set indices to free entry.
    /// If entry wasn't found and no free entry exists for key, set indices to be EM_NULL_INDEX.
    ///
    /// @param[in]      key                     Key of entry to find.
    /// @param[in]      line_cfg_option         Option index in line config  options
    /// @param[out]     out_bank_index          Index of bank containing requested key.
    /// @param[out]     out_entry_index         Index of entry in relevant bank.
    /// @param[out]     out_verifier            Verifier of free entry if free entry is returned.
    ///
    /// @return true if entry found, false otherwise.
    bool find_entry(const em::key_t& key,
                    size_t& line_cfg_option,
                    size_t& out_bank_index,
                    size_t& out_entry_index,
                    em_verifier_t& out_verifier) const;

    /// @brief Get const reference to bank entry according to given bank and entry indices.
    ///
    /// @param[in]      bank_index              Index of bank containing requested key.
    /// @param[in]      entry_index             Index of entry in relevant bank.
    ///
    /// @return Const reference to requested entry.
    const em_bank_entry& get_bank_entry(size_t bank_index, size_t entry_index) const;

    /// @brief Get reference to bank entry according to given bank and entry indices.
    ///
    /// @param[in]      bank_index              Index of bank containing requested key.
    /// @param[in]      entry_index             Index of entry in relevant bank.
    ///
    /// @return Reference to requested entry.
    em_bank_entry& get_bank_entry(size_t bank_index, size_t entry_index);

    /// @brief Get const reference to CAM entry according to given entry index.
    ///
    /// @param[in]      entry_index             Index of entry in CAM.
    ///
    /// @return Const reference to requested entry.
    const em_cam_entry& get_cam_entry(size_t entry_index) const;

    /// @brief Get reference to CAM entry according to given entry index.
    ///
    /// @param[in]      entry_index             Index of entry in CAM.
    ///
    /// @return Reference to requested entry.
    em_cam_entry& get_cam_entry(size_t entry_index);

    /// @brief Insert entry to banks.
    ///
    /// @param[in]      key                     Key to insert to banks.
    /// @param[in]      payload                 Payload to insert to banks.
    /// @param[in]      free_bank_index         Hint for free bank index to insert to. If EM_NULL_INDEX check all banks.
    /// @param[in]      free_entry_index        Hint for free entry index to insert to. If EM_NULL_INDEX check all banks.
    /// @param[in]      verifier                Hint for verifier of key in free entry (if indices aren't EM_NULL_INDEX).
    /// @param[out]     entries_to_write        List of entries to be written to HW.
    ///
    /// @return true if insertion succeeded, false otherwise.
    bool insert_entry_to_banks(const em::key_t& key,
                               const em::payload_t& payload,
                               size_t free_bank_index,
                               size_t free_entry_index,
                               size_t line_cfg_option_index,
                               em_verifier_t& verifier,
                               hw_entries_vec_t& entries_to_write);

    /// @brief Insert entry to cam.
    ///
    /// @param[in]      key                     Key to insert to cam.
    /// @param[in]      payload                 Payload to insert to cam.
    /// @param[in]      free_entry_index        Hint for free entry index to insert to. If EM_NULL_INDEX check all entries in CAM.
    /// @param[out]     entries_to_write        List of entries to be written to HW.
    ///
    /// @return true if insertion succeeded, false otherwise.
    bool insert_entry_to_cam(const em::key_t& key,
                             const em::payload_t& payload,
                             size_t free_entry_index,
                             hw_entries_vec_t& entries_to_write);

    /// @brief Move congesting entry to a different slot (might need some more moves).
    ///
    /// No free slot for key exists. Try moving congestion keys to make room for key.
    /// If fails try move their congestion keys to make room for them to make room for key.
    /// If maximum moving limit reached, don't move anything and return LA_STATUS_RESOURCE.
    /// If moving is possible, move the entries to make room for given key.
    ///
    /// @param[in]      key                     Key to move congestions for.
    /// @param[out]     out_bank_index          Bank index of freed entry.
    /// @param[out]     out_entry_index         Entry index of freed entry.
    /// @param[out]     out_verifier            Verifier of freed entry (with given key).
    /// @param[out]     entries_to_write        List of entries to be written to HW.
    ///
    /// @return true if moving was performed, false otherwise.
    bool handle_collision_banks(const em::key_t& key,
                                size_t& out_bank_index,
                                size_t& out_entry_index,
                                em_verifier_t& out_verifier,
                                hw_entries_vec_t& entries_to_write);

    /// @brief The same as handle collision but now trying to move from CAM.
    ///
    /// @param[in]      key                     Key to move congestions for.
    /// @param[out]     out_entry_index         CAM entry index of freed entry.
    /// @param[out]     entries_to_write        List of entries to be written to HW.
    ///
    /// @return true if moving was performed, false otherwise.
    bool handle_collision_cam(const em::key_t& key, size_t& out_entry_index, hw_entries_vec_t& entries_to_write);

    // Help struct to hold candidate entry to move, for handle collision implementation.
    struct candidate_entry_indices {
        size_t m_bank_index;             // Entry bank index.
        size_t m_entry_index;            // Entry index in bank.
        size_t m_moving_depth;           // Number of movings to do if this entry is the first to move.
        size_t m_parent_candidate_index; // Candidate index (in vector) of entry to move to this entry.
        em::key_t m_key;                 // Key of candidate.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(candidate_entry_indices)

    typedef std::vector<candidate_entry_indices> em_moving_candidates_vec_t;

    /// @brief Check if candidate entries can be moved, if yes, move them.
    ///
    /// @param[in]      moving_candidates       Vector of candidate entries to move.
    /// @param[out]     out_bank_index          Bank index of freed entry.
    /// @param[out]     out_entry_index         Entry index of freed entry.
    ///
    /// @return true if moving was performed, false otherwise.
    bool check_and_move_candidates(em_moving_candidates_vec_t& moving_candidates,
                                   size_t& out_bank_index,
                                   size_t& out_entry_index,
                                   hw_entries_vec_t& entries_to_write);

    /// @brief Move entries in EM core to make room for another entry.
    ///
    /// Strart from the entry in given index (in vector), move it to free entry specified,
    /// then move its parent candidate to the now free entry.
    /// Keep going until no parent candidate.
    ///
    /// @param[in]      moving_candidates       Vector of candidate entries to move.
    /// @param[in]      from_index              Index in vector of entry to move first.
    /// @param[in,out]  free_bank_index         Bank index of free entry.
    /// @param[in,out]  free_entry_index        Entry index of free entry.
    void move_entries(const em_moving_candidates_vec_t& moving_candidates,
                      size_t from_index,
                      size_t& free_bank_index,
                      size_t& free_entry_index,
                      hw_entries_vec_t& entries_to_write);

    /// @brief Get hasher pointer according to key width and bank index.
    ///
    /// @param[in]      key_width               Width of key to get hasher for.
    /// @param[in]      bank_index              Index of bank to get hasher for.
    ///
    /// @return Const pointer to relevant hasher.
    em_hasher_scptr get_hasher(size_t key_width, size_t bank_index) const;

    /// @brief Get key index in key option list.
    /// Order of keys is significant.
    /// The index is used in encoding of key width in bank line.
    ///
    /// @param[in]      key_width               Width of key to get index.
    ///
    /// @return index or EM_NULL_INDEX if the width is illegal.
    size_t get_key_option_index(size_t key_width) const;

    /// @brief Get index in line config option list.
    /// Order of keys is significant.
    /// The index is used in encoding of key width and payload width in bank line.
    ///
    /// @param[in]      key_width               Width of key to get index.
    ///
    /// @param[in]      payload_width           Width of payload to get index
    ///
    /// @return index or EM_NULL_INDEX if the width is illegal.
    size_t get_line_config_option_index(size_t key_width, size_t payload_width) const;

private:
    /// @brief Write list of provided entries to EM banks or CAM.
    ///
    /// @param[in]  entires_to_write    List of entries to write.
    ///
    /// @retval     status code.
    la_status write_to_physical_em(const hw_entries_vec_t& entires_to_write);

    /// @brief Write to the specified bank of the EM core.
    ///
    /// @param[in]  bank_idx            Bank index of the provided EM core. The bank must be active.
    /// @param[in]  entry_idx           Bank entry index.
    /// @param[in]  key                 EM key.
    /// @param[in]  veifier             Encrypted key verifier to write to EM.
    /// @param[in]  payload             Payload to write to EM.
    ///
    /// @retval     status code.
    la_status write_to_physical_bank(size_t bank_idx,
                                     size_t entry_idx,
                                     const em::key_t& key,
                                     size_t line_cfg_index,
                                     const em::key_t& verifier,
                                     const em::payload_t& payload);

    /// @brief Erase key from the specified bank of the EM core.
    ///
    /// @param[in]  bank_idx            Bank index of the provided EM core. The bank must be active.
    /// @param[in]  entry_idx           Bank entry index.
    ///
    /// @retval     status code.
    la_status erase_from_physical_bank(size_t bank_idx, size_t entry_idx);

    /// @brief Write to CAM.
    ///
    /// @param[in]  entry_idx           Bank entry index.
    /// @param[in]  key                 Key to write to EM.
    /// @param[in]  payload             Payload to write to EM.
    ///
    /// @retval     status code.
    la_status write_to_physical_cam(size_t entry_idx, const em::key_t& key, const em::payload_t& payload);

    /// @brief Erase key from CAM.
    ///
    /// @param[in]  entry_idx           Bank entry index.
    ///
    /// @retval     status code.
    la_status erase_from_physical_cam(size_t entry_idx);

    /// @brief Adds ECC to the most significant bits of entry starting ecc_lsb
    ///
    /// @param[in]  entry            EM bank entry data.
    /// @param[in]  ecc_lsb          ecc lsb. data [ecc_lsb-1:0]; ecc [width-1:ecc_lsb]
    void add_ecc_to_em_entry(bit_vector384_t& entry, size_t ecc_lsb);

    /// @brief Helper to initialize per-bank hashers for each key width
    void init_hashers();

private:
    double get_utilization_percentage();

    // Members
    bool m_is_cam_evacuation_disabled;

    // Low Level Device
    ll_device_sptr m_ll_device;

    // Parameters
    size_t m_num_of_banks;                ///< Number of banks in EM.
    size_t m_num_of_bank_entries;         ///< Number of entries in EM bank.
    size_t m_num_of_cam_entries;          ///< Number of entries in CAM.
    size_t m_entry_width;                 ///< Sum of widths of key and payload.
    size_t m_max_moving_depth;            ///< Maximum number of moves in collision handling.
    const size_t m_orig_max_moving_depth; ///< Backup of m_max_moving_depth in case it changes

    // Physical EM representation.
    physical_em m_em;
    bool m_flexible_entry; ///< Whether this EM supports flexible entry

    // Data
    std::vector<em_bank_t> m_banks; ///< Vector of banks.
    em_cam_t m_cam;                 ///< Vector of entries representing CAM.

    // Resource monitor
    resource_monitor_sptr m_resource_monitor;
    size_t m_num_entries;

    // Helpers
    using em_hashers_t = std::vector<std::pair<size_t, std::vector<em_hasher_scptr> > >;
    em_hashers_t m_hashers; ///< Vector of pairs of key width and vector of EM hashers, one per each bank.
};

} // namespace silicon_one

#endif
