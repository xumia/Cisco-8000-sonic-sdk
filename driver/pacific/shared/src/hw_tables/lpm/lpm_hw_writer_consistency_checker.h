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

#ifndef __LEABA_LPM_HW_WRITER_CONSISTENCY_CHECKER_H__
#define __LEABA_LPM_HW_WRITER_CONSISTENCY_CHECKER_H__

#include "hw_tables/lpm_types.h"
#include "logical_lpm_impl.h"
#include "lpm_core_tcam_allocator.h"
#include "lpm_internal_types.h"

#include <array>
#include <memory>
#include <unordered_map>

namespace silicon_one
{

static const size_t NUM_OF_L1_HW_LINES = 4096;
static const size_t NUM_OF_L2_HW_LINES = 16384;
static const size_t NUM_OF_TCAM_HW_LINES = 512;
static const size_t NUM_OF_TCAM_HW_BANKS = 4;
static const size_t NUM_OF_DISTRIBUTOR_HW_LINES = 128;
static const size_t NUM_OF_TCAM_BUNKSETS = 2;
static const size_t MAX_QUAD_BLOCK = 240;

static const size_t NUM_OF_CORES = 16;

class lpm_hw_writer_consistency_checker
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // lpm_core_hw_writer API-s
    la_status write_l2_sram_buckets(const size_t core_id, const lpm_bucket* bucket0, const lpm_bucket* bucket1);
    la_status write_l2_hbm_bucket(const size_t core_id, const lpm_bucket* bucket);
    la_status write_l1_line(const size_t core_id, const lpm_bucket* bucket0, const lpm_bucket* bucket1);
    la_status write_tcam(const size_t core_id,
                         const tcam_cell_location& location,
                         const lpm_key_t& key,
                         lpm_payload_t payload,
                         bool only_update_payload);
    la_status invalidate_tcam(const size_t core_id, const tcam_cell_location& location, const lpm_key_t& key);

    /// @brief Writes expected payloads for current actions.
    ///
    /// @param[in]      actions                 Current actions.
    ///
    /// @return #la_status.
    la_status write_expected_payloads_for_current_actions(const lpm_implementation_desc_vec& actions);

    /// @brief Perform update instructions in distributor logical representation.
    ///
    /// @param[in]      instructions       Hardware instructions to perform.
    ///
    /// @return  la_status.
    la_status update_distributor(const lpm_distributor::hardware_instruction_vec& instructions);

    /// @brief Lookup a key in HW logical representation.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_payload      Hit payload.
    ///
    /// @return #la_status.
    la_status lookup(const lpm_key_t& key, lpm_payload_t& out_hit_payload);

private:
    /// @brief Default c'tor - shouldn't be used, allowed only for serialization purposes.
    lpm_hw_writer_consistency_checker() = default;

    /// @brief Data that Layer1/Layer2 HW line contains.
    struct bucket_data {
        lpm_key_t m_root;                ///< Root key node of the bucket.
        lpm_key_payload m_default_entry; ///< Default entry of the bucket, used in case there is no hit.
        lpm_key_payload_vec entries;     ///< All nodes from from the bucket.
        size_t ref_count;                ///< Number of references to this HW line.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(bucket_data)

    /// @brief Data that TCAM HW line contains.
    struct tcam_data {
        lpm_key_t key;         ///< Root key node of the bucket.
        lpm_payload_t payload; ///< Payload for the key.
        bool is_valid;         ///< Indikator if HW line is valid.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(tcam_data)

    /// @brief Payload value.
    struct payload_data {
        lpm_payload_t payload; ///< Payload for the key.
        bool is_valid;         ///< Indicator if the key is valid prefix.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(payload_data)

    /// @brief Data that Distributor HW line contains.
    struct distributor_data {
        lpm_key_t key;   ///< Key for this prefix.
        size_t group_id; ///< Group id for this prefix.
        bool is_valid;   ///< Indikator if HW line is valid.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(distributor_data)

    /// @brief Type of device.
    enum class device_type {
        pacific,   ///< Pacific.
        gibraltar, ///< Gibraltar
        akpg,      ///< AKPG
    };

    /// @brief Increases L1 ref count.
    ///
    /// If this is the first time this L1 bucket is being pointed to, then also increases relevant L2 ref counts.
    ///
    /// @param[in]      hw_index    Hw index of L1 bucket.
    void increase_l1_ref_count(const size_t core_id, lpm_bucket_index_t& hw_index);

    /// @brief Decreases L1 ref count.
    ///
    /// If this L1 bucket is not being pointed to any more, then also decreases relevant L2 ref counts.
    ///
    /// @param[in]      hw_index    Hw index of L1 bucket.
    void decrease_l1_ref_count(const size_t core_id, lpm_bucket_index_t& hw_index);

    /// @brief Lookup a key in distributor logical representation.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[out]     out_hit_core_id      Hit core_id.
    /// @param[out]     out_location         Hit location.
    ///
    /// @return #la_status.
    la_status lookup_distributor(const lpm_key_t& key, size_t& out_hit_core_id, size_t& out_location);

    /// @brief Lookup a key in TCAM.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[in]      core_id              Core in which to lookup.
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_location         Hit location.
    ///
    /// @return #la_status.
    la_status lookup_tcam(const lpm_key_t& key, size_t core_id, lpm_payload_t& out_hit_payload, tcam_cell_location& out_location);

    /// @brief Lookup a key in TCAM by avoiding given location.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[in]      core_id              Core in which to lookup.
    /// @param[in]      location_to_avoid    TCAM location to be avoided during the lookup.
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_location         Hit location.
    ///
    /// @return #la_status.
    la_status lookup_tcam_avoiding_specific_location(const lpm_key_t& key,
                                                     size_t core_id,
                                                     const tcam_cell_location& location_to_avoid,
                                                     lpm_payload_t& out_hit_payload,
                                                     tcam_cell_location& out_location);

    /// @brief Lookup a key in Level 1.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[in]      core_id              Core in which to lookup.
    /// @param[in]      hw_index             Hw index of the bucket.
    /// @param[out]     out_hit_payload      Hit payload.
    /// @param[out]     out_l1_hit_default   Default payload is used.
    ///
    /// @return #la_status.
    la_status lookup_l1(const lpm_key_t& key,
                        size_t core_id,
                        lpm_bucket_index_t hw_index,
                        lpm_payload_t& out_hit_payload,
                        bool& out_l1_hit_default);

    /// @brief Lookup a key in Level 2.
    ///
    /// @param[in]      key                  Key to lookup.
    /// @param[in]      core_id              Core in which to lookup.
    /// @param[in]      hw_index             Hw index of the bucket.
    /// @param[out]     out_hit_payload      Hit payload.
    ///
    /// @return #la_status.
    la_status lookup_l2(const lpm_key_t& key, size_t core_id, lpm_bucket_index_t hw_index, lpm_payload_t& out_hit_payload);

    /// @brief Verify consistency during write of one Level 1 bucket.
    ///
    /// @param[in]      core_id              Core that buckets belong to.
    /// @param[in]      hw_index             Hw index of the bucket.
    /// @param[in]      bucket               Bucket that is being verified.
    ///
    /// @return #la_status.
    la_status verify_l1_bucket(const size_t core_id, lpm_bucket_index_t hw_index, const lpm_bucket* bucket);

    /// @brief Verify consistency during write of one Level 2 bucket.
    ///
    /// @param[in]      core_id              Core that bucket belongs to.
    /// @param[in]      hw_index             Hw index of the bucket.
    /// @param[in]      bucket               Bucket that is being verified.
    ///
    /// @return #la_status.
    la_status verify_l2_bucket(const size_t core_id, lpm_bucket_index_t hw_index, const lpm_bucket* bucket);

    // @brief Update Level 1 data structure.
    ///
    /// @param[in]      core_id              Core that buckets belong to.
    /// @param[in]      hw_index             Hw index of the bucket.
    /// @param[in]      bucket               Bucket that is being written.
    void update_l1_data_structure(const size_t core_id, lpm_bucket_index_t hw_index, const lpm_bucket* bucket);

    /// @brief Update Level 2 data structure.
    ///
    /// @param[in]      core_id              Core that buckets belong to.
    /// @param[in]      hw_index             Hw index of the bucket.
    /// @param[in]      bucket               Bucket that is being written.
    void update_l2_data_structure(const size_t core_id, lpm_bucket_index_t hw_index, const lpm_bucket* bucket);

    /// @brief Verify single prefix consistency.
    ///
    /// @param[in]      prefix                  Prefix to verify consistency on.
    /// @param[in]      new_entries             Entries that are being written.
    ///
    /// @return #la_status.
    la_status verify_single_prefix(const lpm_key_payload& prefix, const lpm_key_payload_vec& new_entries);

    /// @brief Verify modification of a TCAM line.
    ///
    /// @param[in]      core_id              Core that tcam_line belongs to.
    /// @param[in]      location             Location of tcam line.
    /// @param[in]      key                  New key.
    /// @param[in]      payload              New payload.
    ///
    /// @return #la_status.
    la_status verify_modify_tcam_line(const size_t core_id,
                                      const tcam_cell_location& location,
                                      const lpm_key_t& key,
                                      lpm_payload_t payload);

    /// @brief Verify insertion of TCAM line.
    ///
    /// @param[in]      core_id              Core that tcam_line belongs to.
    /// @param[in]      location             Location of tcam line.
    /// @param[in]      key                  New key.
    /// @param[in]      payload              New payload.
    ///
    /// @return #la_status.
    la_status verify_insert_tcam_line(const size_t core_id,
                                      const tcam_cell_location& location,
                                      const lpm_key_t& key,
                                      lpm_payload_t payload);

    /// @brief Verify removing of TCAM line.
    ///
    /// @param[in]      core_id              Core that tcam_line belongs to.
    /// @param[in]      location             Location of tcam line.
    /// @param[in]      key                  New key.
    ///
    /// @return #la_status.
    la_status verify_remove_tcam_line(const size_t core_id, const tcam_cell_location& location, const lpm_key_t& key);

    /// @brief Update TCAM data structure on insertion.
    ///
    /// @param[in]      core_id              Core that tcam_line belongs to.
    /// @param[in]      location             Location of tcam line.
    /// @param[in]      key                  New key.
    /// @param[in]      payload              New payload.
    void update_tcam_data_structure_insert(const size_t core_id,
                                           const tcam_cell_location& location,
                                           const lpm_key_t& key,
                                           lpm_payload_t payload);

    /// @brief Update TCAM data structure on modification.
    ///
    /// @param[in]      core_id              Core that tcam_line belongs to.
    /// @param[in]      location             Location of tcam line.
    /// @param[in]      key                  New key.
    /// @param[in]      payload              New payload.
    void update_tcam_data_structure_modify(const size_t core_id,
                                           const tcam_cell_location& location,
                                           const lpm_key_t& key,
                                           lpm_payload_t payload);

    /// @brief Update TCAM data structure on removing.
    ///
    /// @param[in]      core_id              Core that tcam_line belongs to.
    /// @param[in]      location             Location of tcam line.
    void update_tcam_data_structure_remove(const size_t core_id, const tcam_cell_location& location);

    /// @brief Update distributor data on insertion.
    ///
    /// @param[in]      instruction              Instruction data.
    void update_distributor_insert(const lpm_distributor::distributor_hw_instruction& instruction);

    /// @brief Revert insertion of distributor line.
    ///
    /// @param[in]      instruction              Instruction data.
    void revert_distributor_insert(const lpm_distributor::distributor_hw_instruction& instruction);

    /// @brief Update distributor data on remove.
    ///
    /// @param[in]      instruction              Instruction data.
    void update_distributor_remove(const lpm_distributor::distributor_hw_instruction& instruction);

    /// @brief Verify remove of distributor entry.
    ///
    /// @param[in]      instruction              Instruction data.
    ///
    /// @return #la_status.
    la_status verify_remove_distributor_line(const lpm_distributor::distributor_hw_instruction& instruction);

    /// @brief Verify insertion of distributor entry.
    ///
    /// @param[in]      instruction              Instruction data.
    ///
    /// @return #la_status.
    la_status verify_insert_distributor_line(const lpm_distributor::distributor_hw_instruction& instruction);

    /// @brief Get group prefixes.
    ///
    /// @param[in]      core_id              Core in which to look for prefixes.
    /// @param[in]      key                  Key to lookup.
    /// @param[in]      lookup_line_parent   Hw line of parent.
    /// @param[out]     out_prefixes         Collected prefixes.
    ///
    /// @return #la_status.
    la_status get_group_prefixes(const size_t core_id,
                                 const lpm_key_t& key,
                                 size_t lookup_line_parent,
                                 lpm_key_payload_vec& out_prefixes);

    /// @brief Update distributor data on modifying group to core.
    ///
    /// @param[in]      instruction              Instruction data.
    void update_distributor_modify_group_to_core(const lpm_distributor::distributor_hw_instruction& instruction);

    /// @brief Verify modify group to core of distributor entry.
    ///
    /// @param[in]      instruction              Instruction data.
    ///
    /// @return #la_status.
    la_status verify_modify_group_to_core_distributor_line(const lpm_distributor::distributor_hw_instruction& instruction);

    std::array<std::array<bucket_data, NUM_OF_L1_HW_LINES>, NUM_OF_CORES>
        m_l1_logical_representation; ///< Logical representation of Level 1 HW lines.
    std::array<std::array<bucket_data, NUM_OF_L2_HW_LINES>, NUM_OF_CORES>
        m_l2_logical_representation; ///< Logical representation of Level 2 HW lines.
    std::array<std::array<std::array<std::array<tcam_data, NUM_OF_TCAM_HW_LINES>, NUM_OF_TCAM_HW_BANKS>, NUM_OF_TCAM_BUNKSETS>,
               NUM_OF_CORES>
        m_tcam_logical_representation; ///< Logical representation of TCAM HW lines.
    std::array<distributor_data, NUM_OF_DISTRIBUTOR_HW_LINES>
        m_distributor_logical_representation;                               ///< Logical representation of distributor HW lines.
    std::array<size_t, NUM_OF_DISTRIBUTOR_HW_LINES> m_group_to_core_id;     ///< Vector mapping group index to core id.
    std::unordered_map<lpm_key_t, payload_data> m_expected_payload_for_key; ///< Map which maps keys to expected payloads.

    device_type m_device_type = device_type::pacific; ///< Device type.
};

} // namespace silicon_one

#endif
