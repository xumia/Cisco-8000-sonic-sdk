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

#ifndef __LEABA_LPM_CORE_HW_WRITER_AKPG_H__
#define __LEABA_LPM_CORE_HW_WRITER_AKPG_H__

#include "hw_tables/lpm_types.h"
#include "lpm_core_hw_writer.h"
#include "lpm_core_tcam_utils_akpg.h"

/// @file
namespace silicon_one
{

class lpm_core_hw_writer_akpg : public lpm_core_hw_writer
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    // lpm_core_hw_writer's APIs
    la_status write_tcam(const tcam_cell_location& location,
                         const lpm_key_t& key,
                         lpm_payload_t payload,
                         bool only_update_payload) const override;
    la_status invalidate_tcam(const tcam_cell_location& location, const lpm_key_t& key) override;
    lpm_entry read_tcam(const tcam_cell_location& location) const override;
    la_status write_tcam_default_row() const override;
    la_status write_l2_sram_buckets(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const override = 0;
    la_status write_l2_hbm_bucket(const lpm_bucket* bucket) const override = 0;
    std::vector<lpm_entry> read_l2_bucket(size_t hw_index, size_t& out_default_payload) const override = 0;
    la_status write_l1_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const override = 0;
    std::vector<lpm_entry> read_l1_bucket(size_t hw_index, size_t& out_default_payload) const override = 0;
    la_status read_index_of_last_accessed_l2_sram_buckets(vector_alloc<size_t>& bucket_indexes) override = 0;

protected:
    // Auxiliary constants.
    enum {
        NUM_TCAM_BANKS = 4,
        LAST_TCAM_BANK_IDX = NUM_TCAM_BANKS - 1, ///< Index of the last TCAM bank.

        // L2 entry fields widths
        L2_ENTRY_PAYLOAD_WIDTH = 28,
        L2_ENTRY_MERGED_PAYLOAD_WIDTH = L2_ENTRY_PAYLOAD_WIDTH + 1,
        L2_ENTRY_TYPE_WIDTH = 1, // TYPE: leaf or node
        L2_ENTRY_WIDTH = ENTRY_ENC_PREFIX_WIDTH + L2_ENTRY_TYPE_WIDTH + L2_ENTRY_PAYLOAD_WIDTH,

        L2_ENTRY_PREFIX_START = 0,
        L2_ENTRY_TYPE_START = ENTRY_ENC_PREFIX_WIDTH,
        L2_ENTRY_PAYLOAD_START = L2_ENTRY_TYPE_START + 1,
        L2_IS_WIDE_PREFIX_WIDTH = 1,
        L2_GROUP_WIDTH = 2 * L2_ENTRY_WIDTH + 1,
        L2_WIDE_ENC_PREFIX_WIDTH = 2 * ENTRY_PREFIX_WIDTH + L2_ENTRY_MERGED_PAYLOAD_WIDTH,

    };

    /// @brief Auxiliary data to hold L2 entry.
    /// Entry structure is: payload is_leaf prefix (msb .. lsb).
    union l2_group_data {
        struct two_single_entries {
            size_t is_wide_prefix : L2_IS_WIDE_PREFIX_WIDTH;
            size_t prefix0 : ENTRY_ENC_PREFIX_WIDTH;
            size_t is_leaf0 : L2_ENTRY_TYPE_WIDTH;
            size_t payload0 : L2_ENTRY_PAYLOAD_WIDTH;
            size_t prefix1 : ENTRY_ENC_PREFIX_WIDTH;
            size_t is_leaf1 : L2_ENTRY_TYPE_WIDTH;
            size_t payload1 : L2_ENTRY_PAYLOAD_WIDTH;
        };

        struct one_wide_entry {
            size_t is_wide_prefix : L2_IS_WIDE_PREFIX_WIDTH;
            size_t prefix1_valid : 1;
            size_t prefix1 : ENTRY_PREFIX_WIDTH;
            size_t is_leaf : L2_ENTRY_TYPE_WIDTH;
            size_t payload : L2_ENTRY_PAYLOAD_WIDTH;
            size_t prefix2_valid : 1;
            size_t prefix2 : ENTRY_PREFIX_WIDTH;
            size_t prefix0 : L2_ENTRY_MERGED_PAYLOAD_WIDTH;
        };

        two_single_entries single_entries;
        one_wide_entry wide_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_group_data)
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_group_data::two_single_entries)
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_group_data::one_wide_entry)

    /// @brief Construct a core HW writer.
    ///
    /// @param[in]      ldevice                          Low level device.
    /// @param[in]      core_id                          Core id, unique for each core.
    /// @param[in]      tcam_num_banksets                Number of allocated TCAM banksets.
    /// @param[in]      num_cells_per_bankset            Number of cells per bankset.
    /// @param[in]      tcam_bank_size                   Size of TCAM bank.
    /// @param[in]      tcam_size                        Physical size of TCAM bank.
    /// @param[in]      num_tcams_per_bank               Number of TCAMs per bank.
    /// @param[in]      tcam_payload_field_id_width      TCAM payload field width for L1 address.
    /// @param[in]      tcam_payload_field_length_width  TCAM payload field width for key length.
    lpm_core_hw_writer_akpg(const ll_device_sptr& ldevice,
                            lpm_core_id_t core_id,
                            uint8_t tcam_num_banksets,
                            size_t num_cells_per_bankset,
                            size_t tcam_bank_size,
                            size_t tcam_size,
                            size_t num_tcams_per_bank,
                            size_t tcam_payload_field_id_width,
                            size_t tcam_payload_field_length_width);

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_core_hw_writer_akpg();

    /// @brief Generate TCAM payload data.
    ///
    /// @param[in]      l1_address                       Pointer to L1 bucket.
    /// @param[in]      key_width                        Length of key in TCAM.
    ///
    /// @return TCAM payload as bit vector.
    virtual bit_vector generate_tcam_payload_data(lpm_payload_t l1_address, size_t key_width) const = 0;

    /// @brief Update bit in TCAM over 40 register.
    ///
    /// @param[in]      reg_idx            Register index.
    /// @param[in]      bit_idx            Index of the bit to be updated.
    /// @param[in]      value              Value to write.
    ///
    /// @return #la_status.
    la_status update_tcam_over_40_reg(size_t reg_idx, size_t bit_idx, size_t value) const;

    /// @brief CDB core resources needed to write LPM core.
    struct cdb_core_resources_akpg {
        lld_register_array_sptr lpm_rd_mod_wr_group_data_reg; ///
        lld_register_array_sptr tcam_over_40_reg;             ///< Full hit bit per entry in TCAM.
        lld_memory_scptr trie_mem;                            ///< LPM TCAM's memory.
        lpm_core_hw_writer::cdb_core_resources cdb_core;      ///< Relevant cdb core resources.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cdb_core_resources_akpg);

    /// @brief Generate group data for double entry.
    ///
    /// @param[in]  node        Node with double entry.
    /// @param[in]  root_width  Bucket root width.
    /// @param[in]  is_leaf     Is node leaf of bucket.
    /// @param[out] out_group   L2 group holder.
    void generate_group_from_wide_l2_entry(const lpm_node* node, size_t root_width, bool is_leaf, l2_group_data& out_group) const;

    /// @brief Generate group data for two single entries.
    ///
    /// @param[in]  node0       First node in group.
    /// @param[in]  node1       Second node in group.
    /// @param[in]  root_width  Bucket root width.
    /// @param[out] out_group   Generated group.
    void generate_group_from_single_l2_entries(const lpm_node* node0,
                                               const lpm_node* node1,
                                               size_t root_width,
                                               l2_group_data& out_group) const;

    /// @brief Decide if node should be marked as a leaf node when writing bucket to hardware.
    ///
    /// @param[in]      node            Node to check.
    /// @param[in]      is_hbm          Is node to be written to HBM.
    ///
    /// @return Is the node a leaf node.
    bool is_mark_as_leaf(const lpm_node* node, bool is_hbm) const;

    // members
    size_t m_l2_bucket_width;                              ///< L2 bucket width (HW line width).
    size_t m_l2_bucket_num_interleaved_groups;             ///< Maximum interleaved groups in L2 bucket.
    vector_alloc<cdb_core_resources_akpg> m_cdb_core_akpg; ///< Relevant cdb core resources.
    size_t m_num_tcams;                                    ///< Number of TCAMs in the core.
    size_t m_over_40_field_offset;                         ///< Offset of field in over_40_regs per LPM core.
    size_t m_l2_all_groups_width;                          ///< Width of all groups in L2 line.

private:
    /// @brief Write TCAM multiple row key to HW.
    ///
    /// @param[in]      location        Location to write to.
    /// @param[in]      node_key        Key to write.
    ///
    /// @return #la_status.
    la_status write_tcam_v6_key(const tcam_cell_location& location, const lpm_key_t& node_key) const;

    /// @brief Write TCAM single row key to HW.
    ///
    /// @param[in]      location        Location to write to.
    /// @param[in]      node_key        Key to write.
    ///
    /// @return #la_status.
    la_status write_tcam_v4_key(const tcam_cell_location& location, const lpm_key_t& node_key) const;

    // Members
    lpm_core_tcam_utils_akpg m_core_tcam_utils;                       ///< TCAM utils object.
    const std::array<bit_vector, NUM_TCAM_BANKS> m_ipv6_lsb_patterns; ///< IPv6 key lsb patterns in TCAM entries.
    const size_t m_tcam_size;                                         ///< Size of physical TCAM bank.
    const size_t m_tcams_per_bank;                                    ///< Number of TCAMs per bank.
    const size_t m_tcam_payload_l1_address_width;                     ///< TCAM payload field width for L1 address.
    const size_t m_tcam_payload_key_width;                            ///< TCAM payload field width for key length.
    const size_t m_tcam_payload_width;                                ///< Width for TCAM payload.
};

} // namespace silicon_one

#endif
