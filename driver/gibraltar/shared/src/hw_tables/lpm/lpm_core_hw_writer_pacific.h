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

#ifndef __LEABA_LPM_CORE_HW_WRITER_PACIFIC_H__
#define __LEABA_LPM_CORE_HW_WRITER_PACIFIC_H__

#include "lpm_core_hw_writer_pacific_gb.h"
/// @file

namespace silicon_one
{

class lpm_core_hw_writer_pacific : public lpm_core_hw_writer_pacific_gb
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct a core HW writer.
    ///
    /// @param[in]      ldevice                  Low level device
    /// @param[in]      core_id                  Core id, unique for each core.
    /// @param[in]      l2_double_bucket_size    Number of entries in L2 double bucket.
    /// @param[in]      num_tcam_banksets        Number of allocated TCAM banksets.
    /// @param[in]      trap_destination         Payload of destination to raise a trap.
    /// @param[in]      hbm_address_offset       HBM start address.
    lpm_core_hw_writer_pacific(const ll_device_sptr& ldevice,
                               lpm_core_id_t core_id,
                               size_t l2_double_bucket_size,
                               uint8_t num_tcam_banksets,
                               lpm_payload_t trap_destination,
                               size_t hbm_address_offset);

    // lpm_core_hw_writer API-s
    la_status write_l2_sram_buckets(const lpm_bucket* bucket, const lpm_bucket* neighbor_bucket) const override;
    la_status write_l2_hbm_bucket(const lpm_bucket* bucket) const override;
    std::vector<lpm_entry> read_l2_bucket(size_t hw_index, size_t& out_default_payload) const override;
    la_status write_l1_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const override;
    std::vector<lpm_entry> read_l1_bucket(size_t hw_index, size_t& out_default_payload) const override;
    la_status read_index_of_last_accessed_l2_sram_buckets(vector_alloc<size_t>& out_bucket_indexes) override;
    la_status calculate_bucket_location_in_hbm(size_t hw_index,
                                               size_t repl_idx,
                                               hbm_physical_location& out_hbm_location) const override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_core_hw_writer_pacific() : m_revision(), m_hbm_address_offset()
    {
    }

    // Constants: widths and borders based on LPM HW physical implementation
    enum {
        L1_TRAP_LINE = 0,

        // L2 entry fields widths
        L2_ENTRY_PAYLOAD_WIDTH = 20,
        L2_ENTRY_TYPE_WIDTH = 1,

        // L2 bucket non entry data fields widths
        L2_COUNTER_WIDTH = 4,
        L2_DEFAULT_WIDTH = L2_ENTRY_PAYLOAD_WIDTH,
        L2_NON_ENTRY_DATA_WIDTH = 2 * L2_DEFAULT_WIDTH + L2_COUNTER_WIDTH,

        // L2 bucket entries division
        L2_NUM_OF_SHARED_ENTRIES = 14,

        // L2 fields borders
        L2_ENTRY_PAYLOAD_START = 0,
        L2_ENTRY_PREFIX_START = L2_ENTRY_PAYLOAD_START + L2_ENTRY_PAYLOAD_WIDTH,
        L2_ENTRY_TYPE_START = L2_ENTRY_PREFIX_START + ENTRY_ENC_PREFIX_WIDTH,
        L2_ENTRY_WIDTH = L2_ENTRY_TYPE_START + L2_ENTRY_TYPE_WIDTH,

        // L2 bucket fields borders
        L2_BUCKET_SHARED_ENTRIES_END = L2_NON_ENTRY_DATA_WIDTH + L2_NUM_OF_SHARED_ENTRIES * L2_ENTRY_WIDTH,

        // L1 entry fields widths
        L1_ENTRY_FULLNESS_WIDTH = 2,
        L1_ENTRY_ID_WIDTH = 15,

        // L1 entry fields borders
        L1_ENTRY_FULLNESS_START = 0,
        L1_ENTRY_ID_START = L1_ENTRY_FULLNESS_START + L1_ENTRY_FULLNESS_WIDTH,
        L1_ENTRY_PREFIX_START = L1_ENTRY_ID_START + L1_ENTRY_ID_WIDTH,
        L1_ENTRY_WIDTH = L1_ENTRY_PREFIX_START + ENTRY_ENC_PREFIX_WIDTH,

        // L1 entry fullness value
        L1_ENTRY_FULLNESS_VALUE = 0,

        // L1 bucket non entry data fields widths
        L1_COUNTER_WIDTH = 3,
        L1_DEFAULT_WIDTH = L2_DEFAULT_WIDTH,
        L1_NON_ENTRY_DATA_WIDTH = L1_COUNTER_WIDTH + 2 * L1_DEFAULT_WIDTH,

        // L1 bucket entries division
        L1_NUM_OF_SHARED_ENTRIES = 4,
        L1_NUM_OF_FIXED_ENTRIES = 2,
        L1_DOUBLE_BUCKET_SIZE = L1_NUM_OF_SHARED_ENTRIES + 2 * L1_NUM_OF_FIXED_ENTRIES,
        L1_BUCKET_WIDTH = L1_NON_ENTRY_DATA_WIDTH + L1_DOUBLE_BUCKET_SIZE * L1_ENTRY_WIDTH,

        // L1 fields borders
        L1_BUCKET_SHARED_ENTRIES_END = L1_NON_ENTRY_DATA_WIDTH + L1_NUM_OF_SHARED_ENTRIES * L1_ENTRY_WIDTH,

        // HBM
        HBM_CORE_ID_WIDTH = 4,
        HBM_NUM_REPLICATIONS = 4,
        HBM_NUM_SECTIONS = 4,
        HBM_NUM_ENTRIES = 24,
        HBM_NUM_ENTRIES_IN_SECTION = HBM_NUM_ENTRIES / HBM_NUM_SECTIONS,
        HBM_NUM_CHANNELS = 8,
        HBM_SECTION_WIDTH = 256,
        HBM_LINE_WIDTH = HBM_NUM_SECTIONS * HBM_SECTION_WIDTH,

        // L2 fields borders
        HBM_ENTRY_PREFIX_START = 0,
        HBM_ENTRY_PAYLOAD_START = HBM_ENTRY_PREFIX_START + ENTRY_ENC_PREFIX_WIDTH,
        HBM_ENTRY_IS_DEFAULT_START = HBM_ENTRY_PAYLOAD_START + L2_ENTRY_PAYLOAD_WIDTH
                                     - 1, // Payload's MSB (must be consistent with NPL's encoding of defaults)
        HBM_ENTRY_TYPE_START = HBM_ENTRY_PAYLOAD_START + L2_ENTRY_PAYLOAD_WIDTH,
        HBM_ENTRY_WIDTH = L2_ENTRY_WIDTH,
    };

    /// @brief Constants related to LPM hardware
    enum {
        LPM_DOUBLE_ENTRY_PAYLOAD_ENCODING = 0xfffff, ///< Special compressed encoding indicating a double entry (5 MSBs must be 1s)
    };

#pragma pack(push, 1)

    union l2_sram_non_entry_data {
        struct data_struct_s {
            size_t bucket1_shared_entries : L2_COUNTER_WIDTH;
            size_t bucket0_default : L2_DEFAULT_WIDTH;
            size_t bucket1_default : L2_DEFAULT_WIDTH;
        } data_struct;

        size_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_non_entry_data)
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_non_entry_data::data_struct_s)

    struct l2_sram_line {
        l2_sram_non_entry_data non_entry_data;
        bit_vector entry_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_line)

    struct l2_sram_single_entry {
        size_t payload : L2_ENTRY_PAYLOAD_WIDTH;
        size_t key : ENTRY_ENC_PREFIX_WIDTH;
        size_t non_leaf : L2_ENTRY_TYPE_WIDTH;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_single_entry)

    struct l2_sram_double_entry {
        size_t double_entry_enc : L2_ENTRY_PAYLOAD_WIDTH + 1;
        size_t msb_key : ENTRY_PREFIX_WIDTH;
        size_t non_leaf0 : L2_ENTRY_TYPE_WIDTH;
        size_t payload : L2_ENTRY_PAYLOAD_WIDTH;
        size_t lsb_key : ENTRY_ENC_PREFIX_WIDTH;
        size_t non_leaf1 : L2_ENTRY_TYPE_WIDTH;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_double_entry)

    struct l2_hbm_entry {
        size_t key : ENTRY_ENC_PREFIX_WIDTH;
        size_t payload : L2_ENTRY_PAYLOAD_WIDTH;
        size_t non_leaf : L2_ENTRY_TYPE_WIDTH;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_hbm_entry)

    union hbm_hw_index_data {
        struct field_data {
            size_t bucket_bank_channel : 8;
            size_t bucket_row : 7;
            size_t bucket_column : 4;
        };

        field_data fields;
        size_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(hbm_hw_index_data)
    CEREAL_SUPPORT_PRIVATE_CLASS(hbm_hw_index_data::field_data)

    union hbm_bank_channel_data {
        enum {
            LSB_WIDTH = 2,
        };

        struct field_data {
            size_t channel : 4;
            size_t bank_msb : 2;
            size_t bank_lsb : 2;
        };

        field_data fields;
        size_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(hbm_bank_channel_data)
    CEREAL_SUPPORT_PRIVATE_CLASS(hbm_bank_channel_data::field_data)

    union channel_info {
        struct field_data {
            size_t cpu : 1;
            size_t index : 3;
            size_t padding : 60;
        };

        field_data fields;
        size_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(channel_info)
    CEREAL_SUPPORT_PRIVATE_CLASS(channel_info::field_data)

#pragma pack(pop)

    /// @brief CDB core Pacific resources needed to write LPM core.
    struct cdb_core_resources_pacific {
        lld_register_array_scptr lpm_rd_mod_wr_entry_regs; ///< L2 entries 2-44.
        lld_register_scptr lpm_rd_mod_wr_entry_0_1_reg;    ///< L2 entries 0-1.
        lld_register_scptr lpm_last_shared_sram_ptr_reg;   ///< L2 last accessed SRAM row
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cdb_core_resources_pacific)

    /// @brief Write L2 double bucket to HW via rd_mod_wrt mechanism.
    ///
    /// @param[in]      row             Row of double bucket to write.
    /// @param[in]      hw_bucket       Double bucket to write.
    ///
    /// @return #la_status.
    la_status write_l2_sram_line(lpm_bucket_index_t row, const l2_sram_line& hw_bucket_st) const;

    /// @brief Write L2 bucket to HBM.
    ///
    /// @param[in]      hw_index        HW index of L2 bucket to write.
    /// @param[in]      hbm_line_data   Bucket to write.
    ///
    /// @return #la_status.
    la_status write_l2_hbm_line(size_t hw_index, const bit_vector& hbm_line_data) const;

    /// @brief Convert two complementing L1 buckets to a bit vector representing HW double bucket.
    ///
    /// @param[in]      bucket0         First bucket.
    /// @param[in]      bucket1         Second bucket.
    ///
    /// @return HW double bucket as a bit vector.
    bit_vector generate_l1_bucket(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const;

    /// @brief Convert two complementing L2 buckets to a struct representing HW double bucket.
    ///
    /// @param[in]      bucket                  Bucket to write.
    /// @param[in]      neighbor_bucket         Complementary bucket.
    ///
    /// @return HW double bucket as a l2_sram_line.
    l2_sram_line generate_l2_sram_line(const lpm_bucket* bucket, const lpm_bucket* neighbor_bucket) const;

    /// @brief Convert L2 bucket to a bit vector according HBM line formatting.
    ///
    /// @param[in]      bucket          L2 bucket.
    ///
    /// @return bit vector representing HBM line.
    bit_vector generate_l2_hbm_bucket(const lpm_bucket* bucket) const;

    /// @brief Log L1/L2 double bucket.
    void log_double_bucket(lpm_bucket_index_t hw_row,
                           const lpm_bucket* bucket0,
                           const lpm_bucket* bucket1,
                           const bit_vector& hw_bucket,
                           bool l2) const;

    /// @brief Sort bucket's nodes vector such that double entries are before single entries.
    ///
    /// This helps the L2 bucket generation, since double entries should be handled carefully.
    ///
    /// @param[in,out]  nodes           Nodes vector to sort.
    /// @param[in]      root_width      Width of the bucket root entry.
    ///
    /// @return Index of first single entry in vector.
    size_t sort_nodes_for_l2_bucket_generation(vector_alloc<lpm_node*>& nodes, size_t root_width) const;

    /// @brief Set entry in L1 HW bucket.
    ///
    /// @param[in,out]  hw_bucket       HW bucket to set entry to.
    /// @param[in]      offset          Offset in HW bucket to start writing from.
    /// @param[in]      key_payload     Entry struct containing key/payload.
    /// @param[in]      root_width      Bucket's root width.
    void set_entry_in_l1_bucket(bit_vector& hw_bucket, size_t offset, const lpm_key_payload& key_payload, size_t root_width) const;

    /// @brief Create single entry in L2 bucket which located in SRAM.
    ///
    /// @param[in]      node            Node containing the required entry.
    /// @param[in]      prefix_width    Prefix's width as it's written in the bucket.
    ///
    /// @return Struct describig L2 single entry.
    l2_sram_single_entry generate_single_sram_entry(const lpm_node* node, size_t prefix_width) const;

    /// @brief Create double entry in L2 bucket which located in SRAM.
    ///
    /// @param[in]      node            Node containing the required entry.
    /// @param[in]      prefix_width    Prefix's width as it's written in the bucket.
    ///
    /// @return Struct describig L2 double entry.
    l2_sram_double_entry generate_double_entry(const lpm_node* node, size_t prefix_width) const;

    /// @brief Create entry in L2 bucket which located in HBM.
    ///
    /// @param[in]      node            Node containing the required entry.
    /// @param[in]      root_width      Bucket's root width.
    ///
    /// @return Struct describig L2 single entry.
    l2_hbm_entry generate_hbm_entry(const lpm_node* node, size_t prefix_width) const;

    /// @brief Set single entry in L2 HW bucket.
    ///
    /// @param[in,out]  line_entry_data     HW line to set entry to.
    /// @param[in]      entry_idx           Entry index.
    /// @param[in]      bucket_idx          Indication where this is even/odd bucket.
    /// @param[in]      val                 Value to write to the entry.
    void set_l2_sram_line_entry(uint64_t* line_entry_data,
                                size_t entry_idx,
                                size_t bucket_idx,
                                const l2_sram_single_entry& val) const;

    /// @brief Set single entry in L2 HW bucket.
    ///
    /// @param[in,out]  line_entry_data     HW line to set entry to.
    /// @param[in]      entry_idx           Entry index.
    /// @param[in]      val                 Value to write to the entry.
    void set_l2_hbm_line_entry(uint64_t* line_entry_data, size_t entry_idx, const l2_hbm_entry& val) const;

    /// @brief Encode key+length to HW value.
    ///
    /// @param[in]      prefix_value        Key bits.
    /// @param[in]      length              Key length.
    size_t encode_key_length(size_t prefix_value, size_t length) const;

    /// @brief Set double entry in L2 HW bucket.
    ///
    /// @param[in,out]  line_entry_data HW line to set entry to.
    /// @param[in]      field           Field index.
    /// @param[in]      bucket_idx      Indicaset_line_double_entrytion where this is even/odd bucket.
    /// @param[in]      val             Value to write to the entry.
    void set_line_double_entry(uint64_t* line_entry_data, size_t field, size_t bucket_idx, const l2_sram_double_entry& val) const;

    /// @brief Generate bucket for bucket with 1 zero-length entry which is a leaf.
    ///
    /// @param[in,out]  hw_bucket_data  HW bucket to set entry to.
    /// @param[in]      bucket_idx      Indication where this is even/odd bucket.
    /// @param[in]      node            Node containing the only entry in this bucket.
    void handle_leaf_default_for_empty_sram_bucket(uint64_t* line_entry_data, size_t bucket_idx, const lpm_node* node) const;

    /// @brief Generate bucket for bucket with 1 zero-length entry which is a leaf.
    ///
    /// @param[in,out]  hw_bucket_data  HW bucket to set entry to.
    /// @param[in]      node            Node containing the only entry in this bucket.
    void handle_leaf_default_for_empty_hbm_bucket(uint64_t* line_entry_data, const lpm_node* node) const;

    /// @brief Generate the default of L2 SRAM bucket.
    ///
    /// @param[in,out]  hw_bucket_data      HW bucket to set entry to.
    /// @param[in]      bucket_idx          Indication where this is even/odd bucket.
    /// @param[in]      default_payload     Default payload of the bucket.
    void set_l2_sram_default(l2_sram_line& hw_bucket_data, size_t bucket_idx, lpm_payload_t default_payload) const;

    /// @brief Generate the default of L2 HBM bucket.
    ///
    /// @param[in,out]  hw_bucket_data      HW bucket to set entry to.
    /// @param[in]      default_payload     Default payload of the bucket.
    void set_hbm_default(uint64_t* line_entry_data, lpm_payload_t default_payload) const;

    /// @brief Generate entry for L1 HW bucket.
    ///
    /// @param[in]      key_payload     Entry struct containing key/payload.
    /// @param[in]      root_width      Bucket's root width.
    ///
    /// @return L1 entry as a bit vector.
    bit_vector64_t generate_l1_entry(const lpm_key_payload& key_payload, size_t root_width) const;

    /// @brief Auxiliary data to collect from L1 bucket.
    struct l1_bucket_data {
        lpm_key_payload_vec entries;
        size_t root_width = 0;
        lpm_key_payload zero_width_entry;
        bool has_zero_width_entry = false;
        size_t num_shared_entries = 0;
        size_t num_interleaved_entries = 0;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l1_bucket_data)
    l1_bucket_data init_l1_bucket_data(const lpm_bucket* bucket) const;

    /// @brief Decide if node should be marked as a leaf node when writing bucket to hardware.
    ///
    /// @param[in]      node            Node to check
    /// @param[in]      is_hbm          Is node to be written to HBM
    ///
    /// @return Is the node a leaf node.
    bool is_mark_as_leaf(const lpm_node* node, bool is_hbm) const;

    /// @brief decide if L2 node should be marked as "is_default"
    ///
    /// @param[in]      l2_node          Node to check
    ///
    /// @return Whether node should have is_default bit sit
    bool should_force_is_default(const lpm_node* l2_node) const;

private:
    // members
    size_t m_l2_bucket_width;      ///< L2 bucket width (HW line width).
    size_t m_l2_num_fixed_entries; ///< Number of fixed entries in HW line for one L2 bucket.
    bool m_is_full_core;           ///< Is this a full core.
    bit_vector
        m_l1_trap_hw_bucket; ///< L1 bucket to write L1 SRAM line 0 in order to receive L2 buble and also contains default trap
    cdb_core_resources_pacific m_cdb_core_pacific;
    const la_device_revision_e m_revision; ///< Current device revision
    const size_t m_hbm_address_offset;     ///< Address offset of indexes in HBM.
};

} // namespace silicon_one

#endif
