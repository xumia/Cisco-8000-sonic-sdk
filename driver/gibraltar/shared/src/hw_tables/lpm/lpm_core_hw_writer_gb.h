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

#ifndef __LEABA_LPM_CORE_HW_WRITER_GB_H__
#define __LEABA_LPM_CORE_HW_WRITER_GB_H__

#include "lpm_core_hw_writer_pacific_gb.h"

/// @file
namespace silicon_one
{

class lpm_core_hw_writer_gb : public lpm_core_hw_writer_pacific_gb
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct a core HW writer.
    ///
    /// @param[in]      ldevice                  Low level device.
    /// @param[in]      core_id                  Core id, unique for each core.
    /// @param[in]      l2_double_bucket_size    Number of entries in L2 double bucket.
    /// @param[in]      tcam_num_banksets        Number of allocated TCAM banksets.
    lpm_core_hw_writer_gb(const ll_device_sptr& ldevice,
                          lpm_core_id_t core_id,
                          size_t l2_double_bucket_size,
                          uint8_t tcam_num_banksets);

    // lpm_core_hw_writer API-s
    la_status write_l2_sram_buckets(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const override;
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
    lpm_core_hw_writer_gb() = default;

    // Constants: widths and borders based on LPM HW physical implementation
    enum {
        // L2 entry fields widths
        L2_ENTRY_PAYLOAD_WIDTH = 28,
        L2_ENTRY_TYPE_WIDTH = 1, // TYPE: leaf or node

        // L2 bucket non entry data fields widths
        L2_IS_NARROW_WIDTH = 1,
        L2_COUNTER_WIDTH = 4,
        L2_DEFAULT_WIDTH
        = L2_ENTRY_PAYLOAD_WIDTH, ///< default length should be the same as payload, keep for code readability later
        L2_NON_ENTRY_DATA_WIDTH = L2_IS_NARROW_WIDTH + L2_COUNTER_WIDTH + 2 * (L2_DEFAULT_WIDTH + L2_ENTRY_TYPE_WIDTH),

        // L2 bucket entries division
        L2_NUM_OF_SHARED_GROUPS = 12,
        L2_NUM_OF_SHARED_ENTRIES = L2_NUM_OF_SHARED_GROUPS * 2,

        // L2 fields borders
        L2_ENTRY_PREFIX_START = 0,
        L2_ENTRY_TYPE_START = ENTRY_ENC_PREFIX_WIDTH,
        L2_ENTRY_PAYLOAD_START = L2_ENTRY_TYPE_START + 1,
        L2_ENTRY_WIDTH = ENTRY_ENC_PREFIX_WIDTH + L2_ENTRY_TYPE_WIDTH + L2_ENTRY_PAYLOAD_WIDTH,
        L2_GROUP_WIDTH = 2 * L2_ENTRY_WIDTH + 1,
        L2_IS_DOUBLE_GROUP_WIDTH = 1,
        L2_INTERLEAVED_GROUP_WIDTH = 2 * L2_GROUP_WIDTH,

        // L2 bucket fields borders
        L2_BUCKET_ENTRY_DATA_START = 0,
        L2_BUCKET_SHARED_GROUPS_WIDTH = L2_NUM_OF_SHARED_GROUPS * L2_GROUP_WIDTH,

        NUM_BANKS_FOR_LPM_AND_EM = 32,
        L2_ALL_ENTRIES_WIDTH = NUM_BANKS_FOR_LPM_AND_EM * L2_GROUP_WIDTH,

        // L1 entry fields widths
        L1_PAYLOAD_WIDTH = 15,

        // L1 entry fields borders
        L1_IS_DOUBLE_LINE_IN_HBM_WIDTH = 1, ///< When the bit is 1 and the location is HBM it says how many lines to read from HBM.
        L1_ENTRY_WIDTH = L1_PAYLOAD_WIDTH + ENTRY_ENC_PREFIX_WIDTH + L1_IS_DOUBLE_LINE_IN_HBM_WIDTH,

        // L1 bucket non entry data fields widths
        L1_COUNTER_WIDTH = 3,
        L1_DEFAULT_HIT_TRIM_BITS_WIDTH = 8, ///< how many bits to trim from the received ip
        L1_NON_ENTRY_DATA_WIDTH
        = L1_COUNTER_WIDTH + 2 * (L1_PAYLOAD_WIDTH + L1_DEFAULT_HIT_TRIM_BITS_WIDTH + L1_IS_DOUBLE_LINE_IN_HBM_WIDTH),

        // L1 bucket entries division
        L1_NUM_OF_SHARED_ENTRIES = 4,
        L1_NUM_OF_FIXED_ENTRIES = 2,
        L1_DOUBLE_BUCKET_SIZE = L1_NUM_OF_SHARED_ENTRIES + 2 * L1_NUM_OF_FIXED_ENTRIES,
        L1_BUCKET_WIDTH = L1_NON_ENTRY_DATA_WIDTH + L1_DOUBLE_BUCKET_SIZE * L1_ENTRY_WIDTH,

        // L1 fields borders
        L1_BUCKET_SHARED_ENTRIES_END = L1_NON_ENTRY_DATA_WIDTH + L1_NUM_OF_SHARED_ENTRIES * L1_ENTRY_WIDTH,
        L1_BUCKET0_FIXED_ENTRIES_START = L1_BUCKET_SHARED_ENTRIES_END,
        L1_BUCKET1_FIXED_ENTRIES_START = L1_BUCKET_SHARED_ENTRIES_END + (L1_NUM_OF_FIXED_ENTRIES * L1_ENTRY_WIDTH),

        // HBM
        HBM_CORE_ID_WIDTH = 4,
        HBM_NUM_REPLICATIONS = 4,

        HBM_THIN_BUCKET_WIDTH = 1024,
        HBM_GROUP_WIDTH = L2_GROUP_WIDTH,
        HBM_NUM_GROUPS_PER_THIN_BUCKET = HBM_THIN_BUCKET_WIDTH / HBM_GROUP_WIDTH,

        // L2 fields borders
        HBM_GROUP_TYPE_START = 0,
        HBM_GROUP_PREFIX0_START = HBM_GROUP_TYPE_START + L2_ENTRY_TYPE_WIDTH,
        HBM_GROUP_PREFIX1_START = HBM_GROUP_PREFIX0_START + ENTRY_ENC_PREFIX_WIDTH,
        HBM_GROUP_IS_LEAF0_START = HBM_GROUP_PREFIX1_START + ENTRY_ENC_PREFIX_WIDTH,
        HBM_GROUP_PAYLOAD0_START = HBM_GROUP_IS_LEAF0_START + 1,
        HBM_GROUP_IS_LEAF1_START = HBM_GROUP_PAYLOAD0_START + L2_ENTRY_PAYLOAD_WIDTH,
        HBM_GROUP_PAYLOAD1_START = HBM_GROUP_IS_LEAF1_START + 1,
        IS_HBM_OFFSET = 20,
    };

#pragma pack(push, 1)
    /// @brief Auxiliary structure to hold L1 non-entry data.
    struct l1_hw_line {
        uint64_t counter : L1_COUNTER_WIDTH;
        uint64_t bucket0_default : L1_PAYLOAD_WIDTH;
        uint64_t bucket0_bits_to_trim : L1_DEFAULT_HIT_TRIM_BITS_WIDTH;
        bool bucket0_hbm_lines : L1_IS_DOUBLE_LINE_IN_HBM_WIDTH;
        uint64_t bucket1_default : L1_PAYLOAD_WIDTH;
        uint64_t bucket1_bits_to_trim : L1_DEFAULT_HIT_TRIM_BITS_WIDTH;
        bool bucket1_hbm_lines : L1_IS_DOUBLE_LINE_IN_HBM_WIDTH;
        uint64_t flat_entries0 : 64;
        uint64_t flat_entries1 : 64;
        uint64_t flat_entries2 : 64;
        uint64_t flat_entries3 : 64;
        uint64_t flat_entries4 : 64 - L1_NON_ENTRY_DATA_WIDTH;

        inline operator bit_vector()
        {
            uint64_t* storage = (uint64_t*)this;
            return bit_vector(storage, L1_BUCKET_WIDTH);
        }
    } data_struct = {0};
    CEREAL_SUPPORT_PRIVATE_CLASS(l1_hw_line)

    /// @brief Auxiliary data to hold L1 entry.
    /// Entry structure is: payload is_leaf prefix (msb .. lsb).
    union l1_entry_data {
        struct field_data {
            size_t payload : L1_PAYLOAD_WIDTH;
            size_t prefix : ENTRY_ENC_PREFIX_WIDTH;
            bool double_line_in_hbm : L1_IS_DOUBLE_LINE_IN_HBM_WIDTH;
        };

        field_data fields;
        size_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l1_entry_data)
    CEREAL_SUPPORT_PRIVATE_CLASS(l1_entry_data::field_data)

    /// @brief Auxiliary structure to hold L2 non-entry data.
    union l2_sram_non_entry_data {
        struct data_struct_s {
            bool is_double : L2_IS_NARROW_WIDTH;
            size_t counter : L2_COUNTER_WIDTH;
            size_t bucket0_default_is_leaf : L2_ENTRY_TYPE_WIDTH;
            size_t bucket0_default : L2_DEFAULT_WIDTH;
            size_t bucket1_default_is_leaf : L2_ENTRY_TYPE_WIDTH;
            size_t bucket1_default : L2_DEFAULT_WIDTH;
        } data_struct;

        uint64_t flat;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_non_entry_data)
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_non_entry_data::data_struct_s)

    /// @brief Auxiliary data to hold L2 entry.
    /// Entry structure is: payload is_leaf prefix (msb .. lsb).
    union l2_group_data {
        struct data_struct {
            bool is_double : L2_IS_DOUBLE_GROUP_WIDTH;
            size_t prefix0 : ENTRY_ENC_PREFIX_WIDTH;
            size_t is_leaf0 : L2_ENTRY_TYPE_WIDTH;
            size_t payload0 : L2_ENTRY_PAYLOAD_WIDTH;
            size_t prefix1 : ENTRY_ENC_PREFIX_WIDTH;
            size_t is_leaf1 : L2_ENTRY_TYPE_WIDTH;
            size_t payload1 : L2_ENTRY_PAYLOAD_WIDTH;
        };

        data_struct fields;
        uint64_t flat[2];
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_group_data)
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_group_data::data_struct)
#pragma pack(pop)

    /// @brief Auxiliary data to hold L2 entries.
    struct l2_sram_line {
        l2_sram_non_entry_data non_entry_data;
        bit_vector entry_data;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(l2_sram_line)

    /// @brief CDB core resources needed to write LPM core (specific to GB).
    struct cdb_core_resources_gb {
        lld_register_array_sptr lpm_rd_mod_wr_group_data_reg; ///
        lld_register_scptr accessed_buckets_wr;               ///< Read and clear L2 SRAM access bit.
        lld_register_array_sptr accessed_buckets_status_reg;  ///< Access bit for L2 SRAM buckets.
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cdb_core_resources_gb)

    /// @brief Write L2 double bucket to HW via rd_mod_wrt mechanism.
    ///
    /// @param[in]      row             Row of double bucket to write.
    /// @param[in]      hw_l2_line      Double bucket to write.
    ///
    /// @return #la_status.
    la_status write_l2_sram_line(lpm_bucket_index_t row, const l2_sram_line& hw_l2_line) const;

    /// @brief Write L2 bucket to HBM.
    ///
    /// @param[in]      hw_index        HW index of L2 bucket to write.
    /// @param[in]      hbm_line_data   Bucket to write.
    ///
    /// @return #la_status.
    la_status write_l2_hbm_line(size_t hw_index, const std::array<bit_vector, 2>& hbm_line_data) const;

    /// @brief Set the default of L2 SRAM bucket.
    ///
    /// @param[in,out]  hw_bucket_data      HW bucket to set entry to.
    /// @param[in]      bucket_idx          Indication where this is even/odd bucket.
    /// @param[in]      default_payload     Default payload of the bucket.
    /// @param[in]      is_leaf             Default node is leaf.
    void set_l2_sram_default(l2_sram_line& hw_bucket_data, size_t bucket_idx, lpm_payload_t default_payload, bool is_leaf) const;

    /// @brief Write data to HBM memory.
    ///
    /// @param[in]     hbm_location         Physical address where to write the data.
    /// @param[in]     data                 Data to write.
    la_status write_hbm_data(const hbm_physical_location& hbm_location, const bit_vector& data) const;

    /// @brief Convert two complementing L1 buckets to a bit vector representing HW double bucket.
    ///
    /// @param[in]      bucket0         First bucket.
    /// @param[in]      bucket1         Second bucket.
    ///
    /// @return HW double bucket line as a l1_hw_line struct.
    l1_hw_line generate_l1_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const;

    /// @brief Generate L1 bucket entry.
    ///
    /// @param[in]  bucket      L1 bucket of nodes to read data from.
    /// @param[in]  root_width  Width of the L1 bucket root.
    ///
    /// @return  Struct describing L1 entry.
    l1_entry_data generate_l1_entry_data(const lpm_nodes_bucket* bucket, size_t l1_root_width) const;

    /// @brief  Set data about L1 bucket into ouput buffer.
    ///
    /// @param[in,out]   line_entry_data   Pointer to ouput buffer.
    /// @param[in]       l1_entry          Structure containing data to be put on output buffer.
    /// @param[in]       entry_idx         Index of fixed entry for current L2 bucket to be written.
    /// @param[in,out]   shared_entry_idx  Index of shared entry.
    /// @param[in]       bucket_idx        L1 bucket index.
    void set_l1_sram_line_entry(uint64_t* line_entry_data,
                                const l1_entry_data& l1_entry,
                                size_t entry_idx,
                                size_t& shared_entry_idx,
                                size_t bucket_idx) const;

    /// @brief  Generate non entry data of two complementary L1 buckets.
    ///
    /// @param[in,out]  l1_sram_line        Pointer to ouput structure.
    /// @param[in]      bucket0             L1 bucket with even index.
    /// @param[in]      bucket1             L1 bucket with odd index.
    /// @param[in]      default_counter     Default counter.
    void set_l1_defaults(l1_hw_line& l1_sram_line,
                         const lpm_bucket* bucket0,
                         const lpm_bucket* bucket1,
                         size_t default_counter) const;

    /// @brief Convert two complementing L2 buckets to a bit vector representing HW double bucket.
    ///
    /// @param[in]      bucket0         First bucket.
    /// @param[in]      bucket1         Second bucket.
    /// @param[out]     hw_bucket_data  Structure containing lines to be written on hardware.
    ///
    /// @return HW double bucket as a bit vector.
    l2_sram_line generate_l2_sram_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const;

    /// @brief Convert L2 bucket to a bit vector according HBM line formatting.
    ///
    /// @param[in]      bucket          L2 bucket.
    ///
    /// @return array of bit_vectors representing HBM fat line.
    std::array<bit_vector, 2> generate_l2_hbm_bucket(const lpm_bucket* bucket) const;

    /// @brief Set node's data in the correct place within HBM bucket's row vector.
    ///
    /// @param[in]      key             Prefix to set.
    /// @param[in]      payload         Payload to set.
    /// @param[in]      is_leaf         Is node corresponding to key leaf.
    /// @param[in]      root_width      Root width of bucket.
    /// @param[in]      node_idx        Index of node within HBM bucket.
    /// @param[out]     bucket_bits     Bits representing (both parts of) HBM bucket.
    void set_node_in_hbm_bucket(const lpm_key_t& key,
                                lpm_payload_t payload,
                                bool is_leaf,
                                size_t root_width,
                                size_t node_idx,
                                std::array<bit_vector, 2>& bucket_bits) const;

    /// @brief Log L1 double bucket.
    ///
    /// @param[in] hw_row     Hardware row.
    /// @param[in] bucket0    First bucket.
    /// @param[in] bucket1    Second bucket.
    /// @param[in] hw_bucket  Structure containing line to be written on hardware.
    void log_l1_double_bucket(lpm_bucket_index_t hw_row,
                              const lpm_bucket* bucket0,
                              const lpm_bucket* bucket1,
                              const bit_vector& hw_bucket) const;

    /// @brief Log L2 double bucket.
    ///
    /// @param[in] hw_row     Hardware row.
    /// @param[in] bucket0    First bucket.
    /// @param[in] bucket1    Second bucket.
    /// @param[in] hw_bucket  Structure containing lines to be written on hardware.
    void log_l2_double_bucket(lpm_bucket_index_t hw_row,
                              const lpm_bucket* bucket0,
                              const lpm_bucket* bucket1,
                              const l2_sram_line& hw_bucket_data) const;

    /// @brief convert bit vector to a vector of indexes.
    ///
    /// @param[in]        bv                Bit vector.
    /// @param[in]        start_index       What index does bv[0] represent.
    /// @param[in,out]    bucket_indexes    Bucket indexes (appended to current value of this vector).
    void bit_vector_to_bucket_indexes(bit_vector& bv, size_t start_index, vector_alloc<size_t>& out_bucket_indexes) const;

    /// @brief Extract group data from bit vector.
    ///
    /// @param[in]  group_bv              Group bit vector.
    /// @param[in]  bits_between_entries  Bits between entries in interleaved groups.
    /// @param[out] out_group             Structure holding extracted fields.
    void get_shared_group_for_log(const bit_vector& group_bv, size_t bits_between_entries, l2_group_data& out_group) const;

    /// @brief Logs groups of L2 buckets.
    ///
    /// @param[in] hw_bucket_data        Structure containing data to be logged.
    /// @param[in] group_name            Tells whether the group is shared or interleaved.
    /// @param[in] group_start           LSB of first group in hw_bucket_data.
    /// @param[in] group_end             MSB of last group in hw_bucket_data.
    /// @param[in] bits_between_entries  Bits between entries in interleaved groups.
    void log_l2_groups(const l2_sram_line& hw_bucket_data,
                       const char* group_name,
                       int group_start,
                       int group_end,
                       int bits_between_entries = 0) const;

    /// @brief Decide if node should be marked as a leaf node when writing bucket to hardware.
    ///
    /// @param[in]      node            Node to check.
    ///
    /// @return Is the node a leaf node.
    bool is_mark_as_leaf(const lpm_node* node) const;

    /// @brief Generate group data for double entry.
    ///
    /// @param[in]  node        Node with double entry.
    /// @param[in]  root_width  Bucket root width.
    /// @param[in]  is_leaf     Is node leaf of bucket.
    /// @param[out] out_group   L2 group holder.
    void generate_group_from_double_l2_entry(const lpm_node* node, size_t root_width, bool is_leaf, l2_group_data& out_group) const;

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

    /// @brief Write a group in right place inside line_entry_data.
    ///
    /// @param[in]         line_entry_data   Pointer to buffer in which group is to be written.
    /// @param[in]         group             Group to write.
    /// @param[in]         bucket_idx        Bucket hardware index % 2.
    /// @param[in,out]     group_idx         Group index.
    /// @param[in,out]     shared_group_idx  Index of group in shared part.
    void set_l2_sram_line_group(uint64_t* line_entry_data,
                                const l2_group_data& group,
                                size_t bucket_idx,
                                size_t& group_idx,
                                size_t& shared_group_idx) const;

    /// @brief Write all fields of interleaved group into buffer.
    ///
    /// @param[in] line_entry_data       Pointer to buffer in which group is to be written.
    /// @param[in] lsb                   Least significand byte from which to begin writing.
    /// @param[in] l2_group_data         Group structure to be written.
    /// @param[in] bits_between_entries  In interleaved groups there are unused bits between entries.
    void set_l2_sram_line_interleaved_group_bits(uint64_t* line_entry_data,
                                                 size_t lsb,
                                                 const l2_group_data& group,
                                                 size_t bits_between_entries) const;

private:
    // members
    size_t m_l2_bucket_width;                  ///< L2 bucket width (HW line width).
    size_t m_l2_bucket_num_interleaved_groups; ///< Maximum interleaved groups in L2 bucket.
    size_t m_l2_all_groups_width;              ///< Width of all groups in L2 line.
    bool m_use_fat_hbm_buckets;                ///< Whether to use fat HBM buckets (256B).
    cdb_core_resources_gb m_cdb_core_gb;       ///< Relevant cdb core resources.
};

} // namespace silicon_one

#endif
