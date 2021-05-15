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

#ifndef __LEABA_LPM_CORE_HW_WRITER_H__
#define __LEABA_LPM_CORE_HW_WRITER_H__

#include "common/la_status.h"

#include "lld/lld_memory.h"
#include "lld/lld_register.h"

#include "hw_tables/hw_tables_fwd.h"
#include "lpm_common.h"
#include "lpm_core_tcam.h"
#include "lpm_hw_writer_consistency_checker.h"
#include "lpm_internal_types.h"

/// @file

namespace silicon_one
{

class ll_device;

struct lpm_tcam_node;
class lpm_bucket;

/// @brief A representation of LPM entry in TCAM, L1 and L2.
///
/// Consists of a prefix, stored at the particular level and its payload.
/// To construct the complete LPM key, prefixes of TCAM, L1 and L2 should be concatenated.
struct lpm_entry {
    lpm_entry() : is_ipv6(false), is_wide_entry(false), valid(false), is_l2_leaf(false)
    {
    }

    size_t index = 0;
    bit_vector prefix;
    size_t prefix_width;
    size_t payload;
    bool is_ipv6;
    bool is_wide_entry;
    bool valid;
    bool is_l2_leaf;
};

/// @brief HBM specific bucket location.
struct hbm_physical_location {
    size_t bank;
    size_t channel;
    size_t row;
    size_t column;
};

class lpm_core_hw_writer
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Destruct core HW writer.
    virtual ~lpm_core_hw_writer();

    /// @brief Get device of this LPM core hardware writer.
    ///
    /// @return ll_device_sptr of the writer's device.
    const ll_device_sptr& get_ll_device() const;

    /// @brief Write L2 double bucket to the SRAM.
    ///
    /// @param[in]      bucket0         First bucket.
    /// @param[in]      bucket1         Second bucket.
    ///
    /// @return #la_status.
    virtual la_status write_l2_sram_buckets(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const = 0;

    /// @brief Write L2 bucket to the HBM.
    ///
    /// @param[in]      bucket         Bucket to write.
    ///
    /// @return #la_status.
    virtual la_status write_l2_hbm_bucket(const lpm_bucket* bucket) const = 0;

    /// @brief Given hw_index and replica calculates the actual physical location in terms of bank/channel/row/column.
    ///
    /// @param[in]      hw_index                HW index of the bucket.
    /// @param[in]      repl_idx                Replica index.
    /// @param[out]     out_hbm_location        HBM location of the bucket with the given hw_index in the given replication.
    ///
    /// @return #la_status.
    virtual la_status calculate_bucket_location_in_hbm(size_t hw_index,
                                                       size_t repl_idx,
                                                       hbm_physical_location& out_hbm_location) const;

    /// @brief Read L2 bucket from HW.
    ///
    /// @param[in]      hw_index                HW index representing L2 row and bucket
    ///                                         hw_index = 2 * row + (bucket index).
    /// @param[out]     out_default_payload     Default payload of bucket.
    ///
    /// @return list of bucket entries.
    virtual std::vector<lpm_entry> read_l2_bucket(size_t hw_index, size_t& out_default_payload) const = 0;

    /// @brief Write L1 double bucket to HW according to bucket and its complementary.
    ///
    /// @param[in]      bucket0         First bucket.
    /// @param[in]      bucket1         Second bucket.
    ///
    /// @return #la_status.
    virtual la_status write_l1_line(const lpm_bucket* bucket0, const lpm_bucket* bucket1) const = 0;

    /// @brief Read L1 bucket from HW.
    ///
    /// @param[in]      hw_index                HW index representing L1 row and bucket
    ///                                         hw_index = 2 * row + (bucket index).
    /// @param[out]     out_default_payload     Default payload of bucket.
    ///
    /// @return list of bucket entries.
    virtual std::vector<lpm_entry> read_l1_bucket(size_t hw_index, size_t& out_default_payload) const = 0;

    /// @brief Write a TCAM block to HW.
    ///
    /// @param[in]      location              Block location to write to.
    /// @param[in]      key                   Key to write to TCAM.
    /// @param[in]      payload               TCAM payload.
    /// @param[in]      only_update_payload   Don't touch key and mask, only modify payload.
    ///
    /// @return #la_status.
    virtual la_status write_tcam(const tcam_cell_location& location,
                                 const lpm_key_t& key,
                                 lpm_payload_t payload,
                                 bool only_update_payload) const = 0;

    /// @brief Invalidate TCAM block in HW.
    ///
    /// @param[in]      location               Block location to invalidate.
    ///
    /// @return #la_status.
    virtual la_status invalidate_tcam(const tcam_cell_location& location, const lpm_key_t& key) = 0;

    /// @brief Read TCAM block from HW.
    ///
    /// @param[in]      location                Block location to read.
    ///
    /// @return entry stored in the row.
    virtual lpm_entry read_tcam(const tcam_cell_location& location) const = 0;

    /// @brief Writes "catch all" rows to TCAM banks.
    /// TCAM miss causes HW to lose LPM request credits. Misses can happend due to user misconfiguration or HW bugs.
    /// In any case, this protection is needed to prevent HW to get stuck.
    ///
    /// @return #la_status.
    virtual la_status write_tcam_default_row() const = 0;

    /// @brief Read last accessed L2 SRAM buckets.
    ///
    /// @param[out]      out_bucket_indexes        Last accessed L2 buckets.
    ///
    /// @return #la_status.
    virtual la_status read_index_of_last_accessed_l2_sram_buckets(vector_alloc<size_t>& out_bucket_indexes) = 0;

    /// @brief Translate a TCAM location into a flat row.
    ///
    /// @param[in]     location         TCAM location.
    ///
    /// @return TCAM row.
    size_t tcam_location_to_row(const tcam_cell_location& location) const;

    /// @brief Translate a TCAM flat row into a location.
    ///
    /// @param[in]     row              TCAM row.
    ///
    /// @return TCAM location.
    tcam_cell_location tcam_row_to_location(size_t row) const;

protected:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_core_hw_writer() : m_core_id(), m_num_cells_per_bankset(), m_tcam_bank_size()
    {
    }

    enum {
        // Same for L1 and L2
        ENTRY_PREFIX_WIDTH = 16,
        ENTRY_ENC_PREFIX_WIDTH = ENTRY_PREFIX_WIDTH + 1,

        TCAM_ROW_WIDTH = 40,
    };

    /// @brief Construct a core HW writer.
    ///
    /// @param[in]      ldevice                  Low level device
    /// @param[in]      core_id                  Core id, unique for each core.
    /// @param[in]      num_tcam_banksets        Number of allocated TCAM banksets.
    /// @param[in]      num_cells_per_bankset    Number of cells per bankset.
    /// @param[in]      tcam_bank_size           Size of TCAM bank.
    lpm_core_hw_writer(const ll_device_sptr& ldevice,
                       lpm_core_id_t core_id,
                       uint8_t num_tcam_banksets,
                       size_t num_cells_per_bankset,
                       size_t tcam_bank_size);

    /// @brief Encode prefix.
    ///
    /// The encoding is as following:
    /// 1.  Bits are MSB aligned
    /// 2.  Reading from LSB, the first apearing 1 is the beginning of the valid data
    ///     As a result, the width of the prefix data is <width> - <position of first 1 from LSB>
    ///
    /// @param[in]      key                 Key to encode.
    /// @param[in]      root_width          Bucket's root width.
    /// @param[in]      output_width        Width of output field.
    ///
    /// @return Encoded prefix.
    lpm_key_t encode_prefix(const lpm_key_t& key, size_t root_width, size_t output_width) const;

    /// @brief Decode prefix.
    ///
    /// The encoding is as following:
    /// 1.  Bits are MSB aligned
    /// 2.  Reading from LSB, the first apearing 1 is the beginning of the valid data
    ///     As a result, the width of the prefix data is <width> - <position of first 1 from LSB>
    ///
    /// @param[in]      prefix          Encoded prefix.
    ///
    /// @return Decoded prefix with correct width.
    bit_vector decode_prefix(const bit_vector& prefix) const;

    /// @brief Verify no data is overwritten
    ///
    /// @param[in]      line_entry_data     Pointer to the data buffer.
    /// @param[in]      msb                 The MSB to check if it contains data.
    /// @param[in]      lsb                 The LSB to check if it contains data.
    ///
    /// @return Whether line_entry_data contains data in the region MSB-LSB.
    bool verify_no_overrides(const uint64_t* line_entry_data, size_t msb, size_t lsb) const;

    /// @brief CDB core resources needed to write LPM core.
    struct cdb_core_resources {
        vector_alloc<lld_memory_scptr> lpm_tcam;             ///< LPM TCAM.
        lld_memory_scptr subtrie_mem;                        ///< LPM L1 memory.
        lld_register_scptr lpm_rd_mod_wr_valid_reg;          ///< L2 valid register - triggers the operation.
        lld_register_scptr lpm_rd_mod_wr_address_reg;        ///< L2 address line number in banks
        lld_register_scptr lpm_rd_mod_wr_non_entry_data_reg; ///< L2 non entry data
                                                             ///     default payload0 - bit[19:0]
                                                             ///     default payload1 - bit[39:20]
                                                             ///     interleaved offset - bit[43:40]
        lld_memory_array_scptr srams_group;                  ///< Actual L2 banks.
        lld_register_scptr ecc_1b_int_reg;                   ///< L2 ECC Reg (1b)
        lld_register_scptr ecc_2b_int_reg;                   ///< L2 ECC Reg (2b)
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(cdb_core_resources)

    // members
    ll_device_sptr m_ll_device;           ///< Low level device.
    const lpm_core_id_t m_core_id;        ///< Core id.
    uint8_t m_tcam_num_banksets;          ///< Number of allocated TCAM banksets.
    const size_t m_num_cells_per_bankset; ///< Number of cells in TCAM bankset.
    const size_t m_tcam_bank_size;        ///< Number of cells in TCAM bank.
    mutable lpm_hw_writer_consistency_checker_sptr m_consistency_checker;

public:
    map_alloc<lpm_key_t, bool, key_less_operator> m_key_to_force_is_leaf;
};

} // namespace silicon_one

#endif
