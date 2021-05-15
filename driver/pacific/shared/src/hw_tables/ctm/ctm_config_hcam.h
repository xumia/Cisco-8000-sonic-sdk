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

#ifndef __CTM_CONFIG_HCAM_H__
#define __CTM_CONFIG_HCAM_H__

#include "common/bit_vector.h"
#include "common/la_status.h"
#include "ctm_common_hcam.h"
#include "ctm_config.h"
#include "lld/lld_fwd.h"

#include <map>
#include <stddef.h>
#include <vector>

namespace silicon_one
{

/// @brief Static configuration of CDB Central Tcam.
///
class ctm_config_hcam : public ctm_config
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS
public:
    enum hcam_data_bank { LARGE_DATA_BANK, SMALL_DATA_BANK };

    // This output (A, B, C, D) to integer value mapping is defined in the
    // description of the regionToOutputMapping fields within the
    // HcmDatabaseConfig memory in the LBR.
    enum hcam_output { OUTPUT_A = 0, OUTPUT_B, OUTPUT_C, OUTPUT_D };

    // These data bank source values are defined in the description of the
    // HcmBankSourceSelect memory in the LBR.
    enum hcam_data_bank_src {
        DB_SRC_TCAM_OUT_A = 0,
        DB_SRC_TCAM_OUT_B,
        DB_SRC_TCAM_OUT_C,
        DB_SRC_TCAM_OUT_D,
        DB_SRC_TILE,
        DB_SRC_SBAND_CTR_0,
        DB_SRC_SBAND_CTR_1,
        DB_SRC_DISABLED
    };

    // These are the values for the 2-bit field0_mode in the HcmLargeDataBank
    // and HcmSmallDataBank entries.
    enum hcam_data_bank_field0_mode {
        AD_FIELD0_FRAMES = 0,
        AD_FIELD0_AD_63_32,
        AD_FIELD0_AD_31_0,
        AD_FIELD0_DISABLED,
    };

    // These are the values for the 2-bit field1_mode in the HcmLargeDataBank
    // and HcmSmallDataBank entries.
    enum hcam_data_bank_field1_mode {
        AD_FIELD1_FRAMES = 0,
        AD_FIELD1_BYTES,
        AD_FIELD1_AD_39_0,
        AD_FIELD1_DISABLED,
    };

    // These are the values for the HcmTcamSkipOrIncomplete entries.
    enum hcam_tcam_skip_or_incomplete {
        TCAM_SKIP = 0,
        TCAM_INCOMPLETE,
    };

    enum {
        NUM_ALT_KEY_BITS_NARROW_KEY = 32,
        DEFAULT_TCAM_REGION = 0,
        NUM_SRAMS_PER_TILE = 4,
    };

    // These are the fields in each of the 4 hcmOutputMappingTable groups.
    struct hcam_output_map_ent {
        bool valid;
        uint8_t src_sel_hi;
        uint8_t src_sel_lo;
        uint8_t src_id_out_sel;
        uint8_t ret_if_out;
        bool is_last;
    };

    // C'tor
    ctm_config_hcam(const ll_device_sptr& ldevice, size_t number_of_slices, bool seperate_rx_tx);

    // D'tor
    virtual ~ctm_config_hcam()
    {
    }

    la_status configure_hw() override;

    la_status configure_one_device(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const;

    /// @brief Does the slice have separate RX and TX HCAM devies?
    //
    /// @param[in]  slice_idx           Slice index / number
    //
    /// @retval     bool
    bool has_separate_rx_tx(size_t slice_idx) const;

    /// @brief Config a static mapping of each TCAM entry to a data bank entry.
    //
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Map to small or large data banks?
    /// @param[in]  field0              Enable 'field0' in the data bank entry?
    /// @param[in]  field1              Enable 'field1' in the data bank entry?
    ///
    /// @retval     status code.
    la_status cfg_static_tcam_data_bank_mapping(const ll_device_sptr& ldevice,
                                                size_t slice_idx,
                                                hcam_dir dir,
                                                ctm_config_hcam::hcam_data_bank bank_type,
                                                bool field0,
                                                bool field1) const;

    /// @brief Register NPL table for a given slice interface.
    /// The table is added to all slices.
    ///
    /// @param[in]  group_id           Group ID.
    /// @param[in]  logical_id         Table logical ID.
    /// @param[in]  is_wide            Table key size.
    la_status add_table(const group_desc& group_id, size_t logical_db_id);
    const vector_alloc<tcam_desc_hcam>& get_eligible_tcams_for_group(const group_desc& desc) const;

    std::vector<group_desc> get_groups_by_tcam(const tcam_desc_hcam& tcam) const;

    /// @brief Get the number of database config table entries in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries.
    virtual size_t get_num_database_config_entries(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the number of TCAM regions in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries.
    virtual size_t get_num_tcam_regions(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the number of TCAM instances in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries.
    virtual size_t get_num_tcam_instances(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the number of entries in each TCAM instance in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries.
    virtual size_t get_num_tcam_entries_per_instance(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the total number of TCAM entries in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries.
    size_t get_num_tcam_entries(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const;

    /// @brief Get the number of TCAM blocks in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of blocks.
    virtual size_t get_num_tcam_blocks(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the number of data banks in the HCAM
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Large or Small data banks
    ///
    /// @retval     Number of data banks.
    virtual size_t get_num_data_banks(const ll_device_sptr& ldevice,
                                      size_t slice_idx,
                                      hcam_dir dir,
                                      hcam_data_bank bank_type) const = 0;

    /// @brief Get the number of entries in each data bank in the HCAM
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Large or Small data banks
    ///
    /// @retval     Number of entries per data bank.
    virtual size_t get_num_entries_per_data_bank(const ll_device_sptr& ldevice,
                                                 size_t slice_idx,
                                                 hcam_dir dir,
                                                 hcam_data_bank bank_type) const = 0;

    /// @brief Get the total number of data bank entries in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Large or Small data banks
    ///
    /// @retval     Number of entries.
    size_t get_num_data_bank_entries(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir, hcam_data_bank bank_type) const;

    /// @brief Get the number of tiles in the HCAM
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of tiles.
    virtual size_t get_num_tiles(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the number of entries per tile in the HCAM
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries per tile.
    virtual size_t get_num_entries_per_tile(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the total number of tile entries in the HCAM.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries.
    size_t get_num_tile_entries(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const;

    /// @brief Get the number of entries per tile mask table.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    ///
    /// @retval     Number of entries per tile mask table.
    virtual size_t get_num_entries_per_tile_mask_table(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const = 0;

    /// @brief Get the type of data bank (large or small) we want to statically map to
    ///
    /// @retval     Data bank type
    virtual ctm_config_hcam::hcam_data_bank get_static_mapped_tcam_data_bank_type() const = 0;

    /// @brief Get the data bank entry that a given TCAM entry is mapped to.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  entry               TCAM entry number.
    /// @param[out] bank_type           Large or Small data banks
    /// @param[out] bank                Data bank number
    /// @param[out] bank_entry          Entry within the data bank
    void tcam_entry_to_data_bank_entry(const ll_device_sptr& ldevice,
                                       size_t slice_idx,
                                       hcam_dir dir,
                                       size_t tcam_entry,
                                       ctm_config_hcam::hcam_data_bank& bank_type,
                                       size_t& bank,
                                       size_t& bank_entry) const;

    /// @brief Given a TCAM entry number, return the TCAM instance and line num within that instance.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  entry               TCAM entry number.
    /// @param[out] tcam_inst           Data bank number
    /// @param[out] line_num            Line number within the TCAM instance
    void tcam_entry_to_inst_and_line_num(const ll_device_sptr& ldevice,
                                         size_t slice_idx,
                                         hcam_dir dir,
                                         size_t tcam_entry,
                                         size_t& tcam_inst,
                                         size_t& line_num) const;

    /// @brief Set the Associated Data (AD) in a data bank entry.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Large or Small data banks
    /// @param[in]  bank                Data bank number
    /// @param[in]  bank_entry          Entry within the data bank
    /// @param[in]  ad                  The AD to write in the entry.
    ///
    /// @retval     status code.
    virtual la_status set_data_bank_entry_ad(const ll_device_sptr& ldevice,
                                             size_t slice_idx,
                                             hcam_dir dir,
                                             ctm_config_hcam::hcam_data_bank bank_type,
                                             size_t bank_num,
                                             size_t entry_num,
                                             bit_vector ad) const = 0;

    /// @brief Get the Associated Data (AD) in a data bank entry.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Large or Small data banks
    /// @param[in]  bank                Data bank number
    /// @param[in]  bank_entry          Entry within the data bank
    /// @param[out] ad                  AD value returned.
    ///
    /// @retval     status code.
    virtual la_status get_data_bank_entry_ad(const ll_device_sptr& ldevice,
                                             size_t slice_idx,
                                             hcam_dir dir,
                                             ctm_config_hcam::hcam_data_bank bank_type,
                                             size_t bank_num,
                                             size_t entry_num,
                                             bit_vector& ad) const = 0;

    /// @brief Convert data bank type and index to data bank pointer.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Large or Small data banks
    /// @param[in]  bank_idx            Index within the large or small banks
    ///
    /// @retval     Global scope data bank pointer.
    uint32_t data_bank_idx_to_ptr(const ll_device_sptr& ldevice,
                                  size_t slice_idx,
                                  hcam_dir dir,
                                  ctm_config_hcam::hcam_data_bank bank_type,
                                  size_t bank_idx) const;

    /// @brief Convert bank type/number/entry to data bank pointer.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  bank_type           Large or Small data banks
    /// @param[in]  bank                Bank number
    /// @param[in]  bank_entry          Entry within the specific bank
    ///
    /// @retval     Global scope data bank pointer.
    uint32_t data_bank_entry_to_ptr(const ll_device_sptr& ldevice,
                                    size_t slice_idx,
                                    hcam_dir dir,
                                    ctm_config_hcam::hcam_data_bank bank_type,
                                    size_t bank,
                                    size_t bank_entry) const;

    /// @brief Convert data bank pointer to bank type/number/entry.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  ptr                 Global scope data bank pointer
    /// @param[out] bank_type           Large or Small data banks
    /// @param[out] bank                Bank number
    /// @param[out] bank_entry          Entry within the specific bank
    void data_bank_ptr_to_entry(const ll_device_sptr& ldevice,
                                size_t slice_idx,
                                hcam_dir dir,
                                size_t ptr,
                                ctm_config_hcam::hcam_data_bank& bank_type,
                                size_t& bank,
                                size_t& bank_entry) const;

    /// @brief Get data bank pointer statically mapped for a TCAM entry.
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  tcam_entry          TCAM entry number.
    ///
    /// @retval     Global scope data bank pointer.
    uint32_t tcam_entry_to_data_bank_ptr(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir, size_t tcam_entry) const;

protected:
    using group_tcams_vec = vector_alloc<group_desc>;
    using group_dir_vec = vector_alloc<group_tcams_vec>;
    using group_slice_vec = vector_alloc<group_dir_vec>;
    using tcam_desc_hcam_vec = vector_alloc<tcam_desc_hcam>;
    using tcam_ifs_vec = vector_alloc<tcam_desc_hcam_vec>;

    group_slice_vec m_tcams_to_group;
    vector_alloc<tcam_ifs_vec> m_group_to_tcams;
    bool m_seperate_rx_tx;
    void create_tcams_group_mapping();
    ctm_config_hcam() = default;

    /// @brief Set the values in one entry of the Database Config Table
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  entry_num           The entry number
    /// @param[in]  wide_key            Does the DB use wide keys?
    /// @param[in]  reg_to_output_map   Mapping of regions to outputs
    ///
    /// @retval     status code.
    virtual la_status set_database_config_entry(const ll_device_sptr& ldevice,
                                                size_t slice_idx,
                                                hcam_dir dir,
                                                size_t entry_num,
                                                bool wide_key,
                                                std::vector<ctm_config_hcam::hcam_output>& reg_to_output_map) const = 0;

    /// @brief Set the values in one entry of the TCAM Block Table
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  entry_num           The entry number
    /// @param[in]  region              Region number
    /// @param[in]  tile_search_cnt     Tile search count
    ///
    /// @retval     status code.
    virtual la_status set_tcam_block_entry(const ll_device_sptr& ldevice,
                                           size_t slice_idx,
                                           hcam_dir dir,
                                           size_t entry_num,
                                           uint64_t region,
                                           uint64_t tile_search_cnt) const = 0;

    /// @brief Set all entries of the TCAM Block Table to the same values
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  region              Region number
    /// @param[in]  tile_search_cnt     Tile search count
    ///
    /// @retval     status code.
    la_status set_all_tcam_block_entries(const ll_device_sptr& ldevice,
                                         size_t slice_idx,
                                         hcam_dir dir,
                                         uint64_t region,
                                         uint64_t tile_search_cnt) const;

    /// @brief Set the value in one entry of the TCAM SkipOrIncomplete Table
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  entry_num           The entry number
    /// @param[in]  s_or_i              Value to set
    ///
    /// @retval     status code.
    virtual la_status set_tcam_skip_or_incomplete_entry(const ll_device_sptr& ldevice,
                                                        size_t slice_idx,
                                                        hcam_dir dir,
                                                        size_t entry_num,
                                                        ctm_config_hcam::hcam_tcam_skip_or_incomplete s_or_i) const = 0;

    /// @brief Set all entries of the TCAM SkipOrIncomplete Table to the same values
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  s_or_i              Value to set
    ///
    /// @retval     status code.
    la_status set_all_tcam_skip_or_incomplete_entries(const ll_device_sptr& ldevice,
                                                      size_t slice_idx,
                                                      hcam_dir dir,
                                                      ctm_config_hcam::hcam_tcam_skip_or_incomplete s_or_i) const;

    /// @brief Set the values in one entry of the Data Bank Pointer Table
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  entry_num           The entry number
    /// @param[in]  main_ptr            The "main pointer" value for the entry
    /// @param[in]  field0              The "field0" value for the entry
    /// @param[in]  field1              The "field1" value for the entry
    ///
    /// @retval     status code.
    virtual la_status set_data_bank_pointer_entry(const ll_device_sptr& ldevice,
                                                  size_t slice_idx,
                                                  hcam_dir dir,
                                                  size_t entry_num,
                                                  uint64_t main_ptr,
                                                  bool field0,
                                                  bool field1) const = 0;

    /// @brief Set the values in one entry of the Bank Source Select Table
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  entry_num           The entry number
    /// @param[in]  large_srcs          Source field for each large data bank
    /// @param[in]  small_srcs          Source field for each small data bank
    ///
    /// @retval     status code.
    virtual la_status set_bank_source_select_entry(const ll_device_sptr& ldevice,
                                                   size_t slice_idx,
                                                   hcam_dir dir,
                                                   size_t entry_num,
                                                   std::vector<hcam_data_bank_src>& large_srcs,
                                                   std::vector<hcam_data_bank_src>& small_srcs) const = 0;

    /// @brief Set the values in one entry of the Output Mapping Table
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  db_id               The database id
    /// @param[in]  ret_if0             Return interface 0 id
    /// @param[in]  ret_if1             Return interface 1 id
    /// @param[in]  src_id1_val         src_id1 valid?
    /// @param[in]  output_maps         Mapping value for each output (A, B, C, D)
    ///
    /// @retval     status code.
    virtual la_status set_hcam_output_mapping_entry(const ll_device_sptr& ldevice,
                                                    size_t slice_idx,
                                                    hcam_dir dir,
                                                    size_t db_id,
                                                    size_t ret_if0,
                                                    size_t ret_if1,
                                                    bool src_id1_val,
                                                    std::vector<hcam_output_map_ent>& output_maps) const = 0;

    /// @brief Configure one database when doing "simple TCAM" mode
    ///
    /// @param[in]  ldevice             Pointer to Low Level Device.
    /// @param[in]  slice_idx           Slice index / number
    /// @param[in]  dir                 Rx or Tx HCAM
    /// @param[in]  db_id               The database id
    /// @param[in]  wide_key            Does the DB use wide keys?
    ///
    /// @retval     status code.
    la_status cfg_one_database_for_simple_tcam(const ll_device_sptr& ldevice,
                                               size_t slice_idx,
                                               hcam_dir dir,
                                               size_t db_id,
                                               bool wide_key) const;
};

} // namespace silicon_one

#endif // __CTM_CONFIG_TCAM_H__
