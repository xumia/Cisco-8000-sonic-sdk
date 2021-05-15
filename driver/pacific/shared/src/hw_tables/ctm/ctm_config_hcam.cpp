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

#include "ctm_config_hcam.h"

#include "common/defines.h"
#include "common/gen_utils.h"
#include "common/logger.h"
#include "lld/ll_device.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_enums.h"
#include "nplapi/npl_tables_enum.h"

namespace silicon_one
{

ctm_config_hcam::ctm_config_hcam(const ll_device_sptr& ldevice, size_t number_of_slices, bool seperate_rx_tx)
    : ctm_config(ldevice, number_of_slices), m_seperate_rx_tx(seperate_rx_tx)

{
    create_tcams_group_mapping();
}

bool
ctm_config_hcam::has_separate_rx_tx(size_t slice_idx) const
{
    // Not currently tracking this per slice since there is no device
    // where this differs among slices.
    return m_seperate_rx_tx;
}

// Common hardware config for all HCAM variants
la_status
ctm_config_hcam::configure_hw()
{
    la_status status = LA_STATUS_SUCCESS;

    for (size_t slice_idx = 0; slice_idx < m_num_of_slices; ++slice_idx) {

        // First config the RX HCAM device.  If we don't have separate RX and
        // TX devices, the lower level routines will just ignore the direction
        // parameter here.
        status = configure_one_device(m_ll_device, slice_idx, HCAM_RX);
        return_on_error(status);

        if (has_separate_rx_tx(slice_idx)) {
            // If we have separate RX and TX HCAM devices, we now config the TX
            status = configure_one_device(m_ll_device, slice_idx, HCAM_TX);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_hcam::configure_one_device(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const
{
    la_status status = LA_STATUS_SUCCESS;

    // Put all blocks in DEFAULT_TCAM_REGION with a tile search
    // count of 0.  We are not using the tiles for now.
    status = set_all_tcam_block_entries(ldevice, slice_idx, dir, DEFAULT_TCAM_REGION, 0);
    return_on_error(status);

    // Set the skip_or_complete flag for all TCAM entries to
    // 'skip'.  We would only ever consider setting it to 'incomplete'
    // if we were supporting hardware merge.  We are not yet.
    status = set_all_tcam_skip_or_incomplete_entries(ldevice, slice_idx, dir, TCAM_SKIP);
    return_on_error(status);

    // Statically map each TCAM entry to a databank entry.
    //
    // Note that the last 2 parameters here are indicators of whether we
    // want to enable "field 0" and "field 1" in the actual result AD
    // entries.  For a simple 64b result AD, we need to enable field 0
    // but not field 1.
    status = cfg_static_tcam_data_bank_mapping(ldevice, slice_idx, dir, get_static_mapped_tcam_data_bank_type(), true, false);
    return_on_error(status);

    // Config databases for all possible database ids.  In the current simple TCAM
    // implementation, the only thing unique for the databases is whether they use
    // wide or narrow keys.
    //
    // Even databse id:  the database uses narrow keys.
    // Odd database id:  the databasde uses wide keys
    for (size_t idx = 0; idx < get_num_database_config_entries(ldevice, slice_idx, dir); idx++) {
        bool wide_key = (idx % 2) == 1;

        status = cfg_one_database_for_simple_tcam(ldevice, slice_idx, dir, idx, wide_key);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
ctm_config_hcam::add_table(const group_desc& group_id, size_t logical_db_id)
{
    la_status status = LA_STATUS_SUCCESS;
    bool wide_key = group_id.is_wide();
    switch (group_id.interface) {
    case ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW:
    case ctm::group_desc::group_ifs_e::GROUP_IFS_FW1_NARROW:
    case ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE:
        status = cfg_one_database_for_simple_tcam(m_ll_device, group_id.slice_idx, HCAM_RX, logical_db_id, wide_key);
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TX0_NARROW:
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TX1_NARROW:
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TX_WIDE:
        status = cfg_one_database_for_simple_tcam(m_ll_device, group_id.slice_idx, HCAM_TX, logical_db_id, wide_key);
        break;
    case ctm::group_desc::group_ifs_e::GROUP_IFS_TERM:
        break;
    default:
        status = LA_STATUS_ENOTIMPLEMENTED;
    }
    return status;
}
std::vector<group_desc>
ctm_config_hcam::get_groups_by_tcam(const tcam_desc_hcam& tcam) const
{
    std::vector<group_desc> ret_vec;
    const group_desc& config_desc = m_tcams_to_group[tcam.slice_idx][tcam.rx_or_tx][tcam.tcam_idx];
    ret_vec.push_back(config_desc);
    return ret_vec;
}
const vector_alloc<tcam_desc_hcam>&
ctm_config_hcam::get_eligible_tcams_for_group(const group_desc& group_desc) const
{
    const vector_alloc<tcam_desc_hcam>& ret_list = m_group_to_tcams[group_desc.slice_idx][group_desc.interface];
    return ret_list;
}

// Note the group mapping in this function was hacked to support the
// HCAM device with the smallest TCAM size:  Asic3.  It needs to be
// fixed to handle the different TCAM sizes among the HCAM devices.
void
ctm_config_hcam::create_tcams_group_mapping()
{
    size_t tcam_idx = 0;
    m_group_to_tcams.resize(m_num_of_slices);
    m_tcams_to_group.resize(m_num_of_slices);
    for (size_t slice_idx = 0; slice_idx < m_num_of_slices; slice_idx++) {
        m_group_to_tcams[slice_idx].resize(group_desc::NUMBER_OF_GROUPS_IFS);
        m_tcams_to_group[slice_idx] = group_dir_vec(3, group_tcams_vec(3));
        // For tcam 0 define: slice, RX/TX,  even/odd, tcam # --> TX & RX Narrow and Term TCAM
        tcam_idx = 0;
        tcam_desc_hcam tcam_rx(slice_idx, hcam_dir::HCAM_RX, tcam_idx);
        group_desc group_desc_rx(slice_idx, ctm::group_desc::group_ifs_e::GROUP_IFS_FW0_NARROW);
        m_group_to_tcams[group_desc_rx.slice_idx][group_desc_rx.interface].push_back(tcam_rx);
        m_tcams_to_group[tcam_rx.slice_idx][tcam_rx.rx_or_tx][tcam_rx.tcam_idx] = group_desc_rx;

        tcam_desc_hcam tcam_tx(slice_idx, hcam_dir::HCAM_TX, tcam_idx);
        group_desc group_desc_tx(slice_idx, ctm::group_desc::group_ifs_e::GROUP_IFS_TX0_NARROW);
        m_group_to_tcams[group_desc_tx.slice_idx][group_desc_tx.interface].push_back(tcam_tx);
        m_tcams_to_group[tcam_tx.slice_idx][tcam_tx.rx_or_tx][tcam_tx.tcam_idx] = group_desc_tx;

        tcam_desc_hcam tcam_term(slice_idx, hcam_dir::NONE, tcam_idx);
        group_desc group_desc_term(slice_idx, ctm::group_desc::group_ifs_e::GROUP_IFS_TERM);
        m_group_to_tcams[group_desc_term.slice_idx][group_desc_term.interface].push_back(tcam_term);
        m_tcams_to_group[tcam_term.slice_idx][tcam_term.rx_or_tx][tcam_term.tcam_idx] = group_desc_term;

        // For tcam 1 define: slice, RX/TX,  even/odd, tcam # --> TX & RX wide
        tcam_idx = 1;

        tcam_desc_hcam tcam_tx1(slice_idx, hcam_dir::HCAM_TX, tcam_idx);
        group_desc group_desc_tx1(slice_idx, ctm::group_desc::group_ifs_e::GROUP_IFS_TX_WIDE);
        m_group_to_tcams[group_desc_tx1.slice_idx][group_desc_tx1.interface].push_back(tcam_tx1);
        m_tcams_to_group[tcam_tx1.slice_idx][tcam_tx1.rx_or_tx][tcam_tx1.tcam_idx] = group_desc_tx1;

        tcam_desc_hcam tcam_rx2(slice_idx, hcam_dir::HCAM_RX, tcam_idx);
        group_desc group_desc_rx2(slice_idx, ctm::group_desc::group_ifs_e::GROUP_IFS_FW_WIDE);
        m_group_to_tcams[group_desc_rx2.slice_idx][group_desc_rx2.interface].push_back(tcam_rx2);
        m_tcams_to_group[tcam_rx2.slice_idx][tcam_rx2.rx_or_tx][tcam_rx2.tcam_idx] = group_desc_rx2;
    }
}

// Set all entries in the HcmTcamBlock memory with the same values.
la_status
ctm_config_hcam::set_all_tcam_block_entries(const ll_device_sptr& ldevice,
                                            size_t slice_idx,
                                            hcam_dir dir,
                                            uint64_t region,
                                            uint64_t tile_search_cnt) const
{
    la_status status = LA_STATUS_SUCCESS;

    for (size_t entry_num = 0; entry_num < get_num_tcam_blocks(ldevice, slice_idx, dir); entry_num++) {
        status = set_tcam_block_entry(ldevice, slice_idx, dir, entry_num, region, tile_search_cnt);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// Set all entries in the HcmTcamBlock memory with the same values.
la_status
ctm_config_hcam::set_all_tcam_skip_or_incomplete_entries(const ll_device_sptr& ldevice,
                                                         size_t slice_idx,
                                                         hcam_dir dir,
                                                         ctm_config_hcam::hcam_tcam_skip_or_incomplete s_or_i) const
{
    la_status status = LA_STATUS_SUCCESS;

    for (size_t entry_num = 0; entry_num < get_num_tcam_entries(ldevice, slice_idx, dir); entry_num++) {
        status = set_tcam_skip_or_incomplete_entry(ldevice, slice_idx, dir, entry_num, s_or_i);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// This function configures a simple static mapping of TCAM entries to
// data bank entries.  The caller specifies whether we want to map to
// large or small data banks.
la_status
ctm_config_hcam::cfg_static_tcam_data_bank_mapping(const ll_device_sptr& ldevice,
                                                   size_t slice_idx,
                                                   hcam_dir dir,
                                                   ctm_config_hcam::hcam_data_bank bank_type,
                                                   bool field0,
                                                   bool field1) const
{
    la_status status = LA_STATUS_SUCCESS;

    for (size_t tcam_entry = 0; tcam_entry < get_num_tcam_entries(ldevice, slice_idx, dir); tcam_entry++) {
        uint32_t db_ptr = data_bank_idx_to_ptr(ldevice, slice_idx, dir, bank_type, tcam_entry);
        status = set_data_bank_pointer_entry(ldevice, slice_idx, dir, tcam_entry, db_ptr, field0, field1);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

// Most of the behavior in HCAM is configured on a per "database" basis.
// There is a ton of configurability spread across multiple tables/memories
// for each database.
//
// For now, this function does all of the config that we need on a
// per-database basis when we are just using HCAM for simple TCAM
// functionality.
//
// When we support more HCAM functionality, the database config will get
// a lot more interesting.
la_status
ctm_config_hcam::cfg_one_database_for_simple_tcam(const ll_device_sptr& ldevice,
                                                  size_t slice_idx,
                                                  hcam_dir dir,
                                                  size_t db_id,
                                                  bool wide_key) const
{
    la_status status = LA_STATUS_SUCCESS;

    size_t num_regions = get_num_tcam_regions(ldevice, slice_idx, dir);

    // Map all TCAM regions to HCAM Output A
    std::vector<ctm_config_hcam::hcam_output> r_to_o_map(num_regions, OUTPUT_A);

    status = set_database_config_entry(ldevice, slice_idx, dir, db_id, wide_key, r_to_o_map);
    return_on_error(status);

    // TODO:  We still need to find the corect values for the output
    // mapping table.
    //
    // There are 4 output maps, one for each of the HCAM outputs A, B, C, D.
    // For the simple TCAM implementation, we are using only output A so
    // that is the only one that we set as valid and specify the other
    // mapping values for.  We just mark the other outputs as not valid.
    std::vector<hcam_output_map_ent> output_maps(4, hcam_output_map_ent());
    output_maps[0].src_sel_hi = 0;
    output_maps[0].src_sel_lo = 1;
    output_maps[0].src_id_out_sel = 0;
    output_maps[0].ret_if_out = 0;
    output_maps[0].is_last = true;
    output_maps[0].valid = true;

    output_maps[1].valid = false;
    output_maps[2].valid = false;
    output_maps[3].valid = false;

    status = set_hcam_output_mapping_entry(ldevice, slice_idx, dir, db_id, 0, 0, false, output_maps);
    return_on_error(status);

    // For the simple TCAM implementation, we will only use either the
    // large or small data banks.  We disable the banks that we are not
    // using and map the ones that we are using to to TCAM output A.

    std::vector<hcam_data_bank_src> l_srcs(get_num_data_banks(ldevice, slice_idx, dir, LARGE_DATA_BANK), DB_SRC_DISABLED);
    std::vector<hcam_data_bank_src> s_srcs(get_num_data_banks(ldevice, slice_idx, dir, SMALL_DATA_BANK), DB_SRC_DISABLED);

    if (get_static_mapped_tcam_data_bank_type() == LARGE_DATA_BANK) {
        std::fill(l_srcs.begin(), l_srcs.end(), DB_SRC_TCAM_OUT_A);
    } else {
        std::fill(s_srcs.begin(), s_srcs.end(), DB_SRC_TCAM_OUT_A);
    }

    status = set_bank_source_select_entry(ldevice, slice_idx, dir, db_id, l_srcs, s_srcs);
    return_on_error(status);

    return LA_STATUS_SUCCESS;
}

// Return the total number of TCAM entries in the HCAM.
size_t
ctm_config_hcam::get_num_tcam_entries(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const
{
    return (get_num_tcam_instances(ldevice, slice_idx, dir) * get_num_tcam_entries_per_instance(ldevice, slice_idx, dir));
}

// Return the total number of tile entries in the HCAM.
size_t
ctm_config_hcam::get_num_tile_entries(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir) const
{
    return (get_num_tiles(ldevice, slice_idx, dir) * get_num_entries_per_tile(ldevice, slice_idx, dir));
}

// Return the total number of large or small data bank entries in the HCAM.
size_t
ctm_config_hcam::get_num_data_bank_entries(const ll_device_sptr& ldevice,
                                           size_t slice_idx,
                                           hcam_dir dir,
                                           hcam_data_bank bank_type) const
{
    return (get_num_data_banks(ldevice, slice_idx, dir, bank_type)
            * get_num_entries_per_data_bank(ldevice, slice_idx, dir, bank_type));
}

// Given a type (large or small) of data bank and an index within that
// data bank space, return the corresponding global scope data bank pointer.
uint32_t
ctm_config_hcam::data_bank_idx_to_ptr(const ll_device_sptr& ldevice,
                                      size_t slice_idx,
                                      hcam_dir dir,
                                      ctm_config_hcam::hcam_data_bank bank_type,
                                      size_t bank_idx) const
{
    // The large data banks are first in the flat pointer space, so the
    // the pointer for bank_idx == bank_idx
    if (bank_type == LARGE_DATA_BANK) {
        return bank_idx;
    } else {
        size_t num_large_banks = get_num_data_banks(ldevice, slice_idx, dir, LARGE_DATA_BANK);
        size_t entries_per_large_bank = get_num_entries_per_data_bank(ldevice, slice_idx, dir, LARGE_DATA_BANK);
        return ((num_large_banks * entries_per_large_bank) + bank_idx);
    }
}

// Given a type (large or small) of data bank, a bank number, and an entry
// within the bank, return the corresponding global scope data bank pointer.
uint32_t
ctm_config_hcam::data_bank_entry_to_ptr(const ll_device_sptr& ldevice,
                                        size_t slice_idx,
                                        hcam_dir dir,
                                        ctm_config_hcam::hcam_data_bank bank_type,
                                        size_t bank,
                                        size_t bank_entry) const
{
    size_t entries_per_bank = get_num_entries_per_data_bank(ldevice, slice_idx, dir, bank_type);
    size_t bank_idx = (entries_per_bank * bank) + bank_entry;

    return data_bank_idx_to_ptr(ldevice, slice_idx, dir, bank_type, bank_idx);
}

// Given a global scope data bank pointer, return the type of bank, the bank
// number, and the entry number within the bank.
void
ctm_config_hcam::data_bank_ptr_to_entry(const ll_device_sptr& ldevice,
                                        size_t slice_idx,
                                        hcam_dir dir,
                                        size_t ptr,
                                        ctm_config_hcam::hcam_data_bank& bank_type,
                                        size_t& bank,
                                        size_t& bank_entry) const
{
    size_t num_large_banks = get_num_data_banks(ldevice, slice_idx, dir, LARGE_DATA_BANK);
    size_t entries_per_large_bank = get_num_entries_per_data_bank(ldevice, slice_idx, dir, LARGE_DATA_BANK);

    if (ptr < (num_large_banks * entries_per_large_bank)) {
        bank_type = LARGE_DATA_BANK;
        bank = ptr / entries_per_large_bank;
        bank_entry = ptr % entries_per_large_bank;
    } else {
        size_t bank_idx = ptr - (num_large_banks * entries_per_large_bank);
        size_t entries_per_small_bank = get_num_entries_per_data_bank(ldevice, slice_idx, dir, SMALL_DATA_BANK);

        bank_type = SMALL_DATA_BANK;
        bank = bank_idx / entries_per_small_bank;
        bank_entry = bank_idx % entries_per_small_bank;
    }
}

// Given a TCAM entry number, return the global scope data bank pointer statically
// mapped to that index.
uint32_t
ctm_config_hcam::tcam_entry_to_data_bank_ptr(const ll_device_sptr& ldevice, size_t slice_idx, hcam_dir dir, size_t tcam_entry) const
{
    return data_bank_idx_to_ptr(ldevice, slice_idx, dir, get_static_mapped_tcam_data_bank_type(), tcam_entry);
}

// Given a TCAM entry number, return the data bank entry mapped to that index.
void
ctm_config_hcam::tcam_entry_to_data_bank_entry(const ll_device_sptr& ldevice,
                                               size_t slice_idx,
                                               hcam_dir dir,
                                               size_t tcam_entry,
                                               ctm_config_hcam::hcam_data_bank& bank_type,
                                               size_t& bank,
                                               size_t& bank_entry) const
{
    uint32_t ptr = tcam_entry_to_data_bank_ptr(ldevice, slice_idx, dir, tcam_entry);

    data_bank_ptr_to_entry(ldevice, slice_idx, dir, ptr, bank_type, bank, bank_entry);
}

// Given a TCAM entry number (a number between 0 and num_tcam_entries-1),
// return the TCAM instace that the entry is in and the line number
// within the instance for the entry.
void
ctm_config_hcam::tcam_entry_to_inst_and_line_num(const ll_device_sptr& ldevice,
                                                 size_t slice_idx,
                                                 hcam_dir dir,
                                                 size_t tcam_entry,
                                                 size_t& tcam_inst,
                                                 size_t& line_num) const
{
    tcam_inst = tcam_entry / get_num_tcam_entries_per_instance(ldevice, slice_idx, dir);
    line_num = tcam_entry % get_num_tcam_entries_per_instance(ldevice, slice_idx, dir);
}

} // namespace silicon_one
