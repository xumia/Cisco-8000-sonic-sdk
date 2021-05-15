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

#ifndef __CTM_MGR_H__
#define __CTM_MGR_H__

#include "api/types/la_acl_types.h"
#include "common/allocator_wrapper.h"
#include "common/bit_vector.h"
#include "common/gen_utils.h"
#include "ctm/ctm_common.h"
#include "engine_block_mapper.h"
#include "hw_tables/memory_tcam.h"
#include "hw_tables/physical_locations.h"
#include "hw_tables/tcam_types.h"
#include "ra/ra_types_fwd.h"

namespace silicon_one
{

class ll_device;
class ctm_config;

using namespace ctm;

/// @brief Implementation of #silicon_one::
class ctm_mgr
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  ldevice
    /// @param[in]  ipv4_acl_type
    /// @param[in]  ipv6_acl_type
    /// @param[in]  lpm_tcam_num_banksets
    /// @param[in]  block_mapper             Pointer to low level device.
    ctm_mgr(const ll_device_sptr& ldevice, engine_block_mapper block_mapper, size_t number_of_slices);

    // D'tor
    virtual ~ctm_mgr() = default;

    /// @brief Get initialized configuration object for CTM.
    ///
    /// @retval     pointer to the initialized configuration object.
    virtual const ctm_config_sptr get_ctm_config() const = 0;

    /// @brief Write Database configuration to the device.
    ///
    /// @retval     status code.
    virtual la_status configure_hw() const = 0;

    /// TCAM MGR API
    virtual la_status write(table_desc table_id,
                            size_t line_idx,
                            const bit_vector& key,
                            const bit_vector& mask,
                            const bit_vector& value)
        = 0;
    virtual la_status write_bulk(table_desc table_id,
                                 size_t first_line_idx,
                                 size_t bulk_size,
                                 const vector_alloc<tcam_entry_desc>& entries)
        = 0;
    virtual la_status move(table_desc table_id, size_t src_line_idx, size_t dest_line) = 0;
    virtual la_status update(table_desc table_id, size_t line_idx, const bit_vector& value) = 0;
    virtual la_status invalidate(table_desc table_id, size_t line_idx) = 0;
    virtual la_status read(table_desc table_id,
                           size_t line_idx,
                           bit_vector& out_key,
                           bit_vector& out_mask,
                           bit_vector& out_value,
                           bool& out_valid)
        = 0;
    virtual la_status set_default_value(table_desc table_id, const bit_vector& key, const bit_vector& mask, const bit_vector& value)
        = 0;

    virtual size_t get_table_size(const table_desc& table_id) const = 0;
    void register_table_to_group(group_desc group_id, table_desc table_id, size_t logical_db_id);

    /// @brief Returns the number of valid lines in a table.
    ///
    /// @param[in]  table
    ///
    /// @retval     Number of valid lines
    virtual size_t get_table_usage(const table_desc& table) const = 0;

    ///@brief Calclute the maximum entries that can be inserted successfully in a table in the current system state.
    ///
    ///@param[in] table table for which to check the maximum scale.
    ///@retval   number of lines that can be successfully inserted.
    virtual size_t get_max_available_space(const table_desc& table) = 0;

    size_t m_num_of_slices; // TODO public?

protected:
    using table_vec = std::vector<table_desc>;
    using group_vec = std::vector<ctm::group_desc>;
    ctm_mgr() = default; // For serialization purposes only.

    bool is_table_wide(const table_desc& table) const;

    // Pointer to low level device.
    ll_device_sptr m_ll_device;
    // Engine <-> lld_block mapper.
    engine_block_mapper m_block_mapper;

    map_alloc<group_desc, table_vec> m_group_to_tables_mapping; // tables registration to a Group
    map_alloc<table_desc, group_desc> m_table_to_group_mapping; // tables registration to a Group

    mutable group_desc m_current_group; // Transient data representing the current group that we got trough the API call;

    virtual void start_ctm_mgr_api_call(const table_desc& table_id) const;
    table_vec get_tables_for_group(const group_desc& desc) const;
    group_desc get_group_for_table(const table_desc& table) const;
    void add_table(group_desc group_id, ctm::table_desc table_id, size_t logical_db_id){};
    virtual size_t get_number_of_lines_in_group(const group_desc& group) const = 0;
};

} // namespace silicon_one

#endif // __CTM_TCAM_H__
