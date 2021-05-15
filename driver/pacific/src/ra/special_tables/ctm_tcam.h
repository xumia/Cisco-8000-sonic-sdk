// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __CTM_TCAM_H__
#define __CTM_TCAM_H__

#include "ctm/ctm_common.h"
#include "hw_tables/logical_tcam.h"
#include "ra/ra_types_fwd.h"

#include <vector>

namespace silicon_one
{

class ctm_mgr;
/// @brief Implementation of #silicon_one::logical_tcam interface.
///
/// Special implementation for Central TCAM memories (CTM).
/// CTM may hold several NPL tables, distinguished by table logical ID.
/// From user perspective, the mapping of NPL table to a logical TCAM is irrelevant, thus table operations (insert, remove ets) are
/// done using relative to NPL table line numbers.
/// This implementation maintains mapping between the indices of a specific table to the absolute indices of the shared resource,
/// making sure, tables mapped to the same TCAM do not collide.
class ctm_tcam : public logical_tcam
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief C'tor
    ///
    /// @param[in]  tcam_width          Key and key mask width in bits.
    /// @param[in]  sram_width          Value width in bits.
    /// @param[in]  ctm mgr.
    ctm_tcam(ctm::table_desc table_id,
             ctm::group_desc group_id,
             size_t logical_db_id,
             size_t key_width,
             size_t value_width,
             const ctm_mgr_sptr& _ctm_mgr);

    /// Logical TCAM API
    la_status write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value) override;
    la_status write_bulk(size_t first_line, size_t entries_num, const vector_alloc<tcam_entry_desc>& entries) override;
    la_status move(size_t src_line, size_t dest_line) override;
    la_status update(size_t line, const bit_vector& value) override;
    la_status invalidate(size_t line) override;
    la_status read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const override;

    la_status set_default_value(const bit_vector& key, const bit_vector& mask, const bit_vector& value) override;
    size_t size() const override;
    la_status get_max_available_space(size_t& out_max_scale) const override;
    la_status get_physical_usage(size_t& out_physical_usage) const override;

private:
    ctm_tcam() = default; // For serialization purposes only
    ctm::table_desc m_table_id;
    size_t m_key_width;
    size_t m_value_width;
    size_t m_size;
    ctm_mgr_wptr m_ctm_mgr;
};

} // namespace silicon_one

#endif // __CTM_TCAM_H__
