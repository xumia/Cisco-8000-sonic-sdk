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

#ifndef __MC_COPY_ID_MANAGER_H__
#define __MC_COPY_ID_MANAGER_H__

#include "api/types/la_common_types.h"
#include "common/la_status.h"
#include "common/ranged_index_generator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include <map>

namespace silicon_one
{

class mc_copy_id_manager
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    mc_copy_id_manager() = default;
    //////////////////////////////
public:
    mc_copy_id_manager(la_device_impl_wptr device, la_slice_id_t slice);
    ~mc_copy_id_manager() = default;
    la_status initialize();
    la_status destroy();

    /// @brief Get a mc-copy-id for the given user.
    ///
    /// @param[in]  user                    Object requesting the mc-copy-id
    /// @param[in]  is_wide                 Use wide entry in the mc-cud-table
    /// @param[out] out_mc_copy_id          mc-copy-id.
    ///
    /// Null users are allowed, resulting with an entry in the CUD table.
    ///
    /// @retval LA_STATUS_SUCCESS         Operation completed successfully.
    /// @retval LA_STATUS_ERESOURCE       No free entry was found.
    la_status get_mc_copy_id(const la_object* user, bool is_wide, uint64_t& out_mc_copy_id);
    la_status get_mc_copy_id(const la_object_wcptr& user, bool is_wide, uint64_t& out_mc_copy_id);
    la_status get_stack_mc_copy_id(uint64_t& out_stack_mc_copy_id);

    /// @brief Release the given mc-copy-id.
    la_status release_mc_copy_id(uint64_t mc_copy_id);

    /// @brief Return the mc_cud_table key for the given mc-copy-id
    static uint64_t get_mc_cud_table_key(uint64_t mc_copy_id);
    static uint64_t cud_entry_index_2_mc_copy_id(uint64_t cud_entry_index);
    static uint64_t mc_copy_id_2_cud_entry_index(uint64_t mc_copy_id);

private:
    enum { NUM_OF_ROWS_IN_MC_CUD_TABLE = (1 << 14) };
    enum { ENTRIES_PER_ROW_IN_MC_CUD_TABLE = 2 };
    enum { NUM_OF_ENTRIES_IN_MC_CUD_TABLE = (NUM_OF_ROWS_IN_MC_CUD_TABLE * ENTRIES_PER_ROW_IN_MC_CUD_TABLE) };
    enum { NUM_OF_ENTRIES_RESERVED_FOR_IBM = 64 };
    enum { NUM_OF_LINES_IN_MC_COPY_ID_MAP = (1 << 6) };

    // Masks to apply to the mc-copy-id prefixes that identifies the object type
    enum {
        L3_AC_MC_COPY_ID_PREFIX_PADDED = L3_AC_MC_COPY_ID_PREFIX_6b << 12,
        L3_AC_MC_COPY_ID_PREFIX_MASK = L3_AC_MC_COPY_ID_MASK_6b << 12,
        MCG_COUNTER_MC_COPY_ID_PREFIX_PADDED = MCG_COUNTER_MC_COPY_ID_PREFIX_6b << 12,
        MCG_COUNTER_MC_COPY_ID_PREFIX_MASK = MCG_COUNTER_MC_COPY_ID_MASK_6b << 12,
        CUD_MAP_PREFIX_PADDED = CUD_MAP_PREFIX_6b << 12,
        CUD_MAP_PREFIX_MASK = CUD_MAP_MASK_6b << 12,
        L2_AC_MC_COPY_ID_PREFIX_PADDED = L2_AC_MC_COPY_ID_PREFIX_6b << 12,
        L2_AC_MC_COPY_ID_PREFIX_MASK = L2_AC_MC_COPY_ID_MASK_6b << 12,
    };

    // Indices of SVI and MPLS members is limited by the length of the prefix that
    // distinguishes between them
    enum {
        MAX_INDEX_OF_SVI_MEMBERS = 8 * 1024,
        MAX_INDEX_OF_MPLS_MEMBERS = 8 * 1024,
    };

    la_device_impl_wptr m_device;
    la_device_revision_e m_device_revision;
    la_slice_id_t m_slice;
    ranged_index_generator m_index_gen;
    std::map<uint64_t, bool> m_entries;

    /// @brief Static initialization of mc_copy_id_map table.
    la_status initialize_mc_copy_id_map();

    la_status allocate(bool is_wide, uint64_t& out_table_entry_index);
    la_status release(uint64_t table_entry_index);

    bool is_l2_ac_mc_copy_id(uint64_t mc_copy_id);
    bool is_l3_ac_mc_copy_id(uint64_t mc_copy_id);
    bool is_mcg_counter_mc_copy_id(uint64_t mc_copy_id);
    bool is_stack_mc_copy_id(uint64_t mc_copy_id);

    /// @brief common mc_copy_id for stack copy
    uint64_t m_stack_mc_copyid;
};

} // namespace silicon_one

#endif // __MC_COPY_ID_MANAGER_H__
