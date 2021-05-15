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

#include "mc_copy_id_manager.h"
#include "api/npu/la_l2_service_port.h"
#include "api/npu/la_l3_ac_port.h"
#include "api/types/la_object.h"
#include "nplapi/npl_constants.h"
#include "nplapi/npl_types.h"
#include "nplapi/nplapi_tables.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

mc_copy_id_manager::mc_copy_id_manager(la_device_impl_wptr device, la_slice_id_t slice)
    : m_device(device), m_slice(slice), m_stack_mc_copyid(0)
{
    m_device_revision = m_device->m_ll_device->get_device_revision();
    m_index_gen = ranged_index_generator(NUM_OF_ENTRIES_RESERVED_FOR_IBM, NUM_OF_ENTRIES_IN_MC_CUD_TABLE, true /*allow_pairs*/);
}

la_status
mc_copy_id_manager::initialize()
{
    la_status status = initialize_mc_copy_id_map();

    bool svl_mode = false;
    m_device->get_bool_property(la_device_property_e::ENABLE_SVL_MODE, svl_mode);
    if (svl_mode) {
        uint64_t mc_cud_table_entry;
        status = allocate(false, mc_cud_table_entry);
        return_on_error(status);
        m_stack_mc_copyid = CUD_MAP_PREFIX_PADDED | mc_cud_table_entry;
    }

    return status;
}

la_status
mc_copy_id_manager::destroy()
{
    // TODO clear table entries?
    return LA_STATUS_SUCCESS;
}

bool
mc_copy_id_manager::is_l2_ac_mc_copy_id(uint64_t mc_copy_id)
{
    return ((mc_copy_id & L2_AC_MC_COPY_ID_PREFIX_MASK) == L2_AC_MC_COPY_ID_PREFIX_PADDED);
}

bool
mc_copy_id_manager::is_l3_ac_mc_copy_id(uint64_t mc_copy_id)
{
    return ((mc_copy_id & L3_AC_MC_COPY_ID_PREFIX_MASK) == L3_AC_MC_COPY_ID_PREFIX_PADDED);
}

bool
mc_copy_id_manager::is_mcg_counter_mc_copy_id(uint64_t mc_copy_id)
{
    return ((mc_copy_id & MCG_COUNTER_MC_COPY_ID_PREFIX_MASK) == MCG_COUNTER_MC_COPY_ID_PREFIX_PADDED);
}

bool
mc_copy_id_manager::is_stack_mc_copy_id(uint64_t mc_copy_id)
{
    return (mc_copy_id == m_stack_mc_copyid);
}

la_status
mc_copy_id_manager::get_mc_copy_id(const la_object_wcptr& user, bool is_wide, uint64_t& out_mc_copy_id)
{
    if ((user != nullptr) && (user->type() == la_object::object_type_e::L2_SERVICE_PORT)) {
        // L2 Service Port
        const auto& port = user.weak_ptr_static_cast<const la_l2_service_port>();
        if (port->get_port_type() != la_l2_service_port::port_type_e::PWE) {
            out_mc_copy_id = L2_AC_MC_COPY_ID_PREFIX_PADDED | port->get_gid();
            return LA_STATUS_SUCCESS;
        }
    }

    if ((user != nullptr) && (user->type() == la_object::object_type_e::L3_AC_PORT)) {
        // L3-AC
        const auto& port = user.weak_ptr_static_cast<const la_l3_ac_port>();
        out_mc_copy_id = L3_AC_MC_COPY_ID_PREFIX_PADDED | get_l3_dlp_value_from_gid(port->get_gid());
        return LA_STATUS_SUCCESS;
    }

    if ((user != nullptr) && (user->type() == la_object::object_type_e::STACK_PORT)) {
        // Stack Port
        out_mc_copy_id = m_stack_mc_copyid;
        return LA_STATUS_SUCCESS;
    }

    // Either user was not provided, or user needs the mc-cud-table
    uint64_t mc_cud_table_entry;
    la_status status = allocate(is_wide, mc_cud_table_entry);
    return_on_error(status);
    out_mc_copy_id = CUD_MAP_PREFIX_PADDED | mc_cud_table_entry;

    return LA_STATUS_SUCCESS;
}

la_status
mc_copy_id_manager::get_mc_copy_id(const la_object* user, bool is_wide, uint64_t& out_mc_copy_id)
{
    return get_mc_copy_id(m_device->get_sptr(user), is_wide, out_mc_copy_id);
}

la_status
mc_copy_id_manager::get_stack_mc_copy_id(uint64_t& out_stack_mc_copy_id)
{
    out_stack_mc_copy_id = m_stack_mc_copyid;
    return LA_STATUS_SUCCESS;
}

la_status
mc_copy_id_manager::release_mc_copy_id(uint64_t mc_copy_id)
{
    if (is_l2_ac_mc_copy_id(mc_copy_id) || is_l3_ac_mc_copy_id(mc_copy_id) || is_stack_mc_copy_id(mc_copy_id)) {
        return LA_STATUS_SUCCESS;
    }

    uint64_t mc_cud_table_entry = mc_copy_id & ~CUD_MAP_PREFIX_MASK;
    return release(mc_cud_table_entry);
}

la_status
mc_copy_id_manager::allocate(bool is_wide, uint64_t& out_entry_index)
{
    out_entry_index = is_wide ? m_index_gen.allocate_pair() : m_index_gen.allocate();
    if (out_entry_index == ranged_index_generator::INVALID_INDEX) {
        return LA_STATUS_ERESOURCE;
    }

    m_entries[out_entry_index] = is_wide;

    return LA_STATUS_SUCCESS;
}

la_status
mc_copy_id_manager::release(uint64_t entry_index)
{
    auto it = m_entries.find(entry_index);
    if (it == m_entries.end()) {
        log_err(HLD, "%s: entry not found %lu", __func__, entry_index);
        return LA_STATUS_ENOTFOUND;
    }

    m_index_gen.release(entry_index);

    bool is_wide = it->second;
    if (is_wide) {
        if ((entry_index & 1) != 0) {
            log_err(HLD, "%s: wide entry index is expected to be even %lu", __func__, entry_index);
            return LA_STATUS_EINVAL;
        }

        m_index_gen.release(entry_index + 1);
    }

    m_entries.erase(it);

    return LA_STATUS_SUCCESS;
}

la_status
mc_copy_id_manager::initialize_mc_copy_id_map()
{
    /*
    mc_copy_id_table:
            reads : mc_copy_id[17:12]
    writes:
            map_cud : whether or not cud mapping is taken from a table-> L2 and L3-AC don't use the table-> L3-SVI,MPLS and mirrors
    do
            mc_copy_id_msbs : 8 bits
            encap_type : different between L2, L3-AC and L3-SVI

    mc-copy-id is 18 bits.

    Constraints:
    - L3 has only 2 bits for the prefix so must take a full 64k in the range
    - L3 prefix must start with '11' to activate ECO on GB_A1 so HW will shift 4 bits
    - MCG counters prefix must not begin with '11' (so GB_A1 will not shift 4 bits)

    The way how it is split to L2, L3, MC counters and CUD mapping is like this:

    CUD mapping ranges:
    ============Assumed Ranges==============
    L2:            0K-128K     i.e. cud[17]    == 1'b0
    Map:          128K-160K    i.e. cud[17:15] == 3'b100
    MCG counters: 160K-192K    i.e. cud[17:15] == 3'b101
    L3:           192K-256K    i.e. cud[17:16] == 2'b11
    ========================================

    Our table is populated taking only 6 most significant bits of mc_copy_id.

    Important: the code here (i.e. mapping) must be the same as it is defined in hardware.npl
    */

    auto& table = m_device->m_tables.mc_copy_id_map[m_slice];
    npl_mc_copy_id_map_key_t k;
    npl_mc_copy_id_map_value_t v;
    v.action = NPL_MC_COPY_ID_MAP_ACTION_UPDATE;
    npl_mc_copy_id_map_entry_t* e = nullptr;

    for (size_t line = 0; line < NUM_OF_LINES_IN_MC_COPY_ID_MAP; line++) {
        k.cud_mapping_local_vars_mc_copy_id_17_12_ = line;

        // L2, L3, MC counters and CUD mapping must follow the map described above and one in hardware.npl.

        if ((line & L3_AC_MC_COPY_ID_MASK_6b) == L3_AC_MC_COPY_ID_PREFIX_6b) {
            // Detect L3
            v.payloads.update.map_cud = 0;
            v.payloads.update.encap_type = NPL_NPU_ENCAP_L3_HEADER_TYPE_ETHERNET_NH;
            v.payloads.update.mc_copy_id_msbs = line & 0b1111;
            if (m_device_revision >= la_device_revision_e::GIBRALTAR_A1) {
                // This part of the code is workaround/fix for problem "L3 CUD aligned to LSB",
                // which is resolved on GB A1 via NPL fix, but still requires slightly different setup
                // of this table.
                v.payloads.update.mc_copy_id_msbs = bit_utils::set_bits(v.payloads.update.mc_copy_id_msbs, 7, 6, 0b11);
            }
        } else if ((line & MCG_COUNTER_MC_COPY_ID_MASK_6b) == MCG_COUNTER_MC_COPY_ID_PREFIX_6b) {
            // MCG counters range - shouldn't be initialized
            // it will be initialized at la_device_impl::add_to_mc_copy_id_table()
            continue;
        } else if ((line & CUD_MAP_MASK_6b) == CUD_MAP_PREFIX_6b) {
            // CUD range
            v.payloads.update.map_cud = 1;
            v.payloads.update.encap_type = 0; // don't care
            v.payloads.update.mc_copy_id_msbs = bit_utils::get_bits(line, 2, 0);
        } else if ((line & L2_AC_MC_COPY_ID_MASK_6b) == L2_AC_MC_COPY_ID_PREFIX_6b) {
            // L2 range
            v.payloads.update.map_cud = 0;
            v.payloads.update.encap_type = NPL_NPU_ENCAP_L2_HEADER_TYPE_AC;
            v.payloads.update.mc_copy_id_msbs = line;
        } else {
            dassert_crit(!"should not get here");
        }

        la_status status = table->insert(k, v, e);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

uint64_t
mc_copy_id_manager::get_mc_cud_table_key(uint64_t mc_copy_id)
{
    // mc-copy-id of mirror commands is the mirror-command index.
    // HW accesses the mc-cud-table with the mirror-command index as the key
    // so no need for the right-shift done for other mc-copy-id's
    if (mc_copy_id < la_device_impl::MAX_MIRROR_GID) {
        return mc_copy_id;
    }

    // Direct mc-copy-id's are not expected
    dassert_ncrit((mc_copy_id & CUD_MAP_PREFIX_MASK) == CUD_MAP_PREFIX_PADDED);

    // Key to mc_cud_table is expanded-mc-copy-id[14:1]
    // expanded-mc-copy-id = {mc-copy-id-msbs(8), mc-copy-id[11:0](12)}
    // MSbits of all mc-copy-id's that need the mc-cud-table are {5'b0, mc-copy-id[14:12]}
    // ==>
    // Key = mc-copy-id[11:1]
    return bit_utils::get_bits(mc_copy_id, 14, 1);
}

// Get the MC-copy-ID from the CUD table entry index
uint64_t
mc_copy_id_manager::cud_entry_index_2_mc_copy_id(uint64_t cud_entry_index)
{
    return (CUD_MAP_PREFIX_PADDED | cud_entry_index);
}

// Get CUD table entry index from the the MC-copy-ID
uint64_t
mc_copy_id_manager::mc_copy_id_2_cud_entry_index(uint64_t mc_copy_id)
{
    return (mc_copy_id & (~CUD_MAP_PREFIX_MASK));
}

} // namespace silicon_one
