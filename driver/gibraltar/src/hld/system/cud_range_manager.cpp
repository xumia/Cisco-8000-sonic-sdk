// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "cud_range_manager.h"
#include "common/defines.h"
#include "nplapi/npl_table_types.h"
#include "system/la_device_impl.h"

namespace silicon_one
{

cud_range_manager::cud_range_manager(const la_device_impl_wptr& device, la_slice_id_t slice)
    : m_device(device), m_slice(slice), m_is_initialized(false), m_is_used({{}})
{
}

la_status
cud_range_manager::initialize()
{

    for (size_t range = 0; range < NUM_CUD_RANGES; range++) {
        m_index_gen[range] = ranged_index_generator(0, NUM_ENTRIES_IN_CUD_RANGE, true /*allow_pairs*/);
    }

    m_is_initialized = true;

    // First entries are reserved for IBM
    for (size_t ibm = 0; ibm < la_device_impl::MAX_MIRROR_GID; ibm++) {
        uint64_t cud_entry_index;
        la_status status = allocate(true /*is_wide*/, cud_entry_index);
        return_on_error(status);

        dassert_crit(cud_entry_index == ibm * NUM_ENTRIES_PER_WIDE_CUD); // Range is always 0
    }

    return LA_STATUS_SUCCESS;
}

la_status
cud_range_manager::destroy()
{
    // Release the range that was allocated for IBM at initialization
    size_t range = 0;
    la_status status = release_mc_cud_is_wide_entry(range);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "cud_range_manager::%s: table configuration failed %s", __func__, la_status2str(status).c_str());
        return status;
    }

    m_is_used[range] = false;

    return LA_STATUS_SUCCESS;
}

uint64_t
cud_range_manager::make_cud_entry_index(size_t range, uint64_t id)
{
    return (range << NUM_ENTRY_BITS) | (id & ENTRY_MASK);
}

la_status
cud_range_manager::configure_mc_cud_is_wide_entry(size_t range, bool is_wide)
{
    npl_mc_cud_is_wide_table_t::key_type k;
    npl_mc_cud_is_wide_table_t::value_type v;
    npl_mc_cud_is_wide_table_t::entry_pointer_type e = nullptr;

    k.cud_mapping_local_vars_mc_copy_id_12_7_ = range;
    v.action = NPL_MC_CUD_IS_WIDE_TABLE_ACTION_WRITE;
    v.payloads.cud_mapping_local_vars_mc_cud_is_wide = is_wide;

    return m_device->m_tables.mc_cud_is_wide_table[m_slice]->insert(k, v, e);
}

la_status
cud_range_manager::release_mc_cud_is_wide_entry(size_t range)
{
    npl_mc_cud_is_wide_table_t::key_type k;

    k.cud_mapping_local_vars_mc_copy_id_12_7_ = range;

    return m_device->m_tables.mc_cud_is_wide_table[m_slice]->erase(k);
}

la_status
cud_range_manager::allocate(bool is_wide, uint64_t& out_cud_entry_index)
{
    if (!m_is_initialized) {
        log_err(HLD, "cud_range_manager::%s: not initialized", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    for (size_t range = 0; range < NUM_CUD_RANGES; range++) {
        if (m_is_used[range] && (m_is_wide[range] == is_wide)) {
            uint64_t id = is_wide ? m_index_gen[range].allocate_pair() : m_index_gen[range].allocate();
            if (id != ranged_index_generator::INVALID_INDEX) {
                out_cud_entry_index = make_cud_entry_index(range, id);
                return LA_STATUS_SUCCESS;
            }
        }
    }

    // No matching used range was found. Try to find a free range
    size_t new_range;
    for (new_range = 0; new_range < NUM_CUD_RANGES; new_range++) {
        if (!m_is_used[new_range]) {
            break;
        }
    }

    if (new_range == NUM_CUD_RANGES) {
        log_err(HLD, "cud_range_manager::%s: no matching CUD index was found", __func__);
        return LA_STATUS_ERESOURCE;
    }

    la_status status = configure_mc_cud_is_wide_entry(new_range, is_wide);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "cud_range_manager::%s: table configuration failed %s", __func__, la_status2str(status).c_str());
        return status;
    }

    m_is_used[new_range] = true;
    m_is_wide[new_range] = is_wide;
    uint64_t id = is_wide ? m_index_gen[new_range].allocate_pair() : m_index_gen[new_range].allocate();
    if (id == ranged_index_generator::INVALID_INDEX) {
        log_err(HLD, "cud_range_manager::%s: allocation failed", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    out_cud_entry_index = make_cud_entry_index(new_range, id);

    return LA_STATUS_SUCCESS;
}

la_status
cud_range_manager::release(uint64_t cud_entry_index)
{
    if (!m_is_initialized) {
        log_err(HLD, "cud_range_manager::%s: not initialized", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    size_t range = ((cud_entry_index >> NUM_ENTRY_BITS) & RANGE_MASK);
    uint64_t id = (cud_entry_index & ENTRY_MASK);

    // It's assumed that initialize() will allocate range==0 for IBM entries
    if ((range == 0) && (id < la_device_impl::MAX_MIRROR_GID)) {
        log_err(HLD, "cud_range_manager::%s: cannot release IBM entries", __func__);
        return LA_STATUS_EUNKNOWN;
    }

    if (!m_is_used[range]) {
        log_err(HLD, "cud_range_manager::%s: unexpected range cud_entry_index=%lx", __func__, cud_entry_index);
        return LA_STATUS_EUNKNOWN;
    }

    m_index_gen[range].release(id);
    if (m_is_wide[range]) {
        m_index_gen[range].release(id + 1);
    }

    // Check if the range can be released
    bool is_range_used = (m_index_gen[range].size() > 0);

    if (is_range_used) {
        return LA_STATUS_SUCCESS;
    }

    // Release the range
    la_status status = release_mc_cud_is_wide_entry(range);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "cud_range_manager::%s: table configuration failed %s", __func__, la_status2str(status).c_str());
        return status;
    }

    m_is_used[range] = false;

    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
