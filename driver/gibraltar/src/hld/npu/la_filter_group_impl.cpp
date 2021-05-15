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

#include "la_filter_group_impl.h"
#include "system/la_device_impl.h"

#include "hld_utils.h"

#include "api_tracer.h"
#include "common/defines.h"
#include "common/logger.h"
#include "la_strings.h"

#include <sstream>

namespace silicon_one
{

la_filter_group_impl::la_filter_group_impl(const la_device_impl_wptr& device) : m_device(device), m_index(0)
{
}

la_filter_group_impl::~la_filter_group_impl()
{
}

la_status
la_filter_group_impl::initialize(la_object_id_t oid, uint64_t filter_group_index)
{
    la_status status = LA_STATUS_SUCCESS;
    m_oid = oid;
    m_index = filter_group_index;
    npl_l2_lp_profile_filter_table_t::entry_pointer_type l2entry = nullptr;

    npl_l2_lp_profile_filter_table_t::value_type v;
    v.action = NPL_L2_LP_PROFILE_FILTER_TABLE_ACTION_WRITE;
    v.payloads.split_horizon = 0;

    const auto& table(m_device->m_tables.l3_lp_profile_filter_table);
    npl_l3_lp_profile_filter_table_t::value_type value;

    value.action = NPL_L3_LP_PROFILE_FILTER_TABLE_ACTION_WRITE;
    value.payloads.split_horizon = 0;

    size_t entry_loc = -1;

    // All (this <-> destination) pairs need to be created
    for (uint32_t index = 0; index < la_device_impl::NUM_FILTER_GROUPS_PER_DEVICE; index++) {

        npl_l2_lp_profile_filter_table_t::key_type i;
        // (this, destination)
        i.slp_profile = m_index;
        i.lp_profile = index;
        status = m_device->m_tables.l2_lp_profile_filter_table->set(i, v, l2entry);
        return_on_error(status);

        // (destination, this)
        npl_l2_lp_profile_filter_table_t::key_type j;
        j.slp_profile = index;
        j.lp_profile = m_index;
        status = m_device->m_tables.l2_lp_profile_filter_table->set(j, v, l2entry);
        return_on_error(status);
    }

    // There are 16 filter groups supported today.
    // Initialize function should be ideally called once on device creation,
    // and all 16 enrties should be initialized.
    // Currently it is called everytime when filter group is created.
    // So we only need to initialie only 4 possible combinations for this given filter_group_index.
    //
    // Filter group created with index 0, then we initialse (0,0), (0,1), (0,2 and (0,3)
    // Filter group created with index 1, then we initialse (1,0), (1,1), (1,2 and (1,3)
    // Filter group created with index 2, then we initialse (2,0), (2,1), (2,2 and (2,3)
    // Filter group created with index 3, then we initialse (3,0), (3,1), (3,2 and (3,3)

    for (uint32_t index = 0; index < ((la_device_impl::NUM_FILTER_GROUPS_PER_DEVICE) / 4); index++) {
        // L3 filter table
        // (this, destination)
        npl_l3_lp_profile_filter_table_t::key_type key;
        npl_l3_lp_profile_filter_table_t::key_type mask;

        key.slp_profile = m_index;
        key.lp_profile = index;
        mask.slp_profile = 0x3;
        mask.lp_profile = 0x3;

        entry_loc = -1;
        status = table->locate_first_free_entry(entry_loc);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to find free entry in l3_lp_profile_filter_table (%s)", la_status2str(status).c_str());
            return status;
        }

        // insert in the free location
        npl_l3_lp_profile_filter_table_t::entry_type* l3entry;
        status = table->insert(entry_loc, key, mask, value, l3entry);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "insert profile entry in l3_lp_profile_filter_table failed");
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_filter_group_impl::destroy()
{
    // All (this <-> destination) pairs need to be deleted from table
    for (uint32_t index = 0; index < la_device_impl::NUM_FILTER_GROUPS_PER_DEVICE; index++) {
        npl_l2_lp_profile_filter_table_t::key_type i;
        npl_l2_lp_profile_filter_table_t::key_type j;

        // (this, destination)
        i.slp_profile = m_index;
        i.lp_profile = index;
        // (destination, this)
        j.slp_profile = index;
        j.lp_profile = m_index;

        // Update
        la_status status = m_device->m_tables.l2_lp_profile_filter_table->erase(i);
        // Potentially empty entries, if not found or deleted - success
        if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
            return status;
        }

        status = m_device->m_tables.l2_lp_profile_filter_table->erase(j);
        if (status != LA_STATUS_SUCCESS && status != LA_STATUS_ENOTFOUND) {
            return status;
        }
    }

    const auto& table(m_device->m_tables.l3_lp_profile_filter_table);
    for (uint32_t index = 0; index < ((la_device_impl::NUM_FILTER_GROUPS_PER_DEVICE) / 4); index++) {
        // Remove L3 entry
        // (this, destination)
        npl_l3_lp_profile_filter_table_t::key_type key;
        npl_l3_lp_profile_filter_table_t::key_type mask;

        key.slp_profile = m_index;
        key.lp_profile = index;
        mask.slp_profile = 0x3;
        mask.lp_profile = 0x3;

        size_t entry_loc;
        npl_l3_lp_profile_filter_table_t::entry_type* l3entry;
        la_status status = table->find(key, mask, l3entry, entry_loc);

        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "failed to find filter group entry in l3_lp_profile_filter_table (%s)", la_status2str(status).c_str());
            return status;
        }

        // Remove entry
        status = table->erase(entry_loc);
        if (status != LA_STATUS_SUCCESS) {
            log_err(HLD, "l3_lp_profile_filter_table deletion failed (%s), for filter group", la_status2str(status).c_str());
            return status;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_filter_group_impl::get_filtering_mode(const la_filter_group* dest_group, filtering_mode_e& out_mode)
{
    if (dest_group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(dest_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    const la_filter_group_impl* dest_group_impl = static_cast<const la_filter_group_impl*>(dest_group);

    npl_l2_lp_profile_filter_table_t::key_type k;
    npl_l2_lp_profile_filter_table_t::entry_pointer_type entry = nullptr;

    k.slp_profile = m_index;
    k.lp_profile = dest_group_impl->get_id();

    la_status status = m_device->m_tables.l2_lp_profile_filter_table->lookup(k, entry);
    return_on_error(status);

    out_mode = filtering_mode_e::PERMIT;
    const npl_l2_lp_profile_filter_table_t::value_type& val = entry->value();
    if (val.payloads.split_horizon) {
        out_mode = filtering_mode_e::DENY;
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_filter_group_impl::set_filtering_mode(const la_filter_group* dest_group, filtering_mode_e mode)
{
    start_api_call("dest_group=", dest_group, "mode=", mode);
    if (dest_group == nullptr) {
        return LA_STATUS_EINVAL;
    }

    if (!of_same_device(dest_group, this)) {
        return LA_STATUS_EDIFFERENT_DEVS;
    }

    // Update (source profile, destination profile) bitmap with 1 where applicable.
    // Only maintain blocked values in the bitmap.
    const la_filter_group_impl* dest_group_impl = static_cast<const la_filter_group_impl*>(dest_group);

    npl_l2_lp_profile_filter_table_t::key_type k;
    npl_l2_lp_profile_filter_table_t::value_type v;
    npl_l2_lp_profile_filter_table_t::entry_pointer_type l2entry = nullptr;

    k.slp_profile = m_index;
    k.lp_profile = dest_group_impl->get_id();

    v.action = NPL_L2_LP_PROFILE_FILTER_TABLE_ACTION_WRITE;
    v.payloads.split_horizon = (mode == filtering_mode_e::PERMIT) ? 0 : 1;

    la_status status = m_device->m_tables.l2_lp_profile_filter_table->set(k, v, l2entry);
    return_on_error(status);

    /* L3 Filter table */
    const auto& table(m_device->m_tables.l3_lp_profile_filter_table);
    npl_l3_lp_profile_filter_table_t::key_type key;
    npl_l3_lp_profile_filter_table_t::key_type mask;
    npl_l3_lp_profile_filter_table_t::value_type value;

    key.slp_profile = m_index;
    key.lp_profile = dest_group_impl->get_id();
    mask.slp_profile = 0x3;
    mask.lp_profile = 0x3;

    npl_l3_lp_profile_filter_table_t::entry_type* l3entry;

    size_t entry_loc = -1;
    status = table->find(key, mask, l3entry, entry_loc);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "failed to find the entry in l3_lp_profile_filter_table (%s)", la_status2str(status).c_str());
        return status;
    }

    value.action = NPL_L3_LP_PROFILE_FILTER_TABLE_ACTION_WRITE;
    value.payloads.split_horizon = (mode == filtering_mode_e::PERMIT) ? 0 : 1;

    // Update entry value
    status = table->set_entry_value(l3entry, value);
    if (status != LA_STATUS_SUCCESS) {
        log_err(HLD, "updating etnry in l3_lp_profile_filter_table failed");
        return status;
    }

    return LA_STATUS_SUCCESS;
}

la_object::object_type_e
la_filter_group_impl::type() const
{
    return object_type_e::FILTER_GROUP;
}

std::string
la_filter_group_impl::to_string() const
{
    std::stringstream log_message;
    log_message << "la_filter_group_impl(oid=" << m_oid << ")";
    return log_message.str();
}

la_object_id_t
la_filter_group_impl::oid() const
{
    return m_oid;
}

const la_device*
la_filter_group_impl::get_device() const
{
    return m_device.get();
}

uint64_t
la_filter_group_impl::get_id() const
{
    return m_index;
}
}
