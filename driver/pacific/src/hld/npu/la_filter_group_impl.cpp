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
    npl_l2_lp_profile_filter_table_t::entry_pointer_type entry = nullptr;

    npl_l2_lp_profile_filter_table_t::value_type v;
    v.action = NPL_L2_LP_PROFILE_FILTER_TABLE_ACTION_WRITE;
    v.payloads.split_horizon = 0;

    // All (this <-> destination) pairs need to be created
    for (uint32_t index = 0; index < la_device_impl::NUM_FILTER_GROUPS_PER_DEVICE; index++) {

        npl_l2_lp_profile_filter_table_t::key_type i;
        // (this, destination)
        i.slp_profile = m_index;
        i.lp_profile = index;
        status = m_device->m_tables.l2_lp_profile_filter_table->set(i, v, entry);
        return_on_error(status);

        // (destination, this)
        npl_l2_lp_profile_filter_table_t::key_type j;
        j.slp_profile = index;
        j.lp_profile = m_index;
        status = m_device->m_tables.l2_lp_profile_filter_table->set(j, v, entry);
        return_on_error(status);
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
    npl_l2_lp_profile_filter_table_t::entry_pointer_type entry = nullptr;

    k.slp_profile = m_index;
    k.lp_profile = dest_group_impl->get_id();

    v.action = NPL_L2_LP_PROFILE_FILTER_TABLE_ACTION_WRITE;
    v.payloads.split_horizon = (mode == filtering_mode_e::PERMIT) ? 0 : 1;

    la_status status = m_device->m_tables.l2_lp_profile_filter_table->set(k, v, entry);
    return_on_error(status);

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
