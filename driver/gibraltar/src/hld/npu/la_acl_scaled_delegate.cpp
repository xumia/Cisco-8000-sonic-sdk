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

#include "la_acl_scaled_delegate.h"
#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l3_destination.h"
#include "nplapi/npl_types.h"
#include "system/la_device_impl.h"

#include "common/defines.h"
#include "common/logger.h"
#include "hld_utils.h"
#include "nplapi/npl_table_types.h"

namespace silicon_one
{

la_acl_scaled_delegate::la_acl_scaled_delegate(const la_device_impl_wptr& device, const la_acl_wptr& parent)
    : la_acl_delegate(device, parent)
{
}

la_acl_scaled_delegate::~la_acl_scaled_delegate()
{
}

// la_object API-s

// la_acl API-s
la_status
la_acl_scaled_delegate::clear()
{
    for (size_t i = (size_t)la_acl_scaled::scale_field_e::SIP; i < (size_t)la_acl_scaled::scale_field_e::LAST; i++) {

        while (m_scale_field_entries[i].size() > 0) {
            la_status status = erase((la_acl_scaled::scale_field_e)i, 0);
            return_on_error(status);
        }
    }

    return la_acl_delegate::clear();
}

// la_acl_scaled API-s
la_status
la_acl_scaled_delegate::get_count(la_acl_scaled::scale_field_e scale_field, size_t& out_count) const
{
    if ((scale_field == la_acl_scaled::scale_field_e::UNDEF) || (scale_field >= la_acl_scaled::scale_field_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    out_count = m_scale_field_entries[(int)scale_field].size();

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_scaled_delegate::append(la_acl_scaled::scale_field_e scale_field,
                               const la_acl_scale_field_key& sf_key,
                               const la_acl_scale_field_val& sf_val)
{
    if ((scale_field == la_acl_scaled::scale_field_e::UNDEF) || (scale_field >= la_acl_scaled::scale_field_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    return insert(scale_field, m_scale_field_entries[(int)scale_field].size(), sf_key, sf_val);
}

la_status
la_acl_scaled_delegate::insert(la_acl_scaled::scale_field_e scale_field,
                               size_t position,
                               const la_acl_scale_field_key& sf_key,
                               const la_acl_scale_field_val& sf_val)
{
    if ((scale_field == la_acl_scaled::scale_field_e::UNDEF) || (scale_field >= la_acl_scaled::scale_field_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    auto& entries = m_scale_field_entries[(int)scale_field];

    position = std::max(position, entries.size());

    for (auto slice : m_ifg_use_count->get_slices()) {
        // locate empty line after last entity
        size_t index = 0;

        if (position > 0) {
            // Locate the last ACE before the required position
            la_status status = get_tcam_line_index(slice, scale_field, position - 1, index);
            return_on_error(status);
        }

        // update table
        la_status status = set_tcam_line(slice, scale_field, index + 1, true /* push */, sf_key, sf_val);
        if (status == LA_STATUS_ERESOURCE) {
            // TODO: add resource and retry
            return status;
        }

        return_on_error(status);
    }

    entries.emplace(entries.begin() + position, sf_key, sf_val);
    return LA_STATUS_SUCCESS;
}

la_status
la_acl_scaled_delegate::set(la_acl_scaled::scale_field_e scale_field,
                            size_t position,
                            const la_acl_scale_field_key& sf_key,
                            const la_acl_scale_field_val& sf_val)
{
    if ((scale_field == la_acl_scaled::scale_field_e::UNDEF) || (scale_field >= la_acl_scaled::scale_field_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    auto& entries = m_scale_field_entries[(int)scale_field];

    // Check arguments
    if (position >= entries.size()) {
        return LA_STATUS_EINVAL;
    }

    for (auto slice : m_ifg_use_count->get_slices()) {
        // locate the entity
        size_t index = 0;

        la_status status = get_tcam_line_index(slice, scale_field, position, index);
        return_on_error(status);

        // update table - erase the current and add the updated
        status = erase_tcam_line(slice, scale_field, index);
        return_on_error(status);

        status = set_tcam_line(slice, scale_field, index, false /* push */, sf_key, sf_val);
        return_on_error(status);
    }

    entries[position] = std::make_pair(sf_key, sf_val);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_scaled_delegate::erase(la_acl_scaled::scale_field_e scale_field, size_t position)
{
    if ((scale_field == la_acl_scaled::scale_field_e::UNDEF) || (scale_field >= la_acl_scaled::scale_field_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    auto& entries = m_scale_field_entries[(int)scale_field];

    for (auto slice : m_ifg_use_count->get_slices()) {
        // locate the entity
        size_t index = 0;

        la_status status = get_tcam_line_index(slice, scale_field, position, index);
        return_on_error(status);

        // update table - erase
        status = erase_tcam_line(slice, scale_field, index);
        return_on_error(status);
    }

    entries.erase(entries.begin() + position);

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_scaled_delegate::get(la_acl_scaled::scale_field_e scale_field,
                            size_t position,
                            const la_acl_scale_field_key*& out_sf_key,
                            const la_acl_scale_field_val*& out_sf_val)
{
    if ((scale_field == la_acl_scaled::scale_field_e::UNDEF) || (scale_field >= la_acl_scaled::scale_field_e::LAST)) {
        return LA_STATUS_EINVAL;
    }

    return LA_STATUS_ENOTIMPLEMENTED;
}

// Helper functions

la_status
la_acl_scaled_delegate::get_tcam_line_index(la_slice_id_t slice,
                                            la_acl_scaled::scale_field_e scale_field,
                                            size_t position,
                                            size_t& tcam_line_index) const
{
    size_t tcam_size = get_tcam_size(slice, scale_field);

    // locate the entity
    size_t ent_found = 0; // Count entities

    for (size_t index = 0; (index < tcam_size) && (ent_found <= position); index++) {
        bool contains;
        la_status status = is_tcam_line_contains(slice, scale_field, index, contains);
        return_on_error(status);

        if (!contains) {
            continue;
        }

        ent_found++;

        if (ent_found > position) {
            tcam_line_index = index;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ENOTFOUND;
}

la_status
la_acl_scaled_delegate::add_tcam_entries_to_slice(la_slice_id_t slice)
{
    log_debug(HLD, "la_acl_scaled_delegate::add_tcam_entries_to_slice %d", slice);

    // First confirm there is enough room for the scale entries.
    for (auto scale_field : {la_acl_scaled::scale_field_e::SIP, la_acl_scaled::scale_field_e::DIP}) {
        auto& entries = m_scale_field_entries[(int)scale_field];

        if (entries.size() + get_tcam_fullness(slice, scale_field) > get_tcam_size(slice, scale_field)) {
            log_err(HLD,
                    "Insufficient TCAM space to program SCALE field on slice %d. Reqd %ld, Fullness: %ld/%ld",
                    slice,
                    entries.size(),
                    get_tcam_fullness(slice, scale_field),
                    get_tcam_size(slice, scale_field));

            return LA_STATUS_ERESOURCE;
        }
    }

    // Program the ACE's
    la_status status = la_acl_delegate::add_tcam_entries_to_slice(slice);
    return_on_error(status, HLD, ERROR, "programming scaled acl final table failed on slice %d", slice);

    // Program the scale entries
    for (auto scale_field : {la_acl_scaled::scale_field_e::SIP, la_acl_scaled::scale_field_e::DIP}) {
        auto& entries = m_scale_field_entries[(int)scale_field];

        log_debug(HLD, "scaled acl, programming scale_field %d to slice %d", (int)scale_field, slice);

        size_t prev = 0;
        for (const auto& entry : entries) {
            size_t position = 0;
            la_status status = locate_free_tcam_entry(slice, scale_field, prev, position);
            return_on_error(status);

            status = set_tcam_line(slice, scale_field, position, false, entry.first, entry.second);
            return_on_error(status);

            prev = position;
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
la_acl_scaled_delegate::remove_tcam_entries_from_slice(la_slice_id_t slice)
{
    log_debug(HLD, "la_acl_scaled_delegate::remove_tcam_entries_from_slice %d", slice);

    for (auto scale_field : {la_acl_scaled::scale_field_e::SIP, la_acl_scaled::scale_field_e::DIP}) {
        for (size_t i = 0; i < m_scale_field_entries[(int)scale_field].size(); ++i) {
            size_t index = 0;

            la_status status = get_tcam_line_index(slice, scale_field, 0, index);
            return_on_error(status);

            status = erase_tcam_line(slice, scale_field, index);
            return_on_error(status);
        }
    }

    return la_acl_delegate::remove_tcam_entries_from_slice(slice);
}

} // namespace silicon_one
