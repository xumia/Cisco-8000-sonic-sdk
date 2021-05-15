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

#include "special_tables/ctm_tcam.h"
#include "special_tables/ctm_mgr.h"

#include <tuple>

namespace silicon_one
{

ctm_tcam::ctm_tcam(ctm::table_desc curr_table,
                   ctm::group_desc group_id,
                   size_t logical_db_id,
                   size_t key_width,
                   size_t value_width,
                   const ctm_mgr_sptr& _ctm_mgr)
    : m_table_id(curr_table), m_key_width(key_width), m_value_width(value_width), m_ctm_mgr(_ctm_mgr)
{
    m_ctm_mgr->register_table_to_group(group_id, curr_table, logical_db_id);
    m_size = m_ctm_mgr->get_table_size(curr_table);
}

la_status
ctm_tcam::write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    auto expected_key = std::make_tuple(m_value_width, m_key_width, m_key_width);
    auto new_key = std::make_tuple(value.get_width(), key.get_width(), mask.get_width());
    if (expected_key != new_key) {
        return LA_STATUS_EINVAL;
    }

    return m_ctm_mgr->write(m_table_id, line, key, mask, value);
}

la_status
ctm_tcam::write_bulk(size_t first_line, size_t bulk_size, const vector_alloc<tcam_entry_desc>& entries)
{
    auto expected_key = std::make_tuple(m_value_width, m_key_width, m_key_width);
    for (size_t i = 0; i < bulk_size; i++) {
        auto new_key = std::make_tuple(entries[i].value.get_width(), entries[i].key.get_width(), entries[i].mask.get_width());
        if (expected_key != new_key) {
            return LA_STATUS_EINVAL;
        }
    }

    return m_ctm_mgr->write_bulk(m_table_id, first_line, bulk_size, entries);
}

la_status
ctm_tcam::move(size_t src_line, size_t dest_line)
{
    return m_ctm_mgr->move(m_table_id, src_line, dest_line);
}

la_status
ctm_tcam::update(size_t line, const bit_vector& value)
{
    if (value.get_width() != m_value_width) {
        return LA_STATUS_EINVAL;
    }

    return m_ctm_mgr->update(m_table_id, line, value);
}

la_status
ctm_tcam::invalidate(size_t line)
{
    return m_ctm_mgr->invalidate(m_table_id, line);
}

la_status
ctm_tcam::read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const
{
    return m_ctm_mgr->read(m_table_id, line, out_key, out_mask, out_value, out_valid);
}

la_status
ctm_tcam::set_default_value(const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    if (value.get_width() != m_value_width || key.get_width() != m_key_width || mask.get_width() != m_key_width) {
        return LA_STATUS_EINVAL;
    }

    return m_ctm_mgr->set_default_value(m_table_id, key, mask, value);
}

size_t
ctm_tcam::size() const
{
    return m_size;
}

la_status
ctm_tcam::get_max_available_space(size_t& out_available_space) const
{
    out_available_space = m_ctm_mgr->get_max_available_space(m_table_id);
    return LA_STATUS_SUCCESS;
}

la_status
ctm_tcam::get_physical_usage(size_t& out_physical_usage) const
{
    out_physical_usage = m_ctm_mgr->get_table_usage(m_table_id);
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
