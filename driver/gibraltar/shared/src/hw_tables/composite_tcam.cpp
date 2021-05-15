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

#include "hw_tables/composite_tcam.h"
#include "common/defines.h"

namespace silicon_one
{

composite_tcam::composite_tcam(const std::vector<logical_tcam_sptr>& tcams) : m_tcams(tcams)
{
}

la_status
composite_tcam::write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    for (const logical_tcam_sptr& tcam : m_tcams) {
        la_status status = tcam->write(line, key, mask, value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
composite_tcam::write_bulk(size_t first_line, size_t bulk_size, const vector_alloc<tcam_entry_desc>& entries)
{
    for (const logical_tcam_sptr& tcam : m_tcams) {
        la_status status = tcam->write_bulk(first_line, bulk_size, entries);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
composite_tcam::move(size_t src_line, size_t dest_line)
{
    for (const logical_tcam_sptr& tcam : m_tcams) {
        la_status status = tcam->move(src_line, dest_line);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}
la_status
composite_tcam::update(size_t line, const bit_vector& value)
{
    for (const logical_tcam_sptr& tcam : m_tcams) {
        la_status status = tcam->update(line, value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
composite_tcam::invalidate(size_t line)
{
    for (const logical_tcam_sptr& tcam : m_tcams) {
        la_status status = tcam->invalidate(line);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

la_status
composite_tcam::read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const
{
    la_status ret = m_tcams[0]->read(line, out_key, out_mask, out_value, out_valid);

    return ret;
}

la_status
composite_tcam::set_default_value(const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    for (const logical_tcam_sptr& tcam : m_tcams) {
        la_status status = tcam->set_default_value(key, mask, value);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
composite_tcam::size() const
{
    size_t ret = (size_t)-1;

    for (const logical_tcam_sptr& tcam : m_tcams) {
        size_t size = tcam->size();
        ret = std::min(size, ret);
    }
    return ret;
}

la_status
composite_tcam::get_max_available_space(size_t& out_max_scale) const
{
    size_t smallest_max_scale = (size_t)-1;
    for (const logical_tcam_sptr& tcam : m_tcams) {
        size_t translator_max_scale;
        la_status status = tcam->get_max_available_space(translator_max_scale);
        return_on_error(status);
        smallest_max_scale = std::min(smallest_max_scale, translator_max_scale);
    }
    out_max_scale = smallest_max_scale;
    return LA_STATUS_SUCCESS;
}

la_status
composite_tcam::get_physical_usage(size_t& out_physical_usage) const
{
    size_t max_usage = 0;
    for (const logical_tcam_sptr& tcam : m_tcams) {
        size_t tcam_usage;
        la_status status = tcam->get_physical_usage(tcam_usage);
        return_on_error(status);
        max_usage = std::max(tcam_usage, max_usage);
    }
    out_physical_usage = max_usage;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
