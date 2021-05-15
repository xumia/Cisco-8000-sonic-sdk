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

#include "hw_tables/memory_tcam.h"

#include "lld/ll_device.h"

#include "common/defines.h"
#include "table_utils.h"

namespace silicon_one
{

memory_tcam::memory_tcam(const ll_device_sptr& ldevice,
                         size_t key_width,
                         size_t value_width,
                         const std::vector<tcam_section>& sections)
    : m_ll_device(ldevice), m_key_width(key_width), m_value_width(value_width), m_size(0), m_sections(sections)
{
    for (const tcam_section& section : m_sections) {
        m_size += section.size;
    }
}

la_status
memory_tcam::write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (value.get_width() != m_value_width || key.get_width() != m_key_width || mask.get_width() != m_key_width) {
        return LA_STATUS_EINVAL;
    }
    la_status status = write_unsafe(line, key, mask, value, false);

    return status;
}

la_status
memory_tcam::write_bulk(size_t first_line, size_t bulk_size, const vector_alloc<tcam_entry_desc>& entries)
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

bool
memory_tcam::is_valid(size_t line) const
{
    size_t section_line;
    size_t section_idx = table_utils::find_section_idx_for_line(m_sections, line, section_line);

    bool valid = false;
    bit_vector key;
    bit_vector mask;
    table_utils::read_tcam_section(m_ll_device, m_sections[section_idx].tcams, section_line, key, mask, valid);

    return valid;
}

la_status
memory_tcam::write_unsafe(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value, bool multiple_sram)
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    dassert_crit(!m_ll_device->get_write_to_device() || !is_valid(line));

    size_t section_line;
    size_t section_idx = table_utils::find_section_idx_for_line(m_sections, line, section_line);

    // sram
    la_status status = LA_STATUS_SUCCESS;
    if (multiple_sram) {
        status = table_utils::write_sram_section_with_multiple_mem(
            m_ll_device, m_sections[section_idx].srams, section_line, 0 /*offset*/, value);
    } else {
        status = table_utils::write_sram_section(m_ll_device, m_sections[section_idx].srams, section_line, 0 /*offset*/, value);
    }
    return_on_error(status);

    // tcam
    status = table_utils::write_tcam_section(m_ll_device, m_sections[section_idx].tcams, section_line, key, mask);

    return status;
}

la_status
memory_tcam::move(size_t src_line, size_t dest_line)
{
    if (src_line >= m_size || dest_line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status status = LA_STATUS_SUCCESS;

    // src section
    size_t src_section_line;
    size_t src_section_idx = table_utils::find_section_idx_for_line(m_sections, src_line, src_section_line);

    // read tcam
    bool is_valid = false;
    bit_vector key;
    bit_vector mask;
    status = table_utils::read_tcam_section(m_ll_device, m_sections[src_section_idx].tcams, src_section_line, key, mask, is_valid);
    return_on_error(status);

    if (!is_valid) {
        // If source line is invalid - just invalidate destination and finish.
        return memory_tcam::invalidate(dest_line);
    }

    // read sram
    bit_vector value;
    status = table_utils::read_sram_section(m_ll_device, m_sections[src_section_idx].srams, src_section_line, value);
    return_on_error(status);

    // dest section
    size_t dest_section_line;
    size_t dest_section_idx = table_utils::find_section_idx_for_line(m_sections, dest_line, dest_section_line);

    // write sram
    status
        = table_utils::write_sram_section(m_ll_device, m_sections[dest_section_idx].srams, dest_section_line, 0 /*offset*/, value);
    return_on_error(status);

    // write tcam
    status = table_utils::write_tcam_section(m_ll_device, m_sections[dest_section_idx].tcams, dest_section_line, key, mask);
    return_on_error(status);

    // invalidate src line
    status = memory_tcam::invalidate(src_line);

    return status;
}

la_status
memory_tcam::update(size_t line, const bit_vector& value)
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (value.get_width() != m_value_width) {
        return LA_STATUS_EINVAL;
    }

    la_status status = update_unsafe(line, value);

    return status;
}

la_status
memory_tcam::update_unsafe(size_t line, const bit_vector& value)
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t section_line;
    size_t section_idx = table_utils::find_section_idx_for_line(m_sections, line, section_line);

    // sram
    la_status status
        = table_utils::write_sram_section(m_ll_device, m_sections[section_idx].srams, section_line, 0 /*offset*/, value);

    return status;
}

la_status
memory_tcam::invalidate(size_t line)
{
    // line is got adjusted
    size_t section_offset;
    size_t section_idx = table_utils::find_section_idx_for_line(m_sections, line, section_offset);

    for (const physical_tcam& tcam : m_sections[section_idx].tcams) {
        for (const lld_memory_scptr& mem : tcam.memories) {
            size_t resource_line = tcam.start_line + section_offset;
            la_status status = m_ll_device->invalidate_tcam(*mem, resource_line);
            return_on_error(status);
        }
    }

    return LA_STATUS_SUCCESS;
}

la_status
memory_tcam::set_default_value(const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    if (value.get_width() != m_value_width || key.get_width() != m_key_width || mask.get_width() != m_key_width) {
        return LA_STATUS_EINVAL;
    }

    return set_default_value_unsafe(key, mask, value);
}

la_status
memory_tcam::set_default_value_unsafe(const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    const tcam_section& last_section = m_sections.back();
    size_t line = last_section.size;
    // sram
    la_status status = table_utils::write_sram_section(m_ll_device, last_section.srams, line, 0 /*offset*/, value);
    return_on_error(status);

    // tcam
    status = table_utils::write_tcam_section(m_ll_device, last_section.tcams, line, key, mask);

    return status;
}

la_status
memory_tcam::read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    // src section
    size_t src_section_line;
    size_t src_section_idx = table_utils::find_section_idx_for_line(m_sections, line, src_section_line);

    // read tcam
    bit_vector key;
    bit_vector mask;
    la_status status = table_utils::read_tcam_section(
        m_ll_device, m_sections[src_section_idx].tcams, src_section_line, out_key, out_mask, out_valid);
    return_on_error(status);

    if (!out_valid) {
        // If source line is invalid - no need to read the SRAM.
        return LA_STATUS_SUCCESS;
    }

    // read sram
    status = table_utils::read_sram_section(m_ll_device, m_sections[src_section_idx].srams, src_section_line, out_value);
    return_on_error(status);

    return status;
}

size_t
memory_tcam::size() const
{
    return m_size;
}

la_status
memory_tcam::get_max_available_space(size_t& out_max_scale) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

la_status
memory_tcam::get_physical_usage(size_t& out_physical_usage) const
{
    return LA_STATUS_ENOTIMPLEMENTED;
}

} // namespace silicon_one
