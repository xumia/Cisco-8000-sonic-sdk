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

#include "hw_tables/memory_sram.h"

#include "lld/ll_device.h"

#include "table_utils.h"

namespace silicon_one
{

memory_sram::memory_sram(const ll_device_sptr& ldevice,
                         size_t line_width,
                         const std::vector<sram_section>& sections,
                         bool section_line_reversed)
    : m_ll_device(ldevice),
      m_line_width(line_width),
      m_size(0),
      m_sections(sections),
      m_section_line_reversed(section_line_reversed)
{
    for (const sram_section& section : m_sections) {
        m_size += section.size;
    }
}

la_status
memory_sram::write(size_t line, const bit_vector& value)
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (value.get_width() != m_line_width) {
        return LA_STATUS_EINVAL;
    }

    // Memory SRAM is used as logical table where each line is of size value.size
    // Physical memory for the logical table can be constructed from several different segments of physical memory
    // Each physical line is build from several logical lines

    // The algorithm to find the proper place to write is:
    // 1. Find the proper physical segment of memory
    // 2. Find the physical line in memory
    // 3. Find the offset in the physical line
    // 3.1 the offset might be reversed meaning we need to count from the other direction 0 == entries_per_line - 1
    // entry == logic line
    size_t line_in_section;
    size_t section_idx = table_utils::find_section_idx_for_line(m_sections, line, line_in_section);
    if (!m_sections[section_idx].is_valid) {
        return LA_STATUS_EOUTOFRANGE;
    }

    size_t entries_per_line = m_sections[section_idx].entries_per_line;
    size_t line_offset = line_in_section % entries_per_line;
    if (m_section_line_reversed) {
        line_offset = entries_per_line - line_offset - 1;
    }
    line_offset *= m_line_width;         // offset is in bits
    line_in_section /= entries_per_line; // from logical line to physical

    return table_utils::write_sram_section(m_ll_device, m_sections[section_idx].srams, line_in_section, line_offset, value);
}

size_t
memory_sram::max_size() const
{
    return m_size;
}

} // namespace silicon_one
