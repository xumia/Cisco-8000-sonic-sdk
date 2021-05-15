// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#include "resolution_configurator_impl.h"

namespace silicon_one
{

resolution_ad_entry_allocator::resolution_ad_entry_allocator(la_uint32_t ad_table_size) : m_table_size(ad_table_size)
{
}

la_status
resolution_ad_entry_allocator::allocate(npl_resolution_assoc_data_entry_type_e entry_type,
                                        resolution_assoc_data_table_addr_t& out_entry_addr)
{
    for (auto& line : m_occupied_lines) {
        la_status status = alloc_line_entry(line.second, entry_type, out_entry_addr.select);
        if (status == LA_STATUS_SUCCESS) {
            out_entry_addr.index = line.first;
            return status;
        }
    }

    // No free entry within the occupied lines was found, allocate new line
    for (la_uint32_t line_index = 0; line_index < m_table_size; line_index++) {
        if (m_occupied_lines.find(line_index) == m_occupied_lines.end()) {
            ad_table_line_t table_line{entry_type, 0x1};
            m_occupied_lines[line_index] = table_line;

            out_entry_addr.index = line_index;
            out_entry_addr.select = 0;
            return LA_STATUS_SUCCESS;
        }
    }

    return LA_STATUS_ERESOURCE;
}

la_status
resolution_ad_entry_allocator::release(const resolution_assoc_data_table_addr_t& entry_addr)
{
    auto it = m_occupied_lines.find(entry_addr.index);
    if (it == m_occupied_lines.end()) {
        return LA_STATUS_ENOTFOUND;
    }

    it->second.allocated_entries_mask = bit_utils::set_bit(it->second.allocated_entries_mask, entry_addr.select, false);
    if (!it->second.allocated_entries_mask) {
        m_occupied_lines.erase(it);
    }

    return LA_STATUS_SUCCESS;
}

bool
resolution_ad_entry_allocator::is_line_allocated(la_uint32_t index) const
{
    auto it = m_occupied_lines.find(index);
    return it != m_occupied_lines.end();
}

la_uint8_t
resolution_ad_entry_allocator::get_line_entries_num_per_type(const npl_resolution_assoc_data_entry_type_e entry_type)
{
    // lookup table, index is line/entry type
    static constexpr la_uint8_t type_to_entries_num[4]
        = {NARROW_ENTRIES_PER_LINE, WIDE_ENTRIES_PER_LINE, NARROW_PROTECTED_ENTRIES_PER_LINE, WIDE_PRTOECTED_ENTRIES_PER_LINE};

    return type_to_entries_num[entry_type];
}

la_status
resolution_ad_entry_allocator::alloc_line_entry(ad_table_line_t& table_line,
                                                const npl_resolution_assoc_data_entry_type_e entry_type,
                                                la_uint8_t& select)
{
    if (table_line.type != entry_type) {
        return LA_STATUS_EINVAL;
    }

    // find first cleared bit which indicates the first free entry within the line
    select = bit_utils::get_lsb(~table_line.allocated_entries_mask & bit_utils::ones(get_line_entries_num_per_type(entry_type)));
    if (select != 0xff) {
        // mark that entry as allocated
        table_line.allocated_entries_mask = bit_utils::set_bit(table_line.allocated_entries_mask, select, 1);
        return LA_STATUS_SUCCESS;
    }

    return LA_STATUS_ERESOURCE;
}

la_status
resolution_ad_entry_allocator::get_line_entry_type(la_uint32_t line_index,
                                                   npl_resolution_assoc_data_entry_type_e& out_entry_type) const
{
    auto line_iter = m_occupied_lines.find(line_index);

    if (line_iter == m_occupied_lines.end()) {
        return LA_STATUS_EEXIST;
    }

    out_entry_type = line_iter->second.type;
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
