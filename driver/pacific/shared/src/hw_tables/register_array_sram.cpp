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

#include "hw_tables/register_array_sram.h"

#include "lld/ll_device.h"

#include "common/defines.h"
#include "table_utils.h"

namespace silicon_one
{

register_array_sram::register_array_sram(const ll_device_sptr& ldevice, const register_array_section& section)
    : m_ll_device(ldevice), m_section(section)
{
}

register_array_sram::register_array_sram(const ll_device_sptr& ldevice, const register_array& regs) : m_ll_device(ldevice)
{
    m_section.entries_per_line = regs.entries_per_line;
    m_section.width = regs.width;
    m_section.size = regs.size;
    m_section.srams.push_back(regs);
}

la_status
register_array_sram::write(size_t line, const bit_vector& value)
{
    size_t value_width = m_section.width / m_section.entries_per_line;

    if (value.get_width() != value_width) {
        return LA_STATUS_EINVAL;
    }

    if (line >= m_section.size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    return table_utils::write_sram_section(m_ll_device, m_section.srams, line, value);
}

size_t
register_array_sram::max_size() const
{
    return m_section.size;
}

} // namespace silicon_one
