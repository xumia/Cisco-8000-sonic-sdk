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

#include "special_tables/trap_tcam.h"

#include "common/defines.h"
#include "lld/ll_device.h"

namespace silicon_one
{

trap_tcam::trap_tcam(const ll_device_sptr& ldevice,
                     size_t key_width,
                     size_t value_width,
                     const std::vector<tcam_section>& sections,
                     const std::vector<lld_register_scptr>& config_regs)
    : memory_tcam(ldevice, key_width, value_width, sections),
      m_ll_device(ldevice),
      m_size(sections[0].size),
      m_value_width(value_width),
      m_entries(m_size, false),
      m_config_regs(config_regs),
      m_upper_table_size(m_size / 2)
{
    // Trap table is built from one section.
    dassert_crit(sections.size() == 1);
}

la_status
trap_tcam::write(size_t line, const bit_vector& key, const bit_vector& mask, const bit_vector& value)
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status ret = memory_tcam::write(line, key, mask, value);
    if (ret == LA_STATUS_SUCCESS) {
        m_entries[line] = true;
    }
    return ret;
}

la_status
trap_tcam::move(size_t src_line, size_t dest_line)
{
    if (src_line >= m_size || dest_line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status ret = memory_tcam::move(src_line, dest_line);
    if (ret == LA_STATUS_SUCCESS) {
        m_entries[src_line] = false;
        m_entries[dest_line] = true;
    }
    return ret;
}

la_status
trap_tcam::update(size_t line, const bit_vector& value)
{
    return memory_tcam::update(line, value);
}

la_status
trap_tcam::invalidate(size_t line)
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    la_status ret = memory_tcam::invalidate(line);
    if (ret == LA_STATUS_SUCCESS) {
        m_entries[line] = false;
    }
    return ret;
}

la_status
trap_tcam::read(size_t line, bit_vector& out_key, bit_vector& out_mask, bit_vector& out_value, bool& out_valid) const
{
    if (line >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    if (m_entries[line] == false) {
        out_valid = false;
        return LA_STATUS_SUCCESS;
    }

    la_status ret = memory_tcam::read(line, out_key, out_mask, out_value, out_valid);

    return ret;
}

la_status
trap_tcam::initialize()
{
    la_status status = update_config_regs();
    return_on_error(status);

    for (size_t line = 0; line < NUM_ENTRIES; ++line) {
        status = memory_tcam::invalidate(line);
        return_on_error(status);

        // Trap values are accessed even no "no hit".
        // Accessing unitinialized entries cause crc errors - need to set all to 0;
        bit_vector zero_val(0, m_value_width);
        status = memory_tcam::update(line, zero_val);
        return_on_error(status);
    }

    return LA_STATUS_SUCCESS;
}

size_t
trap_tcam::get_resource_size(bool reversed) const
{
    return (reversed) ? m_size - m_upper_table_size : m_upper_table_size;
}

la_status
trap_tcam::resize_resource(size_t new_size, bool reversed)
{
    if (new_size >= m_size) {
        return LA_STATUS_EOUTOFRANGE;
    }

    new_size = (reversed) ? m_size - new_size : new_size;

    // Resize is impossible if the region between new and old sizes is occupied,
    // because it's essentially occupied by the second table.
    size_t line = std::min(m_upper_table_size, new_size);
    size_t size = std::max(m_upper_table_size, new_size);

    while (line < size) {
        if (m_entries[line]) {
            return LA_STATUS_ERESOURCE;
        }
        ++line;
    }

    m_upper_table_size = new_size;

    la_status ret = update_config_regs();
    return ret;
}

la_status
trap_tcam::update_config_regs()
{
    for (const lld_register_scptr& reg : m_config_regs) {
        const lld_register_desc_t* desc = reg->get_desc();
        bit_vector val_bv(m_upper_table_size, desc->width_in_bits);
        la_status status = m_ll_device->write_register(*reg, val_bv);
        return_on_error(status);
    }
    return LA_STATUS_SUCCESS;
}

} // namespace silicon_one
