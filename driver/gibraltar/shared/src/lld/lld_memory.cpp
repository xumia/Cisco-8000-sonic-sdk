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

#include <string.h>

#include "common/logger.h"
#include "lld/lld_block.h"
#include "lld/lld_memory.h"

namespace silicon_one
{

lld_memory::lld_memory(const lld_block_wcptr& parent_block,
                       const std::string& name,
                       const lld_memory_desc_t& memory_desc,
                       bool is_valid,
                       size_t index)
    : lld_storage(parent_block,
                  name,
                  memory_desc.is_volatile() ? bit_vector() : bit_vector(0, memory_desc.width_total_bits * memory_desc.entries),
                  is_valid,
                  lld_storage_type_e::MEMORY,
                  index),
      m_memory_desc(memory_desc)
{
}

lld_memory::lld_memory(const lld_block_wcptr& parent_block,
                       const std::string& name,
                       const lld_memory_desc_t& memory_desc,
                       bool is_valid)
    : lld_memory(parent_block, name, memory_desc, is_valid, 0)
{
}

lld_memory::lld_memory(const lld_block_wcptr& parent_block,
                       const std::string& name,
                       const lld_memory_desc_t& memory_desc,
                       size_t index,
                       bool is_valid)
    : lld_memory(parent_block, name, memory_desc, is_valid, index)
{
    size_t step = parent_block->need_memory_padding() ? (size_t)lld_memory_desc_t::ARRAY_INSTANCE_OFFSET
                                                      : m_memory_desc.entries * parent_block->get_register_step();
    m_memory_desc.addr += index * step;
}

uint64_t
lld_memory::get_absolute_address() const
{
    return m_parent_block->get_absolute_address(m_memory_desc.addr);
}

void
lld_memory::write_shadow(size_t first_entry, size_t count, const void* in_val) const
{
    if (!m_shadow.get_width()) {
        return;
    }
    count = std::min(m_memory_desc.entries - first_entry, count);
    const uint8_t* val = (const uint8_t*)in_val;

    for (size_t off = 0; off < count; ++off, val += m_memory_desc.width_total) {
        write_shadow_entry(first_entry + off, val);
    }
}

void
lld_memory::fill_shadow(size_t first_entry, size_t count, const bit_vector& in_bv) const
{
    if (!m_shadow.get_width()) {
        return;
    }
    count = std::min(m_memory_desc.entries - first_entry, count);

    for (size_t off = 0; off < count; ++off) {
        write_shadow_entry(first_entry + off, in_bv.byte_array());
    }
}

void
lld_memory::write_shadow_entry(size_t mem_entry_idx, const void* in_val) const
{
    size_t lsb = mem_entry_idx * m_memory_desc.width_total_bits;
    size_t msb = lsb + m_memory_desc.width_total_bits - 1;

    // Most writes are small, so use a static bit-vector for writes up to 192 bits.
    // This avoids the memory management overheads for dynamic bit vectors.
    if (m_memory_desc.width_total_bits < 192) {
        bit_vector192_t tmp(m_memory_desc.width_total, (const uint8_t*)in_val, m_memory_desc.width_total_bits);
        m_shadow.set_bits(msb, lsb, tmp);
    } else {
        bit_vector tmp(m_memory_desc.width_total, (const uint8_t*)in_val, m_memory_desc.width_total_bits);
        m_shadow.set_bits(msb, lsb, tmp);
    }
}

la_status
lld_memory::read_shadow(size_t first_entry, size_t count, void* out_val) const
{
    if (!m_shadow.get_width()) {
        return LA_STATUS_SUCCESS;
    }
    if ((first_entry + count) > m_memory_desc.entries) {
        log_err(LLD,
                "%s: mem %s, read request overflows memory size, first=%ld, count=%ld, entries=%d",
                __func__,
                m_memory_desc.name.c_str(),
                first_entry,
                count,
                m_memory_desc.entries);
        return LA_STATUS_EOUTOFRANGE;
    }

    uint8_t* val = (uint8_t*)out_val;
    for (size_t off = 0; off < count; ++off, val += m_memory_desc.width_total) {
        read_shadow_entry(first_entry + off, val);
    }

    return LA_STATUS_SUCCESS;
}

void
lld_memory::read_shadow_entry(size_t mem_entry_idx, void* out_val) const
{
    size_t lsb = mem_entry_idx * m_memory_desc.width_total_bits;
    size_t msb = lsb + m_memory_desc.width_total_bits - 1;

    const bit_vector tmp = m_shadow.bits(msb, lsb);
    memcpy(out_val, tmp.byte_array(), tmp.get_width_in_bytes());
}

lld_memory_array_container::lld_memory_array_container(const lld_block_wcptr& parent_block,
                                                       const std::string& name,
                                                       const lld_memory_desc_t& memory_desc,
                                                       size_t size,
                                                       bool is_valid)
    : m_parent_block(parent_block), m_memory_desc(memory_desc)
{
    m_array.reserve(size);
    for (size_t i = 0; i < size; i++) {
        char inst_name_buff[256];
        sprintf(inst_name_buff, "%s[%0zd]", name.c_str(), i);
        m_array.push_back(std::make_shared<lld_memory>(parent_block, inst_name_buff, memory_desc, i, is_valid));
    };
}

la_block_id_t
lld_memory_array_container::get_block_id() const
{
    return m_parent_block->get_block_id();
}

size_t
lld_memory_array_container::size() const
{
    return m_array.size();
}

} // namespace silicon_one
