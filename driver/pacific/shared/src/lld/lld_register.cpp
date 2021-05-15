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
#include "lld/lld_register.h"

namespace silicon_one
{

lld_register::lld_register(const lld_block_wcptr& parent_block,
                           const std::string& name,
                           const lld_register_desc_t& register_desc,
                           bool is_valid,
                           size_t index /*= 0*/)
    : lld_storage(parent_block,
                  name,
                  register_desc.is_volatile() ? bit_vector()
                                              : !register_desc.default_value.size()
                                                    ? bit_vector(0, register_desc.width_in_bits)
                                                    : bit_vector(register_desc.width,
                                                                 &register_desc.default_value.data()[index * register_desc.width],
                                                                 register_desc.width_in_bits),
                  is_valid,
                  lld_storage_type_e::REGISTER,
                  index),
      m_register_desc(register_desc)
{
}

lld_register::lld_register(const lld_block_wcptr& parent_block,
                           const std::string& name,
                           const lld_register_desc_t& register_desc,
                           size_t index,
                           bool is_valid)
    : lld_register(parent_block, name, register_desc, is_valid, index)
{
    m_register_desc.addr += index * parent_block->get_register_step();
}

uint64_t
lld_register::get_absolute_address() const
{
    return m_parent_block->get_absolute_address(m_register_desc.addr);
}

void
lld_register::write_shadow(size_t in_val_sz, const void* in_val) const
{
    if (!m_shadow.get_width()) {
        return;
    }
    // verify that the new contents array can fit into the current size of bit_vector
    if (in_val_sz > m_shadow.get_width_in_bytes()) {
        log_debug(LLD,
                  "cannot write reg=%s shadow, input buffer too big. in_val_sz=%ld > shadow width_in_bytes=%ld",
                  m_register_desc.name.c_str(),
                  in_val_sz,
                  m_shadow.get_width_in_bytes());
        return;
    }
    uint8_t* shadow_byte_array = m_shadow.byte_array();
    memcpy(shadow_byte_array, in_val, in_val_sz);
}

la_status
lld_register::read_shadow(size_t out_val_sz, void* out_val) const
{
    if (!m_shadow.get_width()) {
        return LA_STATUS_SUCCESS;
    }
    size_t shadow_width_in_bytes = m_shadow.get_width_in_bytes();

    // verify that the whole shadow can fit into the array.
    if (out_val_sz < shadow_width_in_bytes) {
        log_debug(LLD,
                  "cannot read reg=%s shadow, output buffer too small. out_val_sz=%ld < shadow width_in_bytes=%ld",
                  m_register_desc.name.c_str(),
                  out_val_sz,
                  m_shadow.get_width_in_bytes());
        return LA_STATUS_EINVAL;
    };

    uint8_t* shadow_byte_array = m_shadow.byte_array();
    memcpy(out_val, shadow_byte_array, shadow_width_in_bytes);

    return LA_STATUS_SUCCESS;
}

lld_register_array_container::lld_register_array_container(const lld_block_wcptr& parent_block,
                                                           const std::string& name,
                                                           const lld_register_desc_t& register_desc,
                                                           size_t size,
                                                           bool is_valid)
    : m_parent_block(parent_block), m_register_desc(register_desc)
{
    m_array.reserve(size);
    for (size_t i = 0; i < size; i++) {
        char inst_name_buff[256];
        sprintf(inst_name_buff, "%s[%0zd]", name.c_str(), i);
        m_array.push_back(std::make_shared<lld_register>(parent_block, inst_name_buff, register_desc, i, is_valid));
    };
}

la_block_id_t
lld_register_array_container::get_block_id() const
{
    return m_parent_block->get_block_id();
}

size_t
lld_register_array_container::size() const
{
    return m_array.size();
}

void
lld_register_array_container::write_shadow(size_t first, size_t count, const void* in_val) const
{
    const uint8_t* val = (const uint8_t*)in_val;
    for (size_t i = 0; i < count; ++i) {
        m_array[i]->write_shadow(m_register_desc.width, val + (i * m_register_desc.width));
    }
}

} // namespace silicon_one
