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

#include "ll_filtered_device_impl.h"
#include "access_engine.h"
#include "lld_types_internal.h"

#include "lld/lld_block.h"
#include "lld/lld_utils.h"

#include "common/dassert.h"
#include "common/logger.h"

#include <fstream>
#include <string>

using namespace std;
using namespace silicon_one;

static void
parse_lld_filtering_config_file(const std::string& file,
                                std::set<la_block_id_t>& out_block_ids,
                                std::set<std::string>& out_block_names)
{
    std::ifstream read(file);
    std::string line;
    la_block_id_t block_id;
    bool conversion_success;

    while (std::getline(read, line)) {
        conversion_success = true;
        try {
            block_id = std::stol(line, nullptr, 0);
        } catch (const std::invalid_argument& ia) {
            conversion_success = false;
        } catch (const std::out_of_range& oor) {
            conversion_success = false;
        }
        if (conversion_success) {
            out_block_ids.insert(block_id);
        } else {
            out_block_names.insert(line);
        }
    }

    bool is_logging = true;
    if (is_logging) {
        for (const la_block_id_t b : out_block_ids) {
            log_debug(LLD, "Filtering for block id %d", b);
        }
        for (const std::string& b : out_block_names) {
            log_debug(LLD, "Filtering for block name %s", b.c_str());
        }
    }
}

bool
ll_filtered_device_impl::initialize(const char* device_path, device_simulator* sim, const la_platform_cbs& platform_cbs)
{
    bool result = ll_device_impl::initialize(device_path, sim, platform_cbs);
    if (result && m_use_filtered) {
        validate_blocks();
    }

    return result;
}

void
ll_filtered_device_impl::validate_blocks(void)
{
    lld_block_scptr device_tree = get_device_tree();

    if (device_tree) {
        for (auto it = std::begin(m_filtered_block_ids); it != std::end(m_filtered_block_ids);) {
            if (!get_block(*it)) {
                log_err(LLD, "Block id %d not available, removing it", *it);
                it = m_filtered_block_ids.erase(it);
            } else {
                ++it;
            }
        }

        lld_block::lld_block_vec_t blocks = device_tree->get_leaf_blocks();
        for (auto it = std::begin(m_filtered_block_names); it != std::end(m_filtered_block_names);) {
            if (std::find_if(
                    std::begin(blocks), std::end(blocks), [&it](const lld_block_scptr block) { return *it == block->get_name(); })
                == std::end(blocks)) {
                log_err(LLD, "Block name %s not available, removing it", it->c_str());
                it = m_filtered_block_names.erase(it);
            } else {
                ++it;
            }
        }
    }
}

bool
ll_filtered_device_impl::is_block_allowed(const lld_block_scptr& b) const
{
    bool is_allowed = true;
    if (m_use_filtered) {
        is_allowed = m_filtered_block_ids.find(b->get_block_id()) != m_filtered_block_ids.end();
        if (!is_allowed) {
            is_allowed = m_filtered_block_names.find(b->get_name()) != m_filtered_block_names.end();
        }
    }
    if (!is_allowed) {
        return false;
    }
    is_allowed = m_forbiden_blocks.find(b->get_block_id()) == m_forbiden_blocks.end();
    return is_allowed;
}

ll_filtered_device_impl::ll_filtered_device_impl(la_device_id_t device_id, bool explicitly_allow, std::string allowed_config_file)
    : ll_device_impl(device_id), m_use_filtered(explicitly_allow), m_allowed_config_file(allowed_config_file)
{
    if (m_use_filtered) {
        parse_lld_filtering_config_file(allowed_config_file, m_filtered_block_ids, m_filtered_block_names);
    }
}

la_status
ll_filtered_device_impl::read_register(const lld_register& reg, bit_vector& out_bv)
{
    return read_filtered(reg, [&]() { return ll_device_impl::read_register(reg, out_bv); });
}

la_status
ll_filtered_device_impl::read_register(const lld_register_scptr& reg, bit_vector& out_bv)
{
    return read_filtered(*reg, [&]() { return ll_device_impl::read_register(reg, out_bv); });
}

la_status
ll_filtered_device_impl::peek_register(const lld_register& reg, bit_vector& out_bv)
{
    return read_filtered(reg, [&]() { return ll_device_impl::peek_register(reg, out_bv); });
}

la_status
ll_filtered_device_impl::peek_register(const lld_register_scptr& reg, bit_vector& out_bv)
{
    return read_filtered(*reg, [&]() { return ll_device_impl::peek_register(reg, out_bv); });
}
la_status
ll_filtered_device_impl::read_register(const lld_register& reg, size_t out_val_sz, void* out_val)
{
    return read_filtered(reg, [&]() { return ll_device_impl::read_register(reg, out_val_sz, out_val); });
}

la_status
ll_filtered_device_impl::peek_register(const lld_register& reg, size_t out_val_sz, void* out_val)
{
    return read_filtered(reg, [&]() { return ll_device_impl::peek_register(reg, out_val_sz, out_val); });
}

la_status
ll_filtered_device_impl::read_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv)
{
    if (is_block_allowed(get_block(block_id))) {
        return ll_device_impl::read_register_raw(block_id, addr, width_bits, out_bv);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::peek_register_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv)
{
    if (is_block_allowed(get_block(block_id))) {
        return ll_device_impl::peek_register_raw(block_id, addr, width_bits, out_bv);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::write_register(const lld_register& reg, const bit_vector& in_bv)
{
    return write_filtered(reg, [&]() { return ll_device_impl::write_register(reg, in_bv); });
}

la_status
ll_filtered_device_impl::write_register(const lld_register_scptr& reg, const bit_vector& in_bv)
{
    return write_filtered(*reg, [&]() { return ll_device_impl::write_register(reg, in_bv); });
}

la_status
ll_filtered_device_impl::write_register(const lld_register& reg, size_t in_val_sz, const void* in_val)
{
    return write_filtered(reg, [&]() { return ll_device_impl::write_register(reg, in_val_sz, in_val); });
}

la_status
ll_filtered_device_impl::write_register_raw(la_block_id_t block_id,
                                            la_entry_addr_t addr,
                                            uint32_t width_bits,
                                            const bit_vector& in_bv)
{
    if (is_block_allowed(get_block(block_id))) {
        return ll_device_impl::write_register_raw(block_id, addr, width_bits, in_bv);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& value)
{
    if (is_block_allowed(reg.get_block())) {
        return ll_device_impl::read_modify_write_register(reg, msb, lsb, value);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask)
{
    if (is_block_allowed(reg.get_block())) {
        return ll_device_impl::wait_for_value(reg, equal, val, mask);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::read_memory(const lld_memory& mem, size_t line, bit_vector& out_bv)
{
    return read_filtered(mem, [&]() { return ll_device_impl::read_memory(mem, line, out_bv); });
}

la_status
ll_filtered_device_impl::read_memory(const lld_memory_scptr& mem, size_t line, bit_vector& out_bv)
{
    return read_filtered(*mem, [&]() { return ll_device_impl::read_memory(mem, line, out_bv); });
}

la_status
ll_filtered_device_impl::read_memory(const lld_memory& mem, size_t first_line, size_t count, size_t out_val_sz, void* out_val)
{
    return read_filtered(mem, [&]() { return ll_device_impl::read_memory(mem, first_line, count, out_val_sz, out_val); });
}

la_status
ll_filtered_device_impl::read_memory(const lld_memory& mem, size_t first_line, size_t count, bit_vector& out_bv)
{
    return read_filtered(mem, [&]() { return ll_device_impl::read_memory(mem, first_line, count, out_bv); });
}

la_status
ll_filtered_device_impl::read_memory_raw(la_block_id_t block_id, la_entry_addr_t addr, uint32_t width_bits, bit_vector& out_bv)
{
    if (is_block_allowed(get_block(block_id))) {
        return ll_device_impl::read_memory_raw(block_id, addr, width_bits, out_bv);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::write_memory(const lld_memory& mem, size_t line, const bit_vector& in_bv)
{
    return write_filtered(mem, [&]() { return ll_device_impl::write_memory(mem, line, in_bv); });
}

la_status
ll_filtered_device_impl::write_memory(const lld_memory_scptr& mem, size_t line, const bit_vector& in_bv)
{
    return write_filtered(*mem, [&]() { return ll_device_impl::write_memory(mem, line, in_bv); });
}

la_status
ll_filtered_device_impl::write_memory(const lld_memory& mem, size_t first_line, size_t count, size_t in_val_sz, const void* in_val)
{
    return write_filtered(mem, [&]() { return ll_device_impl::write_memory(mem, first_line, count, in_val_sz, in_val); });
}

la_status
ll_filtered_device_impl::fill_memory(const lld_memory& mem, size_t mem_first_entry, size_t count, const bit_vector& in_bv)
{
    return write_filtered(mem, [&]() { return ll_device_impl::fill_memory(mem, mem_first_entry, count, in_bv); });
}

la_status
ll_filtered_device_impl::write_memory_raw(la_block_id_t block_id,
                                          la_entry_addr_t addr,
                                          uint32_t width_bits,
                                          const bit_vector& in_bv)
{
    if (is_block_allowed(get_block(block_id))) {
        return ll_device_impl::write_memory_raw(block_id, addr, width_bits, in_bv);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::read_modify_write_memory(const lld_memory& mem,
                                                  size_t line,
                                                  size_t msb,
                                                  size_t lsb,
                                                  const bit_vector& value)
{
    if (is_block_allowed(mem.get_block())) {
        return ll_device_impl::read_modify_write_memory(mem, line, msb, lsb, value);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::refresh_memory(const lld_memory& mem, size_t line)
{
    if (is_block_allowed(mem.get_block())) {
        return ll_device_impl::refresh_memory(mem, line);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask)
{
    if (is_block_allowed(mem.get_block())) {
        return ll_device_impl::wait_for_value(mem, line, equal, val, mask);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

la_status
ll_filtered_device_impl::read_tcam(lld_memory const& tcam,
                                   size_t tcam_line,
                                   bit_vector& out_key_bv,
                                   bit_vector& out_mask_bv,
                                   bool& out_valid)
{
    return read_filtered(tcam, [&]() { return ll_device_impl::read_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid); });
}

la_status
ll_filtered_device_impl::read_tcam(lld_memory const& tcam,
                                   size_t tcam_line,
                                   size_t key_mask_sz,
                                   void*& out_key,
                                   void*& out_mask,
                                   bool& out_valid)
{
    return read_filtered(tcam,
                         [&]() { return ll_device_impl::read_tcam(tcam, tcam_line, key_mask_sz, out_key, out_mask, out_valid); });
}

la_status
ll_filtered_device_impl::write_tcam(const lld_memory& tcam,
                                    size_t tcam_line,
                                    const bit_vector& in_key_bv,
                                    const bit_vector& in_mask_bv)
{
    return write_filtered(tcam, [&]() { return ll_device_impl::write_tcam(tcam, tcam_line, in_key_bv, in_mask_bv); });
}

la_status
ll_filtered_device_impl::write_tcam(const lld_memory& tcam,
                                    size_t tcam_line,
                                    size_t key_mask_sz,
                                    const void* in_key,
                                    const void* in_mask)
{
    return write_filtered(tcam, [&]() { return ll_device_impl::write_tcam(tcam, tcam_line, key_mask_sz, in_key, in_mask); });
}

la_status
ll_filtered_device_impl::invalidate_tcam(const lld_memory& tcam, size_t tcam_line)
{
    if (is_block_allowed(tcam.get_block())) {
        return ll_device_impl::invalidate_tcam(tcam, tcam_line);
    } else {
        return LA_STATUS_SUCCESS;
    }
}

ll_device::access_desc
ll_filtered_device_impl::make_read_register(const lld_register& reg, bool peek, bit_vector& out_bv)
{
    return make_command(reg, [&]() { return ll_device_impl::make_read_register(reg, peek, out_bv); });
}

ll_device::access_desc
ll_filtered_device_impl::make_write_register(const lld_register& reg, const bit_vector& in_val)
{
    return make_command(reg, [&]() { return ll_device_impl::make_write_register(reg, in_val); });
}

ll_device::access_desc
ll_filtered_device_impl::make_read_modify_write_register(const lld_register& reg, size_t msb, size_t lsb, const bit_vector& in_val)
{
    return make_command(reg, [&]() { return ll_device_impl::make_read_modify_write_register(reg, msb, lsb, in_val); });
}

ll_device::access_desc
ll_filtered_device_impl::make_read_memory(const lld_memory& mem, size_t first_entry, size_t count, bit_vector& out_bv)
{
    return make_command(mem, [&]() { return ll_device_impl::make_read_memory(mem, first_entry, count, out_bv); });
}

ll_device::access_desc
ll_filtered_device_impl::make_write_memory(const lld_memory& mem, size_t first_entry, size_t count, const bit_vector& in_val)
{
    return make_command(mem, [&]() { return ll_device_impl::make_write_memory(mem, first_entry, count, in_val); });
}

ll_device::access_desc
ll_filtered_device_impl::make_read_modify_write_memory(const lld_memory& mem,
                                                       size_t line,
                                                       size_t msb,
                                                       size_t lsb,
                                                       const bit_vector& in_val)
{
    return make_command(mem, [&]() { return ll_device_impl::make_read_modify_write_memory(mem, line, msb, lsb, in_val); });
}

ll_device::access_desc
ll_filtered_device_impl::make_read_tcam(lld_memory const& tcam,
                                        size_t tcam_line,
                                        bit_vector& out_key_bv,
                                        bit_vector& out_mask_bv,
                                        bool& out_valid)
{
    return make_command(tcam,
                        [&]() { return ll_device_impl::make_read_tcam(tcam, tcam_line, out_key_bv, out_mask_bv, out_valid); });
}

ll_device::access_desc
ll_filtered_device_impl::make_write_tcam(const lld_memory& tcam,
                                         size_t tcam_line,
                                         const bit_vector& in_key_bv,
                                         const bit_vector& in_mask_bv)
{
    return make_command(tcam, [&]() { return ll_device_impl::make_write_tcam(tcam, tcam_line, in_key_bv, in_mask_bv); });
}

ll_device::access_desc
ll_filtered_device_impl::make_invalidate_tcam(const lld_memory& tcam, size_t tcam_line)
{
    return make_command(tcam, [&]() { return ll_device_impl::make_invalidate_tcam(tcam, tcam_line); });
}

ll_device::access_desc
ll_filtered_device_impl::make_wait_for_value(const lld_register& reg, bool equal, uint16_t val, uint16_t mask)
{
    return make_command(reg, [&]() { return ll_device_impl::make_wait_for_value(reg, equal, val, mask); });
}

ll_device::access_desc
ll_filtered_device_impl::make_wait_for_value(const lld_memory& mem, size_t line, bool equal, uint16_t val, uint16_t mask)
{
    return make_command(mem, [&]() { return ll_device_impl::make_wait_for_value(mem, line, equal, val, mask); });
}

bool
ll_filtered_device_impl::is_block_available(la_block_id_t block_id)
{
    return is_block_allowed(get_block(block_id));
}

//------------------------- enabling and disabling blocks

la_status
ll_filtered_device_impl::disable_block(la_block_id_t block_id)
{
    m_forbiden_blocks.insert(block_id);
    return LA_STATUS_SUCCESS;
}
la_status
ll_filtered_device_impl::enable_block(la_block_id_t block_id)
{
    const auto& iter = m_forbiden_blocks.find(block_id);
    if (iter != m_forbiden_blocks.end()) {
        m_forbiden_blocks.erase(iter);
    }
    if (m_use_filtered) {
        if (m_filtered_block_ids.find(block_id) == m_filtered_block_ids.end()) {
            if (!get_block(block_id)) {
                return LA_STATUS_EINVAL;
            }
            m_filtered_block_ids.insert(block_id);
        }
    }
    return LA_STATUS_SUCCESS;
}
