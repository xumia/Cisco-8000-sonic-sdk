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

#include <jansson.h>

#include "common/bit_utils.h"
#include "common/defines.h"
#include "common/logger.h"
#include "lld/ll_device.h"
#include "lld/lld_block.h"
#include "lld/lld_memory.h"

namespace silicon_one
{

void
lld_block::initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name, block_indices_struct block_indices)
{
    m_block_id = block_id;
    m_name = name;
    m_lbr_name = lbr_name;
    m_block_indices = block_indices;
}

void
lld_block::initialize(la_block_id_t block_id, const char* lbr_name, const std::string& name)
{
    initialize(block_id,
               lbr_name,
               name,
               block_indices_struct{LA_SLICE_PAIR_ID_INVALID, LA_SLICE_ID_INVALID, LA_IFG_ID_INVALID, BLOCK_INSTANCE_INVALID});
}

std::string
lld_block::get_name() const
{
    return m_name;
}

std::string
lld_block::get_template_name() const
{
    return m_lbr_name;
}

uint64_t
lld_block::get_absolute_address(la_entry_addr_t addr) const
{
    return (((uint64_t)m_block_id) << bit_utils::BITS_IN_UINT32 | addr);
}

lld_register_scptr
lld_block::get_register(la_entry_addr_t addr) const
{
    map_addr_to_register_t::const_iterator it = m_registers.find(addr);

    if (it == m_registers.end()) {
        return nullptr;
    }

    return it->second;
}

lld_memory_scptr
lld_block::get_memory(la_entry_addr_t addr) const
{
    // Find the first memory following 'addr', then go one element backwards.
    // This will give us the largest element that's lower than 'addr', or an 'end' iterator if that does not exist.
    map_addr_to_memory_t::const_iterator it = m_memories.upper_bound(addr);
    --it;

    if (it == m_memories.end()) {
        return nullptr;
    }

    lld_memory_desc_t const* mem_desc = it->second->get_desc();

    // verify that the searched address is actually a part of the found memory's space
    if (addr >= (mem_desc->addr + mem_desc->entries)) {
        return nullptr;
    }

    return it->second;
}

lld_block::lld_block_vec_t
lld_block::get_leaf_blocks() const
{
    lld_block::lld_block_vec_t res_blocks;
    if (is_valid()) {
        res_blocks.push_back(shared_from_this());
        return res_blocks;
    }

    lld_block::lld_block_vec_t subblocks = get_blocks();
    for (auto block : subblocks) {
        lld_block_vec_t subblock_res = block->get_leaf_blocks();
        if (!subblock_res.empty()) {
            res_blocks.insert(res_blocks.end(), subblock_res.begin(), subblock_res.end());
        }
    }

    return res_blocks;
}

lld_block::lld_register_vec_t
lld_block::get_registers() const
{
    lld_register_vec_t ret;
    for (auto it : m_registers) {
        ret.push_back(it.second);
    }

    return ret;
}

lld_block::lld_memory_vec_t
lld_block::get_memories() const
{
    lld_memory_vec_t ret;
    for (auto it : m_memories) {
        ret.push_back(it.second);
    }

    return ret;
}

const lld_block::block_indices_struct&
lld_block::get_block_indices() const
{
    return m_block_indices;
}

} // namespace silicon_one
