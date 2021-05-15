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

#include "common/ranged_index_generator.h"
#include "common/bit_utils.h"
#include "common/math_utils.h"
#include "common/resource_monitor.h"

#include "common/dassert.h"
#include <algorithm>

/// @file
/// @brief Ranged index generator.

namespace silicon_one
{

constexpr uint64_t EVEN_BIT_MASK = 0x5555555555555555ULL;

// Find pairs of adjacent bits where exactly one bit is set.
constexpr uint64_t
isolate_half_pairs(uint64_t x)
{
    return ((x >> 1) ^ x) & EVEN_BIT_MASK;
}

// Find pairs of adjacent bits where both bits are set.
constexpr uint64_t
isolate_available_pairs(uint64_t x)
{
    return ((x >> 1) & x) & EVEN_BIT_MASK;
}

ranged_index_generator::ranged_index_generator(uint64_t lower_bound, uint64_t upper_bound, bool allow_pairs)
    : m_lower_bound(lower_bound),
      m_upper_bound(upper_bound),
      m_available(upper_bound - lower_bound),
      m_allow_pairs(allow_pairs),
      m_free_indices(div_round_up(m_available, BLOCK_SIZE), UINT64_MAX),
      m_resource_monitor(nullptr)
{
    dassert_crit(upper_bound > lower_bound);
    if (allow_pairs) {
        dassert_crit(lower_bound % 2 == 0);
        dassert_crit(upper_bound % 2 == 0);
    }
}

uint64_t
ranged_index_generator::allocate()
{
    if (m_allow_pairs) {
        // To avoid fragmentation, first try to see if there is a half-free pair
        uint64_t ret = allocate_from_half_pair();
        if (ret != INVALID_INDEX) {
            return ret;
        }
    }

    // Find block with available indices
    auto it = std::find_if(m_free_indices.begin(), m_free_indices.end(), [](uint64_t i) { return i != 0; });
    if (it == m_free_indices.end()) {
        return INVALID_INDEX;
    }

    // Find index in block
    size_t offset = bit_utils::get_lsb(*it);
    uint64_t index = (it - m_free_indices.begin()) * BLOCK_SIZE + offset + m_lower_bound;

    if (index >= m_upper_bound) {
        return INVALID_INDEX;
    }

    // Mark index allocated
    bit_utils::set_bit(&*it, offset, false);
    m_available -= 1;

    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    return index;
}

bool
ranged_index_generator::allocate(uint64_t& index)
{
    uint64_t tmp = allocate();
    if (tmp == INVALID_INDEX) {
        return false;
    } else {
        index = tmp;
        return true;
    }
}

void
ranged_index_generator::release(uint64_t index)

{
    dassert_crit(index >= m_lower_bound && index < m_upper_bound);

    index -= m_lower_bound;

    size_t block_num = index / BLOCK_SIZE;
    uint64_t& block = m_free_indices.at(block_num);
    size_t offset = index % BLOCK_SIZE;

    dassert_crit(((block >> offset) & 0x1) == 0);

    bit_utils::set_bit(&block, offset, true);
    m_available += 1;

    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }
}

void
ranged_index_generator::allocate(uint64_t index, uint64_t& out_index)
{
    dassert_crit(index >= m_lower_bound && index < m_upper_bound);

    index -= m_lower_bound;

    size_t block_num = index / BLOCK_SIZE;
    uint64_t& block = m_free_indices.at(block_num);
    size_t offset = index % BLOCK_SIZE;

    dassert_crit(((block >> offset) & 0x1) != 0);

    bit_utils::set_bit(&block, offset, false);
    m_available -= 1;

    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    out_index = index;
}

bool
ranged_index_generator::is_available(uint64_t index)

{
    dassert_crit(index >= m_lower_bound && index < m_upper_bound);

    index -= m_lower_bound;

    size_t block_num = index / BLOCK_SIZE;
    uint64_t& block = m_free_indices.at(block_num);
    size_t offset = index % BLOCK_SIZE;

    return ((block >> offset) & 0x1);
}

void
ranged_index_generator::set_resource_monitor(const resource_monitor_sptr& monitor)
{
    m_resource_monitor = monitor;
}

void
ranged_index_generator::get_resource_monitor(resource_monitor_sptr& out_monitor)
{
    out_monitor = m_resource_monitor;
}

uint64_t
ranged_index_generator::allocate_from_half_pair()
{
    // Find a block with a half-full pair
    auto it = std::find_if(m_free_indices.begin(), m_free_indices.end(), isolate_half_pairs);
    if (it == m_free_indices.end()) {
        return INVALID_INDEX;
    }

    uint64_t val = *it;

    // Find lsb of the pair
    size_t offset = bit_utils::get_lsb(isolate_half_pairs(val));

    // find which bit in the pair
    if (!((val >> offset) & 0x1)) {
        offset++;
    }

    uint64_t index = (it - m_free_indices.begin()) * BLOCK_SIZE + offset + m_lower_bound;
    if (index >= m_upper_bound) {
        return INVALID_INDEX;
    }

    // Mark entry allocated
    bit_utils::set_bit(&*it, offset, false);
    m_available -= 1;

    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    return index;
}

uint64_t
ranged_index_generator::allocate_pair()
{
    if (!m_allow_pairs) {
        return INVALID_INDEX;
    }

    // Find block with available consecutive pair of entries
    auto it = std::find_if(m_free_indices.begin(), m_free_indices.end(), isolate_available_pairs);
    if (it == m_free_indices.end()) {
        return INVALID_INDEX;
    }

    // Find index in block
    size_t offset = bit_utils::get_lsb(isolate_available_pairs(*it));
    uint64_t index = (it - m_free_indices.begin()) * BLOCK_SIZE + offset + m_lower_bound;

    if (index >= m_upper_bound) {
        return INVALID_INDEX;
    }

    // Mark entry allocated
    bit_utils::set_bit(&*it, offset, false);
    bit_utils::set_bit(&*it, offset + 1, false);
    m_available -= 2;

    if (m_resource_monitor != nullptr) {
        size_t current_size = size();
        m_resource_monitor->update_size(current_size);
    }

    return index;
}

size_t
ranged_index_generator::size() const
{
    return max_size() - m_available;
}

size_t
ranged_index_generator::max_size() const
{
    return m_upper_bound - m_lower_bound;
}

index_handle::index_handle(const ranged_index_generator_wptr& parent, bool is_pair) : m_parent(parent), m_is_pair(is_pair)
{
    m_val = is_pair ? m_parent->allocate_pair() : m_parent->allocate();
}

void
index_handle::release()
{
    if ((m_parent != nullptr) && (m_val != INVALID_INDEX)) {
        m_parent->release(m_val);
        if (m_is_pair) {
            m_parent->release(m_val + 1);
        }
    }
}

index_handle::~index_handle()
{
    release();
}

index_handle&
index_handle::operator=(index_handle&& other) noexcept
{
    if (this != &other) {
        release();

        m_parent = other.m_parent;
        m_val = other.m_val;
        m_is_pair = other.m_is_pair;

        other.m_parent = nullptr;
        other.m_val = INVALID_INDEX;
    }
    return *this;
}

} // namespace silicon_one
