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

#ifndef __RANGED_INDEX_GENERATOR_H__
#define __RANGED_INDEX_GENERATOR_H__

#include <cstdint>
#include <stddef.h>
#include <vector>

#include "common/cereal_utils.h"
#include "common/common_fwd.h"
#include "common/resource_monitor.h"

/// @file
/// @brief Ranged index generator.

namespace silicon_one
{

/// @brief Ranged index generator.
///
/// Manages index allocation/deallocation for a given resource.
class ranged_index_generator
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static constexpr uint64_t INVALID_INDEX = UINT64_MAX;

    ranged_index_generator() = default;

    ranged_index_generator(uint64_t lower_bound, uint64_t upper_bound)
        : ranged_index_generator(lower_bound, upper_bound, false /* allow_pairs */)
    {
    }

    ranged_index_generator(uint64_t lower_bound, uint64_t upper_bound, bool allow_pairs);

    /// @brief Allocate an unused index.
    ///
    /// @return Allocated index, or INVALID_INDEX on failure.
    uint64_t allocate();

    /// @brief Allocate an unused index.
    ///
    /// @param[out] index   Index to fill.
    ///
    /// @return true if index allocated properly, false on failure
    bool allocate(uint64_t& index);

    /// @brief Allocate a pair of unused indices with even alignment
    ///
    /// @return Allocated index, or INVALID_INDEX on failure.
    uint64_t allocate_pair();

    /// @brief Deallocate a used index.
    ///
    /// @param[in]  index   Index to deallocate.
    void release(uint64_t index);

    /// @brief Check if index already allocated.
    ///
    /// @param[in]  index   Index to check if available.
    bool is_available(uint64_t index);

    /// @brief Mark as allocated given index.
    ///
    /// @param[in]  index       Index to mark as allocated.
    /// @param[out] out_index   Index that was marked as allocated.
    void allocate(uint64_t index, uint64_t& out_index);

    /// @brief Number of unused indices.
    ///
    /// @return Current number of unused indices.
    uint32_t available() const
    {
        return m_available;
    }

    /// @brief Retrieve the number of used indices.
    ///
    /// @retval Current number of used indices.
    size_t size() const;

    /// @brief Max number of indices.
    ///
    /// @retval Max number of indices.
    size_t max_size() const;

    /// @brief Set resource monitor.
    ///
    /// An index generator will update the attached monitor every time an index is allocated/deallocated. The resource monitor
    /// should be synced with the
    ///
    /// @param[in]  monitor           Resource monitor to attach.
    void set_resource_monitor(const resource_monitor_sptr& monitor);

    /// @brief Get attached resource monitor.
    ///
    /// @param[out]  out_monitor           Resource monitor to populate.
    void get_resource_monitor(resource_monitor_sptr& out_monitor);

private:
    static constexpr int BLOCK_SIZE = 64;

    uint64_t m_lower_bound = 0;
    uint64_t m_upper_bound = 0;
    uint32_t m_available = 0;

    bool m_allow_pairs = false;

    std::vector<uint64_t> m_free_indices;

    resource_monitor_sptr m_resource_monitor;

    uint64_t allocate_from_half_pair();
};

/// @brief Owning handle for an index allocated from a ranged_index_generator
///
/// Automatically frees held index on destruction.
class index_handle
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    static constexpr uint64_t INVALID_INDEX = UINT64_MAX;

    /// @brief Create an empty index handle
    index_handle() = default;

    /// @brief Construct by allocating a new index from a ranged_index_generator.
    ///
    /// param[in] ranged_index_generator  Generator to allocate from
    /// param[in] is_pair                 If true, allocate using ranged_index_generator pair api
    ///
    /// If allocation fails, index_handle will be in an empty state
    /// The index handle will release the index back to the generator on destruction.
    index_handle(const ranged_index_generator_wptr& parent, bool is_pair);

    /// @brief Construct by allocating a new index from a ranged_index_generator.
    ///
    /// param[in] ranged_index_generator  Generator to allocate from
    ///
    /// If allocation fails, index_handle will be in an empty state
    /// The index handle will release the index back to the generator on destruction.
    explicit index_handle(const ranged_index_generator_wptr& parent) : index_handle(parent, false /* is_pair */)
    {
    }

    /// @brief Construct an index_handle with a specified value, not associated with a ranged_index_generator.
    ///
    /// param[in] other  Index to use
    explicit index_handle(uint64_t index) : m_val(index)
    {
    }

    /// @brief Move constructor. Construct by taking ownership of index from another index_handle.
    ///
    /// param[in] other  Index handle to take ownership from, will be left in empty state
    index_handle(index_handle&& other) noexcept : m_parent(other.m_parent), m_val(other.m_val), m_is_pair(other.m_is_pair)
    {
        other.m_parent = nullptr;
        other.m_val = INVALID_INDEX;
    }

    /// @brief Destroy object, releasing any held index
    ~index_handle();

    /// @brief Move assignment. Take ownership of index from another index_handle.
    ///
    /// param[in] other  Index handle to take ownership from, will be left in empty state
    ///
    /// Does nothing in case of self-assignment.
    index_handle& operator=(index_handle&& other) noexcept;

    /// @brief Check whether the handle is non-empty
    ///
    /// @return true if handle holds an index, false if empty
    explicit operator bool() const
    {
        return m_val != INVALID_INDEX;
    }

    /// @brief Get held index
    ///
    /// @return Held index value or INVALID_INDEX if empty
    operator uint64_t() const
    {
        return m_val;
    }

    /// @brief Get held index
    ///
    /// @return Held index value or INVALID_INDEX if empty
    uint64_t value() const
    {
        return m_val;
    }

private:
    ranged_index_generator_wptr m_parent;
    uint64_t m_val = INVALID_INDEX;
    bool m_is_pair = false;

    void release();
};

} // namespace silicon_one

#endif
