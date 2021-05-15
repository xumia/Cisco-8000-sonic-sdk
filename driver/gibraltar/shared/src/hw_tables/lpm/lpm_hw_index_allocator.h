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

#ifndef __LEABA_LPM_HW_INDEX_ALLOCATOR_H__
#define __LEABA_LPM_HW_INDEX_ALLOCATOR_H__

#include "common/la_status.h"
#include "lpm/lpm_hw_index_allocator.h"
#include "lpm_internal_types.h"

namespace silicon_one
{

class lpm_hw_index_allocator
{
public:
    /// @brief Destroy an allocator.
    virtual ~lpm_hw_index_allocator() = default;

    /// @brief Allocate a HW index for a bucket.
    ///
    /// @param[in]      bucket_size     Physical size to be written to HW.
    /// @param[out]     out_hw_index    Allocated HW index for bucket.
    ///
    /// @return #la_status.
    virtual la_status allocate_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t& out_hw_index) = 0;

    /// @brief Allocate a specific HW index.
    ///
    /// @param[in]      bucket_size     Physical size to be written to HW.
    /// @param[in]      hw_index        HW index to allocate.
    ///
    /// @return #la_status.
    virtual la_status allocate_specific_hw_index_for_bucket(size_t bucket_size, lpm_bucket_index_t hw_index) = 0;

    /// @brief Release HW index.
    ///
    /// @param[in]      hw_index           HW index to release.
    virtual void release_hw_index(lpm_bucket_index_t hw_index) = 0;

    /// @brief Commit previous updates. They cannot be withdrawn after calling this function.
    virtual void commit() = 0;

    /// @brief Withdraw previous updates which haven't been comitted yet and return to previous state.
    virtual void withdraw() = 0;

    /// @brief Check if bucket HW index is free.
    ///
    /// @param[in]     hw_index         HW index to check its availability.
    ///
    /// @return Whether the HW index is free.
    virtual bool is_hw_index_free(lpm_bucket_index_t hw_index) const = 0;

    /// @brief Get number of free indices.
    ///
    /// @return Number of free indicess.
    virtual size_t get_number_of_free_indices() const = 0;

    /// @brief Notify that occupancy of allocated HW index has changed.
    ///
    /// @param[in]      hw_index        Changed HW index.
    /// @param[in]      bucket_size     New physical size to be written to HW.
    virtual void notify_hw_index_size_changed(lpm_bucket_index_t hw_index, size_t bucket_size) = 0;

    /// @brief Utility to check integrity of internal data structures.
    ///
    /// @return True if all checks passed.
    virtual bool sanity() const = 0;

}; // class lpm_hw_index_allocator

} // namespace silicon_one

#endif
