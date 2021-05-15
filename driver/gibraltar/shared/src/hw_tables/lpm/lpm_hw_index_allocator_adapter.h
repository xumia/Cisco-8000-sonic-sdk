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

#ifndef __LEABA_LPM_HW_INDEX_ALLOCATOR_ADAPTER_H__
#define __LEABA_LPM_HW_INDEX_ALLOCATOR_ADAPTER_H__

#include "lpm/lpm_internal_types.h"
#include "lpm_bucket.h"

namespace silicon_one
{

class lpm_hw_index_allocator_adapter
{
public:
    /// @brief Destroy an allocator adapter.
    virtual ~lpm_hw_index_allocator_adapter() = default;

    /// @brief Allocate a HW index for a bucket.
    ///
    /// @param[in]      occupancy_data  Data contains the physical size to be written to HW.
    /// @param[out]     out_hw_index    Allocated HW index for bucket.
    ///
    /// @return #la_status.
    virtual la_status allocate_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                   lpm_bucket_index_t& out_hw_index)
        = 0;

    /// @brief Allocate a specific HW index.
    ///
    /// @param[in]      occupancy_data  Data contains the physical size to be written to HW.
    /// @param[in]      hw_index        HW index to allocate.
    ///
    /// @return #la_status.
    virtual la_status allocate_specific_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                            lpm_bucket_index_t hw_index)
        = 0;

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
    /// @param[in]      occupancy_data  Data contains the new physical size.
    virtual void notify_hw_index_occupancy_changed(lpm_bucket_index_t hw_index, const lpm_bucket::occupancy_data& occupancy_data)
        = 0;

    /// @brief Utility to check integrity of internal data structures.
    ///
    /// @return True if all checks passed.
    virtual bool sanity() const = 0;
};

/// @brief Create a #silicon_one::create_hw_index_allocator_adapter object.
///
/// Creates a hw index allocator and initialize it.
///
/// @param[in]      name                                    Name of the adapter for the logs.
/// @param[in]      ldevice                                 Low level device contains the device revision.
/// @param[in]      level                                   Level of the HW index allocator.
/// @param[in]      num_of_sram_lines                       Number of HW lines in the SRAM.
/// @param[in]      num_buckets_per_sram_line               Number of buckets in each SRAM line.
/// @param[in]      num_of_hbm_buckets                      Number of HW lines in the HBM.
/// @param[in]      num_fixed_entries_per_bucket            Number of fix entries in each bucket.
/// @param[in]      num_shared_entries_per_double_bucket    Number of shared entries in each bucket.
lpm_hw_index_allocator_adapter_sptr create_hw_index_allocator_adapter(std::string name,
                                                                      ll_device_sptr ldevice,
                                                                      lpm_level_e level,
                                                                      size_t num_of_sram_lines,
                                                                      size_t num_buckets_per_sram_line,
                                                                      size_t num_of_hbm_buckets,
                                                                      size_t num_fixed_entries_per_bucket,
                                                                      size_t num_shared_entries_per_double_bucket);

} // namespace silicon_one

#endif
