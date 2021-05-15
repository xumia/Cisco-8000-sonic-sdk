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

#ifndef __LEABA_LPM_HW_INDEX_ALLOCATOR_SRAM_ADAPTER_H__
#define __LEABA_LPM_HW_INDEX_ALLOCATOR_SRAM_ADAPTER_H__

#include "lpm/lpm_hw_index_allocator_adapter.h"
#include "lpm/lpm_internal_types.h"
#include "lpm_bucket.h"

namespace silicon_one
{

class lpm_hw_index_allocator;

class lpm_hw_index_allocator_adapter_sram : public lpm_hw_index_allocator_adapter
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    /// @brief Construct and initialize lpm_hw_index_allocator_adapter_sram
    ///
    /// @param[in]      name                                    Name of the HW index allocator.
    /// @param[in]      ldevice                                 Low level device contains the device revision.
    /// @param[in]      level                                   Level of the HW index allocator.
    /// @param[in]      num_of_sram_lines                       Number of HW lines in the SRAM.
    /// @param[in]      num_fixed_entries_per_bucket            Number of fixed entries in each bucket.
    /// @param[in]      num_shared_entries_per_double_bucket    Number of shared entries in each line.
    lpm_hw_index_allocator_adapter_sram(std::string name,
                                        const ll_device_sptr& ldevice,
                                        lpm_level_e level,
                                        size_t first_line,
                                        size_t num_of_sram_lines,
                                        size_t num_buckets_per_sram_line,
                                        size_t num_fixed_entries_per_bucket,
                                        size_t num_shared_entries_per_double_bucket);

    /// @brief Destroy an allocator.
    ~lpm_hw_index_allocator_adapter_sram();

    // lpm_hw_index_allocator_adapter API-s
    la_status allocate_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                           lpm_bucket_index_t& out_hw_index) override;
    la_status allocate_specific_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                    lpm_bucket_index_t hw_index) override;
    void release_hw_index(lpm_bucket_index_t hw_index) override;
    void commit() override;
    void withdraw() override;
    bool is_hw_index_free(lpm_bucket_index_t hw_index) const override;
    size_t get_number_of_free_indices() const override;
    void notify_hw_index_occupancy_changed(lpm_bucket_index_t hw_index, const lpm_bucket::occupancy_data& occupancy_data) override;
    bool sanity() const override;

private:
    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    lpm_hw_index_allocator_adapter_sram() = default;

private:
    // Properties
    std::string m_name;               ///< HW index allocator's name.
    const ll_device_sptr m_ll_device; ///< Low level device contains the device revision.
    lpm_level_e m_level;              ///< Level of the adapter.

    // State members
    lpm_hw_index_allocator_sptr m_index_allocator; ///< SRAM HW index allocator.
};
} // namespace silicon_one

#endif
