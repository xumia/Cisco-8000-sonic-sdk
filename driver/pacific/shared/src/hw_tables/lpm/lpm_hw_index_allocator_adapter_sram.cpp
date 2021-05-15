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

#include "lpm_hw_index_allocator_adapter_sram.h"
#include "common/gen_utils.h"
#include "common/la_profile.h"
#include "lpm_bucket_occupancy_utils.h"
#include "lpm_common.h"
#include "lpm_hw_index_doubles_allocator.h"
#include "lpm_hw_index_doubles_allocator_pacific.h"
#include "lpm_hw_index_singles_allocator.h"
#include "lpm_string.h"

namespace silicon_one
{

lpm_hw_index_allocator_adapter_sram::lpm_hw_index_allocator_adapter_sram(std::string name,
                                                                         const ll_device_sptr& ldevice,
                                                                         lpm_level_e level,
                                                                         size_t first_line,
                                                                         size_t num_of_sram_lines,
                                                                         size_t num_buckets_per_sram_line,
                                                                         size_t num_fixed_entries_per_bucket,
                                                                         size_t num_shared_entries_per_double_bucket)

    : m_name(name), m_ll_device(ldevice), m_level(level), m_index_allocator(nullptr)
{
    dassert_crit(num_of_sram_lines > 0);
    dassert_crit((num_buckets_per_sram_line == 1) || (num_buckets_per_sram_line == 2));
    if (num_buckets_per_sram_line == 1) {
        m_index_allocator
            = std::make_shared<lpm_hw_index_singles_allocator>(m_name, first_line, num_of_sram_lines, static_cast<size_t>(2));
    } else {
        if ((level == lpm_level_e::L2) && (!is_pacific_revision(ldevice))) {
            // Level 2 from GB and on works in groups granularity.
            num_fixed_entries_per_bucket = div_round_up(num_fixed_entries_per_bucket, 2);
            num_shared_entries_per_double_bucket = div_round_up(num_shared_entries_per_double_bucket, 2);
        }

        m_index_allocator = std::make_shared<lpm_hw_index_doubles_allocator>(
            m_name, first_line, num_of_sram_lines, num_fixed_entries_per_bucket, num_shared_entries_per_double_bucket);
    }
}

lpm_hw_index_allocator_adapter_sram::~lpm_hw_index_allocator_adapter_sram()
{
}

bool
lpm_hw_index_allocator_adapter_sram::is_hw_index_free(lpm_bucket_index_t hw_index) const
{
    bool is_free = m_index_allocator->is_hw_index_free(hw_index);
    return is_free;
}

la_status
lpm_hw_index_allocator_adapter_sram::allocate_specific_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                                           lpm_bucket_index_t hw_index)
{
    size_t hw_resource = lpm_bucket_occupancy_utils::logical_occupancy_to_hw_resource(m_ll_device, m_level, occupancy_data);
    la_status status = m_index_allocator->allocate_specific_hw_index_for_bucket(hw_resource, hw_index);
    return status;
}

la_status
lpm_hw_index_allocator_adapter_sram::allocate_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                                  lpm_bucket_index_t& out_hw_index)
{
    size_t hw_resource = lpm_bucket_occupancy_utils::logical_occupancy_to_hw_resource(m_ll_device, m_level, occupancy_data);
    la_status status = m_index_allocator->allocate_hw_index_for_bucket(hw_resource, out_hw_index);
    return status;
}

void
lpm_hw_index_allocator_adapter_sram::release_hw_index(lpm_bucket_index_t hw_index)
{
    m_index_allocator->release_hw_index(hw_index);
}

size_t
lpm_hw_index_allocator_adapter_sram::get_number_of_free_indices() const
{
    size_t num_free = m_index_allocator->get_number_of_free_indices();
    return num_free;
}

void
lpm_hw_index_allocator_adapter_sram::notify_hw_index_occupancy_changed(lpm_bucket_index_t hw_index,
                                                                       const lpm_bucket::occupancy_data& occupancy_data)
{
    size_t hw_resource = lpm_bucket_occupancy_utils::logical_occupancy_to_hw_resource(m_ll_device, m_level, occupancy_data);
    m_index_allocator->notify_hw_index_size_changed(hw_index, hw_resource);
}

void
lpm_hw_index_allocator_adapter_sram::commit()
{
    m_index_allocator->commit();
}

void
lpm_hw_index_allocator_adapter_sram::withdraw()
{
    m_index_allocator->withdraw();
}

bool
lpm_hw_index_allocator_adapter_sram::sanity() const
{
    bool res = m_index_allocator->sanity();
    return res;
}

} // namespace silicon_one
