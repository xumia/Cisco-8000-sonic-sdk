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

#include "lpm_hw_index_allocator_adapter_hbm.h"
#include "common/gen_utils.h"
#include "common/la_profile.h"
#include "lpm_bucket_occupancy_utils.h"
#include "lpm_common.h"
#include "lpm_hw_index_singles_allocator.h"
#include "lpm_string.h"

namespace silicon_one
{

lpm_hw_index_allocator_adapter_hbm::lpm_hw_index_allocator_adapter_hbm(std::string name,
                                                                       const ll_device_sptr& ldevice,
                                                                       size_t num_of_sram_lines,
                                                                       size_t num_of_hbm_buckets)
    : m_name(name),
      m_ll_device(ldevice),
      m_hbm_address_offset(num_of_sram_lines * 2),
      m_sram_index_allocator(nullptr),
      m_hbm_index_allocator(nullptr)
{
    dassert_crit(num_of_sram_lines > 0);
    dassert_crit(num_of_hbm_buckets > 0);

    m_sram_index_allocator = std::make_shared<lpm_hw_index_singles_allocator>(m_name + "::SRAM_ALLOCATOR", 0, num_of_sram_lines, 2);
    m_hbm_index_allocator = std::make_shared<lpm_hw_index_singles_allocator>(
        m_name + "::HBM_ALLOCATOR", m_hbm_address_offset, num_of_hbm_buckets, static_cast<size_t>(1));
}

lpm_hw_index_allocator_adapter_hbm::lpm_hw_index_allocator_adapter_hbm() : m_hbm_address_offset()
{
}

lpm_hw_index_allocator_adapter_hbm::~lpm_hw_index_allocator_adapter_hbm()
{
}

lpm_hw_index_allocator*
lpm_hw_index_allocator_adapter_hbm::get_hw_index_allocator(lpm_bucket_index_t hw_index) const
{
    dassert_crit(hw_index >= 0);
    if (static_cast<size_t>(hw_index) >= m_hbm_address_offset) {
        return m_hbm_index_allocator.get();
    }

    return m_sram_index_allocator.get();
}

bool
lpm_hw_index_allocator_adapter_hbm::is_hw_index_free(lpm_bucket_index_t hw_index) const
{
    lpm_hw_index_allocator* hw_index_allocator = get_hw_index_allocator(hw_index);
    dassert_crit(hw_index_allocator != nullptr);

    bool is_free = hw_index_allocator->is_hw_index_free(hw_index);
    return is_free;
}

la_status
lpm_hw_index_allocator_adapter_hbm::allocate_specific_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                                          lpm_bucket_index_t hw_index)
{
    size_t hw_resource = lpm_bucket_occupancy_utils::logical_occupancy_to_hw_resource(m_ll_device, lpm_level_e::L2, occupancy_data);
    lpm_hw_index_allocator* hw_index_allocator = get_hw_index_allocator(hw_index);
    dassert_crit(hw_index_allocator != nullptr);

    la_status status = hw_index_allocator->allocate_specific_hw_index_for_bucket(hw_resource, hw_index);
    return status;
}

la_status
lpm_hw_index_allocator_adapter_hbm::allocate_hw_index_for_bucket(const lpm_bucket::occupancy_data& occupancy_data,
                                                                 lpm_bucket_index_t& out_hw_index)
{
    la_status status = m_sram_index_allocator->allocate_hw_index_for_bucket(0 /* bucket_size - don't care */, out_hw_index);
    if (status != LA_STATUS_ERESOURCE) {
        return status;
    }

    status = m_hbm_index_allocator->allocate_hw_index_for_bucket(0 /* bucket_size - don't care */, out_hw_index);
    if (status != LA_STATUS_ERESOURCE) {
        return status;
    }

    return LA_STATUS_ERESOURCE;
}

la_status
lpm_hw_index_allocator_adapter_hbm::allocate_hw_index_for_bucket(l2_bucket_location_e destination, lpm_bucket_index_t& out_hw_index)
{
    la_status status;
    switch (destination) {
    case l2_bucket_location_e::SRAM: {
        status = m_sram_index_allocator->allocate_hw_index_for_bucket(0 /* bucket_size - don't care */, out_hw_index);
        break;
    }
    case l2_bucket_location_e::HBM: {
        status = m_hbm_index_allocator->allocate_hw_index_for_bucket(0 /* bucket_size */, out_hw_index);
        break;
    }
    default:
        dassert_crit(false);
    }

    return status;
}

void
lpm_hw_index_allocator_adapter_hbm::release_hw_index(lpm_bucket_index_t hw_index)
{
    lpm_hw_index_allocator* hw_index_allocator = get_hw_index_allocator(hw_index);
    dassert_crit(hw_index_allocator != nullptr);

    hw_index_allocator->release_hw_index(hw_index);
}

size_t
lpm_hw_index_allocator_adapter_hbm::get_number_of_free_indices() const
{
    size_t num_free_sram = m_sram_index_allocator->get_number_of_free_indices();
    size_t num_free_hbm = m_hbm_index_allocator ? m_hbm_index_allocator->get_number_of_free_indices() : 0;
    size_t total = num_free_sram + num_free_hbm;
    return total;
}

void
lpm_hw_index_allocator_adapter_hbm::notify_hw_index_occupancy_changed(lpm_bucket_index_t hw_index,
                                                                      const lpm_bucket::occupancy_data& occupancy_data)
{
    size_t hw_resource = lpm_bucket_occupancy_utils::logical_occupancy_to_hw_resource(m_ll_device, lpm_level_e::L2, occupancy_data);
    lpm_hw_index_allocator* hw_index_allocator = get_hw_index_allocator(hw_index);
    dassert_crit(hw_index_allocator != nullptr);

    hw_index_allocator->notify_hw_index_size_changed(hw_index, hw_resource);
}

void
lpm_hw_index_allocator_adapter_hbm::commit()
{
    m_sram_index_allocator->commit();
    m_hbm_index_allocator->commit();
}

void
lpm_hw_index_allocator_adapter_hbm::withdraw()
{
    m_sram_index_allocator->withdraw();
    m_hbm_index_allocator->withdraw();
}

size_t
lpm_hw_index_allocator_adapter_hbm::get_number_of_free_indices_in_sram() const
{
    size_t num_free_sram = m_sram_index_allocator->get_number_of_free_indices();
    return num_free_sram;
}

bool
lpm_hw_index_allocator_adapter_hbm::sanity() const
{
    bool res = true;

    res &= m_sram_index_allocator->sanity();
    res &= m_hbm_index_allocator->sanity();

    return res;
}

} // namespace silicon_one
