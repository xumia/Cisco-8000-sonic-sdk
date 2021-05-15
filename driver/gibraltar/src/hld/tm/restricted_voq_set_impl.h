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

#ifndef __RESTICTED_VOQ_SET_IMPL_H__
#define __RESTICTED_VOQ_SET_IMPL_H__

#include <vector>

#include "api/tm/la_voq_set.h"
#include "hld_types_fwd.h"
#include "la_voq_set_impl.h"

namespace silicon_one
{

class restricted_voq_set_impl : public la_voq_set_impl
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit restricted_voq_set_impl(const la_device_impl_wptr& device);
    ~restricted_voq_set_impl() override;

    // Lifecycle
    la_status initialize_from_memories(la_object_id_t oid, la_voq_gid_t base_voq_id, size_t set_size);
    la_status initialize(la_object_id_t oid,
                         la_voq_gid_t base_voq_id,
                         size_t set_size,
                         la_vsc_gid_vec_t base_vsc_vec,
                         la_device_id_t dest_device,
                         la_slice_id_t dest_slice,
                         la_ifg_id_t dest_ifg) override;

    la_status set_cgm_profile(size_t voq_index, la_voq_cgm_profile* cgm_profile) override;
    la_status get_cgm_profile(size_t voq_index, la_voq_cgm_profile*& out_cgm_profile) const override;
    la_status flush(bool block) override;
    la_status set_fabric_priority(size_t voq_index, bool is_high_priority) override;
    la_status get_fabric_priority(size_t voq_index, bool& out_is_high_priority) const override;

    la_status force_local_voq_enable(bool enable) override;

protected:
    uint64_t get_voq_cgm_profile_id(size_t voq_index) const override;

private:
    la_status read_and_parse_vsc_voq_mapping_value();
    la_status read_and_parse_dev_dest_map_value();
    la_status read_voq_cgm_profile_ids();

    // The ids of voq cgm profiles configured in HW
    std::vector<uint64_t> m_cgm_profile_ids;

    restricted_voq_set_impl() = default; // For serialization purposes only.

}; // class restricted_voq_set_impl

} // namespace silicon_one

#endif // __RESTICTED_VOQ_SET_IMPL_H__
