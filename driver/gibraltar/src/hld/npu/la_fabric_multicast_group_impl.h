// BEGIN_LEGAL
//
// Copyright (c) 2018-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_FABRIC_MULTICAST_GROUP_IMPL_H__
#define __LA_FABRIC_MULTICAST_GROUP_IMPL_H__

#include <vector>

#include "api/npu/la_fabric_multicast_group.h"
#include "api/types/la_system_types.h"
#include "common/la_status.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "npu/la_multicast_group_common_base.h"

namespace silicon_one
{

class la_fabric_multicast_group_impl : public la_fabric_multicast_group
{

    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_fabric_multicast_group_impl() = default;
    //////////////////////////////

public:
    explicit la_fabric_multicast_group_impl(const la_device_impl_wptr& device);
    ~la_fabric_multicast_group_impl() override;

    la_status initialize(la_object_id_t oid, la_multicast_group_gid_t multicast_gid, la_replication_paradigm_e rep_paradigm);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_fabric_multicast_group API-s
    la_multicast_group_gid_t get_gid() const override;
    la_multicast_group_gid_t get_local_mcid() const;
    la_status get_devices(la_device_id_vec_t& out_device_id_vec) const override;
    la_status set_devices(const la_device_id_vec_t& device_id_vec) override;
    la_status get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const override;
    la_status configure_mc_bitmap();

private:
    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Global ID
    la_multicast_group_gid_t m_gid;

    // Local MCID
    la_multicast_group_gid_t m_local_mcid;

    // True if this is a scaled mode MCID
    bool m_is_scale_mode_smcid;

    // Replication paradigm
    la_replication_paradigm_e m_rep_paradigm;

    // List of devices included in this group.
    std::vector<la_device_id_t> m_devices;

    // Bit vector of the links for the multicast group
    bit_vector128_t m_links_bitmap;

private:
    la_status flush_mcid_cache() const;
    la_status set_mc_bitmap(la_multicast_group_gid_t mcid, uint64_t* bits);
    la_status set_global_to_local_mcid_mapping(la_multicast_group_gid_t global_mcid, la_multicast_group_gid_t local_mcid);
    la_status erase_global_to_local_mcid_mapping(la_multicast_group_gid_t global_mcid);
    la_status configure_local_mcid(uint64_t* bits);
    la_status release_local_mcid(la_multicast_group_gid_t mcid, bool& out_is_deleted);
    la_status allocate_local_mcid(uint64_t* bitmap, la_multicast_group_gid_t& out_mcid, bool& out_is_new_allocation);
};

} // namespace silicon_one

#endif // __LA_FABRIC_MULTICAST_GROUP_IMPL_H__
