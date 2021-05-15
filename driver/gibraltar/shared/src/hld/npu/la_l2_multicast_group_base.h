// BEGIN_LEGAL
//
// Copyright (c) 2017-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_L2_MULTICAST_GROUP_BASE_H__
#define __LA_L2_MULTICAST_GROUP_BASE_H__

#include <map>
#include <vector>

#include "api/npu/la_l2_destination.h"
#include "api/npu/la_l2_multicast_group.h"
#include "api/types/la_object.h"

#include "npu/la_multicast_group_common_base.h"

namespace silicon_one
{

class la_l2_multicast_group_base : public la_l2_multicast_group
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ~la_l2_multicast_group_base() override;

    la_status initialize(la_object_id_t oid, la_multicast_group_gid_t multicast_gid, la_replication_paradigm_e rep_paradigm);
    la_status destroy();

    // la_object API-s
    la_multicast_group_gid_t get_gid() const override;
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_l2_multicast_group API-s
    la_status add(const la_l2_destination* destination, const la_system_port* dsp) override;
    la_status add(const la_stack_port* stackport, const la_system_port* dsp) override;
    la_status remove(const la_l2_destination* destination) override;
    virtual la_status add(const la_l2_destination* vxlan_port, la_next_hop* next_hop, const la_system_port* dsp) override = 0;
    virtual la_status remove_cud_table_entry(const la_l2_destination* destination, const la_system_port_wcptr& dsp) = 0;
    la_status remove(const la_stack_port* stackport) override;
    la_status get_member(size_t member_idx, const la_l2_destination*& out_destination) const override;
    la_status get_members(la_l2_destination_vec_t& out_l2_mcg_members) const override;
    la_status get_size(size_t& out_size) const override;
    la_status get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const override;
    la_status set_destination_system_port(const la_l2_destination* destination, const la_system_port* dsp) override;
    la_status get_destination_system_port(const la_l2_destination* l2_destination, const la_system_port*& out_dsp) const override;

    la_status transition_copyid_range(la_l3_port_wcptr l3_port);
    size_t get_slice_bitmap() const;

protected:
    explicit la_l2_multicast_group_base(la_device_impl_wptr device);
    la_l2_multicast_group_base() = default;

    using member_t = la_multicast_group_common_base::group_member_desc;

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid{LA_OBJECT_ID_INVALID};

    // Global ID
    la_multicast_group_gid_t m_gid;

    // Replication paradigm
    la_replication_paradigm_e m_rep_paradigm;

    // List of members
    std::vector<member_t> m_members;

    // Maintains number of members per slice - used to update
    // rx entries in MC-EM-DB for ingress rep groups
    size_t m_slice_use_count[ASIC_MAX_SLICES_PER_DEVICE_NUM];

    // Helper object for common MC opeations
    std::shared_ptr<la_multicast_group_common_base> m_mc_common;

    // Destination system-port mapping
    std::map<member_t, la_system_port_wcptr> m_dsp_mapping;

    la_l3_port_wcptr m_mmcg_l3_port;
    uint64_t m_ref_count;

    // MC copy ID mapping
    using mc_copy_id_mapping_t = std::map<member_t, uint64_t>;
    std::array<mc_copy_id_mapping_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_mc_copy_id_mapping;

    // Configure tables for egress replication
    la_status configure_egress_rep(const member_t& member, const la_system_port_wcptr& dsp, uint64_t mc_copy_id);

    // Cleanup tables for egress replication
    la_status teardown_egress_rep(const member_t& member, const la_system_port_wcptr& dsp);

    // Add pwe member to l2 multicast group
    la_status add_pwe(const member_t& member, const la_system_port_wcptr& dsp_sptr);

    // stack copy-id with SVL encap type
    virtual la_status configure_stack_copy_cud_mapping(la_slice_id_t slice, uint64_t mc_copy_id) = 0;

    // MC Copy Id
    virtual la_status get_mc_copy_id(const member_t& member,
                                     const la_system_port_wcptr& dsp,
                                     bool is_wide,
                                     uint64_t& out_mc_copy_id)
        = 0;
    virtual la_status release_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp) = 0;

    virtual la_status add_to_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp) = 0;
    virtual la_status remove_from_mc_copy_id_table(const member_t& member, const la_system_port_wcptr& dsp) = 0;

    la_status configure_cud_mapping(const member_t& member, const la_system_port_wcptr& dsp_sptr, uint64_t mc_copy_id);
    la_status teardown_cud_mapping(const member_t& member, const la_system_port_wcptr& dsp_sptr);

    la_status set_member_dsp(member_t member, const la_system_port_wcptr& curr_dsp, const la_system_port_wcptr& new_dsp);

    // Handle attribute-change notifications
    la_status handle_attribute_change_notifications(dependency_management_op op);

    // Verify the validity of the DSP
    la_status verify_dsp(const la_l2_service_port_base_wcptr& ac_port, const la_system_port_wcptr& dsp) const;

    // Helper functions with MC copy ID management
    la_status allocate_mc_copy_id(const la_l2_destination*, const la_system_port_wcptr& dsp, uint64_t& out_mc_copy_id);
    la_status release_mc_copy_id(const la_l2_destination*, const la_system_port_wcptr& dsp);

    bool add_slice_user(la_slice_id_t slice);
    bool remove_slice_user(la_slice_id_t slice);
    la_status process_slice_addition(la_slice_id_t slice);
    la_status process_slice_removal(la_slice_id_t slice);
    la_status notify_mcg_change_event(bool slice_added, la_slice_id_t slice);
};

} // namespace silicon_one

#endif // __LA_L2_MULTICAST_GROUP_BASE_H__
