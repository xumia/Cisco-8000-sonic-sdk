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

#ifndef __LA_MPLS_MULTICAST_GROUP_IMPL_H__
#define __LA_MPLS_MULTICAST_GROUP_IMPL_H__

#include "api/npu/la_mpls_multicast_group.h"
#include "common/la_status.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "npu/la_multicast_group_common_base.h"

#include <map>
#include <vector>

namespace silicon_one
{

class la_device_impl;
class la_prefix_object_base;

class la_mpls_multicast_group_impl : public la_mpls_multicast_group, public dependency_listener
{

    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_mpls_multicast_group_impl() = default;
    //////////////////////////////

public:
    explicit la_mpls_multicast_group_impl(la_device_impl_wptr device);
    ~la_mpls_multicast_group_impl() override;

    la_status initialize(la_object_id_t oid, la_multicast_group_gid_t multicast_gid, la_replication_paradigm_e rep_paradigm);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_mpls_multicast_group API-s
    la_multicast_group_gid_t get_gid() const override;
    la_status add(const la_prefix_object* prefix_object, const la_system_port* dsp) override;
    la_status add(const la_l3_port* recycle_port) override;
    la_status remove(const la_prefix_object* prefix_object) override;
    la_status remove(const la_l3_port* recycle_port) override;
    la_status get_member(size_t member_idx, la_mpls_multicast_group_member_info& out_prefix_object) const override;
    la_status get_size(size_t& out_size) const override;
    la_status get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const override;
    la_status set_destination_system_port(const la_prefix_object* prefix_object, const la_system_port* dsp) override;
    la_status get_destination_system_port(const la_prefix_object* prefix_object, const la_system_port*& out_dsp) const override;
    la_status set_punt_enabled(bool enabled) override;
    la_status get_punt_enabled(bool& out_enable) const override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    size_t get_slice_bitmap() const;

protected:
    // Maintains number of members per slice - used to update
    // rx entries in MC-EM-DB for ingress rep groups
    size_t m_slice_use_count[ASIC_MAX_SLICES_PER_DEVICE_NUM];

    la_status notify_mcg_change_event(bool slice_added, la_slice_id_t slice);
    la_status process_slice_addition(la_slice_id_t slice);
    la_status process_slice_removal(la_slice_id_t slice);
    bool add_slice_user(la_slice_id_t slice);
    bool remove_slice_user(la_slice_id_t slice);

private:
    using member_t = la_multicast_group_common_base::group_member_desc;
    using prot_info_t = la_multicast_group_common_base::protected_member_info;

    // Containing device
    la_device_impl_wptr m_device;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Global ID
    la_multicast_group_gid_t m_gid;

    // Replication paradigm
    la_replication_paradigm_e m_rep_paradigm;

    // List of non-protected members
    std::vector<member_t> m_members;

    // List of protected members
    std::vector<member_t> m_protected_members;

    // Helper object for common MC opeations
    std::shared_ptr<la_multicast_group_common_base> m_mc_common;

    // MC copy ID mapping
    using mc_copy_id_mapping_t = std::map<std::pair<member_t, la_system_port_wcptr>, uint64_t>;
    std::array<mc_copy_id_mapping_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_mc_copy_id_mapping;

    // Destination system-port mapping
    std::map<member_t, la_system_port_wcptr> m_dsp_mapping;

    // Punt enabled
    bool m_punt_enabled;

private:
    // Configure tables for egress replication
    la_status configure_egress_rep(const member_t& member, const la_system_port_wcptr& dsp, uint64_t mc_copy_id);
    la_status teardown_egress_rep(const member_t& member, const la_system_port_wcptr& dsp);

    // Configure CUD mapping table
    la_status configure_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id);
    la_status configure_cud_mapping(la_slice_id_t dest_slice, uint64_t mc_copy_id);
    la_status teardown_cud_mapping(la_slice_id_t dest_slice, uint64_t mc_copy_id);

    // Verify validity of ports
    la_status verify_parameters(const la_prefix_object_wcptr& pfx_obj, const la_system_port_wcptr& dsp) const;
    la_status verify_dsp(const la_ethernet_port_wcptr& eth, const la_system_port_wcptr& dsp) const;

    // Helper functions with MC copy ID management
    la_status allocate_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp, uint64_t& out_mc_copy_id);
    la_status release_mc_copy_id(const member_t& member, const la_system_port_wcptr& dsp);

    // Remove function body
    la_status do_remove(const member_t& member);

    // Add function body
    la_status do_add(const member_t& member, const la_system_port_wcptr& dsp);

    // Helper functions to add/remove recycle member
    la_status verify_parameters(const la_l3_port* l3_port) const;
    la_status do_add_recycle_port(const member_t& member, const la_system_port_wcptr& dsp);
    la_status do_remove_recycle_port(const member_t& member);
    la_status allocate_mc_copy_id_recycle(const member_t& member, const la_system_port_wcptr& dsp, uint64_t& out_mc_copy_id);
    la_status release_mc_copy_id_recycle(const member_t& member, const la_system_port_wcptr& dsp);
    la_status configure_cud_mapping_recycle(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id);
    la_status teardown_cud_mapping_recycle(la_slice_id_t dest_slice, uint64_t mc_copy_id);

    // Set punt function body
    la_status do_set_punt_enabled(bool enabled);

    // Protection group management helpers
    // Handle an update from underlying protection group
    la_status handle_protection_group_update(const la_multicast_protection_group* protection_group,
                                             multicast_protection_group_change_details mcg_update);
    // Get existing primary/backup members for a protection group
    la_status get_members_for_protection_group(const la_multicast_protection_group* protection_group,
                                               member_t& primary_member,
                                               member_t& backup_member);
    // Check for a case where we only need to modify the is_primary bit in CUD data (swap member from primary -> backup or
    // vice-versa)
    bool check_protection_group_swap_case(const member_t& original_member,
                                          const la_system_port* original_dsp,
                                          const la_next_hop* new_nh,
                                          const la_system_port* new_dsp);
    // Handle update for a single member of a protection group
    la_status handle_protection_group_member_update(const member_t& member,
                                                    const la_system_port* dsp,
                                                    multicast_protection_group_change_details mcg_update,
                                                    bool swap_case);
};

} // namespace silicon_one

#endif // __LA_MPLS_MULTICAST_GROUP_IMPL_H__
