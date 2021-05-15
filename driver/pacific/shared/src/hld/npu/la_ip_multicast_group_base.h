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

#ifndef __LA_IP_MULTICAST_GROUP_BASE_H__
#define __LA_IP_MULTICAST_GROUP_BASE_H__

#include <array>
#include <tuple>
#include <unordered_set>
#include <utility>
#include <vector>

#include "api/npu/la_ip_multicast_group.h"
#include "api/system/la_device.h"
#include "common/la_status.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "npu/la_multicast_group_common_base.h"

namespace silicon_one
{

class la_ip_multicast_group_base : public la_ip_multicast_group, public dependency_listener
{

    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    ~la_ip_multicast_group_base() override;

    la_status initialize(la_object_id_t oid, la_multicast_group_gid_t multicast_gid, la_replication_paradigm_e rep_paradigm);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // la_ip_multicast_group API-s
    la_multicast_group_gid_t get_gid() const override;
    la_multicast_group_gid_t get_local_mcid() const;
    la_status add(const la_l3_port* l3_port, const la_l2_port* l2_port, const la_system_port* dsp) override;
    la_status add(const la_l3_port* l3_port,
                  const la_l2_port* vxlan_port,
                  la_next_hop* next_hop,
                  const la_system_port* dsp) override;
    la_status add(const la_stack_port* stackport, const la_system_port* dsp) override;
    la_status remove(const la_l3_port* l3_port, const la_l2_port* l2_port) override;
    la_status remove(const la_stack_port* stackport) override;
    la_status get_member(size_t member_idx, member_info& out_member) const override;
    la_status get_size(size_t& out_size) const override;
    la_status get_replication_paradigm(la_replication_paradigm_e& out_replication_paradigm) const override;
    la_status set_replication_paradigm(la_replication_paradigm_e replication_paradigm) override;
    la_status set_destination_system_port(const la_l3_port* l3_port, const la_l2_port* l2_port, const la_system_port* dsp) override;
    la_status get_destination_system_port(const la_l3_port* l3_port,
                                          const la_l2_port* l2_port,
                                          const la_system_port*& out_dsp) const override;
    la_status set_punt_enabled(const la_l3_port* l3_port, const la_l2_port* l2_port, bool punt_enabled) override;
    la_status get_punt_enabled(const la_l3_port* l3_port, const la_l2_port* l2_port, bool& out_punt_enabled) const override;
    la_status set_egress_counter(la_device_id_t device_id, la_counter_set* counter_set) override;
    la_status get_egress_counter(la_device_id_t& out_device_id, la_counter_set*& out_counter) const override;
    size_t get_slice_bitmap() const;

    // Track VRF routes using this multicast group
    la_status register_mc_ipv4_vrf_route(la_vrf_impl_sptr vrf_impl, const la_ipv4_addr_t saddr, const la_ipv4_addr_t gaddr);
    la_status unregister_mc_ipv4_vrf_route(la_vrf_impl_sptr vrf_impl, const la_ipv4_addr_t saddr, const la_ipv4_addr_t gaddr);
    la_status register_mc_ipv6_vrf_route(la_vrf_impl_sptr vrf_impl, const la_ipv6_addr_t saddr, const la_ipv6_addr_t gaddr);
    la_status unregister_mc_ipv6_vrf_route(la_vrf_impl_sptr vrf_impl, const la_ipv6_addr_t saddr, const la_ipv6_addr_t gaddr);

    // Keys and hash/equal functions for tracking the vrf routes using this MCG
    using v4_key_t = std::tuple<la_vrf_impl_sptr, la_ipv4_addr_t, la_ipv4_addr_t>;
    using v6_key_t = std::tuple<la_vrf_impl_sptr, la_ipv6_addr_t, la_ipv6_addr_t>;

    // Ingress Replication APIs
    la_status add(const la_svi_port* svi_port, la_l2_multicast_group* l2_mcg) override;
    la_status remove(const la_svi_port* svi_port, la_l2_multicast_group* l2_mcg) override;
    la_status add(const la_ip_multicast_group* ip_mcg) override;
    la_status remove(const la_ip_multicast_group* ip_mcg) override;
    la_status add(const la_mpls_multicast_group* mpls_mcg) override;
    la_status remove(const la_mpls_multicast_group* mpls_mcg) override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    struct v4_key_hash {
        std::size_t operator()(const v4_key_t& k) const
        {
            return std::hash<la_vrf_impl*>()(std::get<0>(k).get()) ^ std::get<1>(k).s_addr ^ std::get<2>(k).s_addr;
        }
    };

    struct v6_key_hash {
        std::size_t operator()(const v6_key_t& k) const
        {
            return std::hash<la_vrf_impl*>()(std::get<0>(k).get()) ^ std::get<1>(k).s_addr ^ std::get<2>(k).s_addr;
        }
    };

    struct v4_key_equal {
        bool operator()(const v4_key_t& k1, const v4_key_t& k2) const
        {
            return ((std::get<0>(k1) == std::get<0>(k2)) && (std::get<1>(k1).s_addr == std::get<1>(k2).s_addr)
                    && (std::get<2>(k1).s_addr == std::get<2>(k2).s_addr));
        }
    };

    struct v6_key_equal {
        bool operator()(const v6_key_t& k1, const v6_key_t& k2) const
        {
            return ((std::get<0>(k1) == std::get<0>(k2)) && (std::get<1>(k1).s_addr == std::get<1>(k2).s_addr)
                    && (std::get<2>(k1).s_addr == std::get<2>(k2).s_addr));
        }
    };

protected:
    explicit la_ip_multicast_group_base(la_device_impl_wptr device);
    la_ip_multicast_group_base() = default;

    using member_t = la_multicast_group_common_base::group_member_desc;

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

    // List of members
    std::vector<member_t> m_members;

    // Maintains number of members per slice - used to update
    // rx entries in MC-EM-DB for ingress rep groups
    size_t m_slice_use_count[ASIC_MAX_SLICES_PER_DEVICE_NUM];

    // Helper object for common MC opeations
    std::shared_ptr<la_multicast_group_common_base> m_mc_common;

    // MC copy ID mapping
    using mc_copy_id_mapping_t = std::map<member_t, uint64_t>;
    std::array<mc_copy_id_mapping_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_mc_copy_id_mapping;

    using mc_egress_punt_copy_id_mapping_t = std::map<member_t, uint64_t>;
    std::array<mc_egress_punt_copy_id_mapping_t, ASIC_MAX_SLICES_PER_DEVICE_NUM> m_mc_egress_punt_copy_id_mapping;

    // Destination system-port mapping
    std::map<member_t, la_system_port_base_wcptr> m_dsp_mapping;

    // Sets of the VRF ipv4/ipv6 routes using this multicast group
    std::unordered_set<v4_key_t, v4_key_hash, v4_key_equal> m_mc_ipv4_vrf_routes;
    std::unordered_set<v6_key_t, v6_key_hash, v6_key_equal> m_mc_ipv6_vrf_routes;

    // MCG counter
    la_counter_set_impl_wptr m_counter;
    la_device_id_t m_mcg_counter_device_id; // The TX la_device ID which allocates the MCG counter
    bool m_is_mcg_counter_allocated;        // True if the MCG counter is allocated on this la_device

    static constexpr la_slice_id_t PUNT_SLICE = 1; // Punt destination - any slice with RCY port will do

    // Configure tables for egress replication
    la_status configure_egress_rep(const member_t& member, const la_system_port_base_wcptr& dsp, uint64_t mc_copy_id);
    la_status teardown_egress_rep(const member_t& member, const la_system_port_base_wcptr& dsp);

    // Configure CUD mapping table
    virtual la_status configure_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) = 0;
    virtual la_status teardown_cud_mapping(const member_t& member, la_slice_id_t dest_slice, uint64_t mc_copy_id) = 0;

    // Verify validity of ports
    la_status verify_parameters(const la_l3_port_wcptr& l3_port,
                                const la_l2_port_wcptr& l2_port,
                                const la_system_port_base_wcptr& dsp) const;
    la_status verify_parameters(const la_l3_port_wcptr& l3_port, const la_l2_port_wcptr& l2_port) const;
    la_status verify_dsp(const la_ethernet_port_wcptr& eth, const la_system_port_base_wcptr& dsp) const;
    la_status verify_parameters(la_replication_paradigm_e rep_paradigm) const;
    la_status verify_parameters(member_t l2mcg_member) const;

    // Helper functions with MC copy ID management
    virtual la_status allocate_mc_copy_id(const member_t& member, la_slice_id_t slice, uint64_t& out_mc_copy_id) = 0;
    virtual la_status release_mc_copy_id(const member_t& member, la_slice_id_t dest_slice) = 0;

    // Remove function body
    la_status do_remove(const member_t& member);

    // Add function body
    la_status do_add(const member_t& member, const la_system_port_base_wcptr& dsp);

    // Set DSP function body
    la_status do_set_destination_system_port(const member_t& member, const la_system_port_base_wcptr& dsp);

    // Get non-punt copy members
    void get_non_punt_and_counter_member_list(std::vector<member_t>& out_member_list) const;

    // Update the VRF routes using this MCG
    la_status update_mc_ipv4_vrf_routes();
    la_status update_mc_ipv6_vrf_routes();

    // Ingress replication helper functions
    la_status configure_ingress_rep(const member_t& member);
    la_status teardown_ingress_rep(const member_t& member);
    la_status configure_ingress_rep(const member_t& member, la_slice_id_t slice);
    la_status teardown_ingress_rep(const member_t& member, la_slice_id_t slice);
    la_status do_add_mcg_member(const member_t& member);
    la_status do_remove_mcg_member(const member_t& member);
    void get_non_mcg_member_list(std::vector<member_t>& out_member_list) const;
    size_t get_non_mcg_member_size() const;
    bool is_mcg_member(const member_t& member) const;
    la_status handle_mcg_change_event(dependency_management_op op);
    la_status notify_mcg_change_event(bool slice_added, la_slice_id_t slice);
    la_status process_slice_addition(la_slice_id_t slice);
    la_status process_slice_removal(la_slice_id_t slice);
    bool add_slice_user(la_slice_id_t slice);
    bool remove_slice_user(la_slice_id_t slice);
};

} // namespace silicon_one

#endif // __LA_IP_MULTICAST_GROUP_BASE_H__
