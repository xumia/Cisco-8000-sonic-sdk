// BEGIN_LEGAL
//
// Copyright (c) 2016-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __LA_IP_OVER_IP_TUNNEL_PORT_IMPL_H__
#define __LA_IP_OVER_IP_TUNNEL_PORT_IMPL_H__
#include "api/npu/la_ip_over_ip_tunnel_port.h"
#include "api/system/la_l2_mirror_command.h"
#include "api/types/la_common_types.h"
#include "common/profile_allocator.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "ipv4_sip_index_manager.h"
#include "la_ac_port_common.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_filter_group_impl.h"

namespace silicon_one
{

class la_vrf_port_common_base;

class la_ip_over_ip_tunnel_port_impl : public la_ip_over_ip_tunnel_port, public dependency_listener
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_ip_over_ip_tunnel_port_impl() = default;
    //////////////////////////////

public:
    explicit la_ip_over_ip_tunnel_port_impl(const la_device_impl_wptr& device);
    ~la_ip_over_ip_tunnel_port_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Object life-cycle management
    la_status initialize(la_object_id_t oid,
                         la_l3_port_gid_t gid,
                         la_ip_tunnel_mode_e tunnel_mode,
                         const la_vrf* underlay_vrf,
                         la_ipv4_prefix_t prefix,
                         la_ipv4_addr_t ip_addr,
                         const la_vrf* vrf,
                         la_ingress_qos_profile_impl* ingress_qos_profile_impl,
                         la_egress_qos_profile_impl* egress_qos_profile_impl);
    la_status destroy();

    // la_object API-s
    object_type_e type() const override;
    const la_device* get_device() const override;
    la_object_id_t oid() const override;
    std::string to_string() const override;

    // l3_port API-s
    la_l3_port_gid_t get_gid() const override;
    la_status set_active(bool active) override;
    la_status get_active(bool& out_active) const override;
    la_status get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const override;
    la_status set_protocol_enabled(la_l3_protocol_e protocol, bool enabled) override;
    la_status get_event_enabled(la_event_e event, bool& out_enabled) const override;
    la_status set_event_enabled(la_event_e event, bool enabled) override;
    la_status get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const override;
    la_status set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode) override;
    la_status set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile) override;
    la_status get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const override;
    la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) override;
    la_status get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const override;

    la_status set_ecn_remark_enabled(bool enabled) override;
    la_status get_ecn_remark_enabled(bool& out_enabled) const override;
    la_status set_ecn_counting_enabled(bool enabled) override;
    la_status get_ecn_counting_enabled(bool& out_enabled) const override;

    la_status set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode) override;
    la_mpls_qos_inheritance_mode_e get_qos_inheritance_mode() const override;
    la_status set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group) override;
    la_status get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const override;
    la_status clear_acl_group(la_acl_direction_e dir) override;
    la_status set_pbr_enabled(bool enabled) override;
    la_status get_pbr_enabled(bool& out_enabled) const override;
    la_status set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter) override;
    la_status get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const override;
    la_status set_egress_counter(la_counter_set::type_e type, la_counter_set* counter) override;
    la_status get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const override;
    la_status set_meter(const la_meter_set* meter) override;
    la_status get_meter(const la_meter_set*& out_meter) const override;
    la_status get_load_balancing_profile(la_l3_port::lb_profile_e& out_lb_profile) const override;
    la_status set_load_balancing_profile(la_l3_port::lb_profile_e lb_profile) override;
    la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_drop_counter_offset(la_stage_e stage, size_t offset) override;
    la_status get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const override;
    la_status set_source_based_forwarding(const la_l3_destination* l3_destination,
                                          bool label_present,
                                          la_mpls_label label) override;
    la_status clear_source_based_forwarding() override;
    la_status get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                          bool& out_label_present,
                                          la_mpls_label& out_label) const override;

    la_status set_ingress_sflow_enabled(bool enabled) override;
    la_status get_ingress_sflow_enabled(bool& out_enabled) const override;
    la_status set_egress_sflow_enabled(bool enabled) override;
    la_status get_egress_sflow_enabled(bool& out_enabled) const override;

    // la_ip_over_ip_tunnel_port API-s
    const la_vrf* get_underlay_vrf() const override;
    la_status set_underlay_vrf(const la_vrf* underlay_vrf) override;
    const la_vrf* get_overlay_vrf() const override;
    la_status set_overlay_vrf(const la_vrf* overlay_vrf) override;
    la_ipv4_addr_t get_remote_ip_addr() const override;
    la_status set_remote_ip_address(la_ipv4_addr_t remote_ip_address) override;
    la_status get_local_ip_prefix(la_ipv4_prefix_t& out_prefix) const override;
    la_status set_local_ip_prefix(const la_ipv4_prefix_t prefix) override;
    la_ttl_inheritance_mode_e get_ttl_inheritance_mode() const override;
    la_status set_ttl_inheritance_mode(la_ttl_inheritance_mode_e mode) override;
    la_lp_attribute_inheritance_mode_e get_lp_attribute_inheritance_mode() const override;
    la_status set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e mode) override;
    la_ipv4_addr_t get_local_ip_addr() const override;
    la_status set_local_ip_address(la_ipv4_addr_t local_ip_address) override;
    la_uint8_t get_ttl() const override;
    la_status set_ttl(la_uint8_t ttl) override;
    bool get_decrement_inner_ttl() const override;
    la_status set_decrement_inner_ttl(bool decrement_inner_ttl) override;
    la_status add_virtual_mac(const la_mac_addr_t& out_mac_addr) override;
    la_status remove_virtual_mac(const la_mac_addr_t& out_mac_addr) override;
    la_status get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const override;
    la_status get_encap_tos(la_ip_tos& out_encap_tos) const override;
    la_status set_encap_tos(la_ip_tos encap_tos) override;
    la_tunnel_encap_qos_mode_e get_encap_qos_mode() const override;
    la_status set_encap_qos_mode(la_tunnel_encap_qos_mode_e mode) override;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    /// Update Tunnel termination attributes
    la_status update_tunnel_term_attributes_per_slice(la_slice_id_t slice, npl_base_l3_lp_attributes_t& attribs);
    la_status teardown_tunnel_termination_table_per_slice(la_slice_id_t slice_idx);

    // Manage the ip tunnel DLP table
    la_status update_ip_tunnel_dlp_table();
    la_status configure_ip_tunnel_dlp_table(la_slice_pair_id_t pair_idx);
    la_status teardown_ip_tunnel_dlp_table();
    la_status teardown_ip_tunnel_dlp_table(la_slice_pair_id_t pair_idx);

    // CSC (Carrier supporting Carrier)
    la_status set_csc_enabled(bool enabled) override;
    la_status get_csc_enabled(bool& out_enabled) const override;

    la_status get_filter_group(const la_filter_group*& out_filter_group) const override;
    la_status set_filter_group(la_filter_group* filter_group) override;

private:
    struct slice_data {
        /// my_ipv4_table entry and location
        size_t my_ipv4_table_entry_location = -1;
        npl_my_ipv4_table_entry_wptr_t my_ipv4_table_entry;

        /// Tunnel termination table entry
        npl_base_l3_lp_attributes_t m_base_l3_lp_attributes;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data);

    struct slice_pair_data {
        /// Address of entry of the  large_encap_ip_tunnel_table
        npl_large_encap_ip_tunnel_table_entry_wptr_t large_encap_ip_tunnel_table_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_pair_data);

    // Device that created the port
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// L3 global ID of this port
    la_l3_port_gid_t m_gid;

    // the mode of the tunnel: encap, decap or encap-decap
    la_ip_tunnel_mode_e m_tunnel_mode;

    /// Underlay VRF object
    la_vrf_impl_wcptr m_underlay_vrf;

    /// Tunnel Source address
    la_ipv4_addr_t m_ip_addr;

    /// Tunnel Destination Prefix
    la_ipv4_prefix_t m_prefix;

    /// Attached VRF object
    la_vrf_impl_wcptr m_vrf;

    /// Ingress QoS profile
    la_ingress_qos_profile_impl_wptr m_ingress_qos_profile;

    /// Egress QoS profile
    la_egress_qos_profile_impl_wptr m_egress_qos_profile;

    // LP mode
    la_lp_attribute_inheritance_mode_e m_lp_attribute_inheritance_mode;

    // Encap TTL
    la_uint8_t m_ttl;

    // Tunnel decrements inner TTL if true
    bool m_decrement_inner_ttl;

    // Tunnel Encap QoS mode
    la_tunnel_encap_qos_mode_e m_encap_qos_mode;

    // Tunnel Encap tos
    la_ip_tos m_encap_tos;

    // The router-port implementation object
    la_vrf_port_common_base_sptr m_vrf_port_common;

    // DIP entropy mode configuration
    la_ip_tunnel_dip_entropy_mode_e m_dip_entropy_mode;
    npl_gre_dip_entropy_e m_npl_dip_entropy_mode;

    /// Per-slice-pair data
    std::vector<slice_data> m_slice_data;

    // Slice-pair data
    std::vector<slice_pair_data> m_slice_pair_data;

    npl_l3_lp_additional_attributes_t m_addl_l3_lp_attributes;

    // local ip index profile
    ipv4_sip_index_manager::ipv4_sip_index_profile_t m_my_ipv4_index{};

    // IFG management
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    /// @brief  Update Tunnel termination attributes
    la_status configure_tunnel_termination_table_per_slice(la_slice_id_t slice_idx);
    la_status update_tunnel_term_attributes();
    la_status update_tunnel_term_attributes_per_slice_with_sip_dip(la_slice_id_t slice,
                                                                   const npl_base_l3_lp_attributes_t& attribs,
                                                                   const npl_l3_lp_additional_attributes_t& addl_attribs);
    la_status update_tunnel_term_attributes_per_slice_with_dip(la_slice_id_t slice,
                                                               const npl_base_l3_lp_attributes_t& attribs,
                                                               const npl_l3_lp_additional_attributes_t& addl_attribs);
    la_status teardown_tunnel_termination_table();
    la_status teardown_tunnel_termination_table_per_slice_sip_dip(la_slice_id_t slice_idx);
    la_status teardown_tunnel_termination_table_per_slice_dip(la_slice_id_t slice_idx);

    // Helper functions for adding/removing attribute dependency
    void register_vrf_dependency(const la_vrf_impl_wcptr& vrf);
    void deregister_vrf_dependency(const la_vrf_impl_wcptr& vrf);

    la_status ipv4_tunnel_add(const la_vrf_impl_wcptr& underlay_vrf,
                              la_ipv4_prefix_t local_ip_prefix,
                              la_ipv4_addr_t remote_ip_addr,
                              const la_l3_port_wptr& port);
    la_status ipv4_tunnel_remove(const la_vrf_impl_wcptr& underlay_vrf,
                                 la_ipv4_prefix_t local_ip_prefix,
                                 la_ipv4_addr_t remote_ip_addr,
                                 const la_l3_port_wptr& port);
    la_l3_port_wptr ipv4_tunnel_search(const la_vrf_impl_wcptr& underlay_vrf,
                                       la_ipv4_prefix_t local_ip_prefix,
                                       la_ipv4_addr_t remote_ip_addr);
    la_status add_tunnel_endpoint();
    la_status remove_tunnel_endpoint();
    // get slice pairs from only network slices in use
    la_slice_pair_id_vec_t get_used_nw_slice_pairs(void);
};

} // namespace silicon_one

#endif // __LA_IP_OVER_IP_TUNNEL_PORT_IMPL_H_
