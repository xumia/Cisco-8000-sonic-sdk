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

#ifndef __LA_L3_AC_PORT_IMPL_H__
#define __LA_L3_AC_PORT_IMPL_H__
#include "api/npu/la_l3_ac_port.h"
#include "api/system/la_mirror_command.h"
#include "api/types/la_common_types.h"
#include "api/types/la_ip_types.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "ifg_use_count.h"
#include "la_ac_port_common.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_filter_group_impl.h"

namespace silicon_one
{

class la_vrf_port_common_base;

class la_l3_ac_port_impl : public la_l3_ac_port, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_l3_ac_port_impl(const la_device_impl_wptr& device);
    ~la_l3_ac_port_impl() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Object life-cycle management
    la_status initialize(la_object_id_t oid,
                         la_l3_port_gid_t gid,
                         const la_ethernet_port* ethernet_port,
                         la_vlan_id_t vid1,
                         la_vlan_id_t vid2,
                         la_mac_addr_t mac_addr,
                         const la_vrf* vrf,
                         la_ingress_qos_profile_impl* ingress_qos_profile_impl,
                         la_egress_qos_profile_impl* egress_qos_profile_impl);
    la_status destroy();
    la_status disable() override;

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

    // Mirror command API-s
    la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;

    // la_l3_ac_port API-s
    la_status set_mac(const la_mac_addr_t& mac_addr) override;
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2) override;
    la_status get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const override;
    la_status get_mldp_bud_terminate_enabled(bool& out_enabled) const override;
    la_status set_mldp_bud_terminate_enabled(bool enabled) override;

    const la_ethernet_port* get_ethernet_port() const override;
    la_status set_service_mapping_vids(la_vlan_id_t vid1, la_vlan_id_t vid2) override;
    la_status get_service_mapping_vids(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const override;
    const la_vrf* get_vrf() const override;
    la_status set_vrf(const la_vrf* vrf) override;
    la_status add_ipv4_subnet(la_ipv4_prefix_t subnet) override;
    la_status delete_ipv4_subnet(la_ipv4_prefix_t subnet) override;
    la_status get_ipv4_subnets(la_ipv4_prefix_vec_t& out_subnets) const override;
    la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    la_status delete_ipv4_host(la_ipv4_addr_t ip_addr) override;
    la_status get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const override;
    la_status get_ipv4_host_and_class_id(la_ipv4_addr_t ip_addr,
                                         la_mac_addr_t& out_mac_addr,
                                         la_class_id_t& out_class_id) const override;
    la_status get_ipv4_hosts(la_mac_addr_vec& out_mac_addresses) const override;
    la_status get_ipv4_hosts(la_ipv4_addr_vec& out_ip_addresses) const override;
    la_status add_ipv6_subnet(la_ipv6_prefix_t subnet) override;
    la_status delete_ipv6_subnet(la_ipv6_prefix_t subnet) override;
    la_status get_ipv6_subnets(la_ipv6_prefix_vec_t& out_subnets) const override;
    la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    la_status delete_ipv6_host(la_ipv6_addr_t ip_addr) override;
    la_status get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_address) const override;
    la_status get_ipv6_host_and_class_id(la_ipv6_addr_t ip_addr,
                                         la_mac_addr_t& out_mac_address,
                                         la_class_id_t& out_class_id) const override;
    la_status get_ipv6_hosts(la_mac_addr_vec& out_mac_addresses) const override;
    la_status get_ipv6_hosts(la_ipv6_addr_vec& out_ip_addresses) const override;
    la_status set_system_port_voq_set(const la_system_port* system_port, la_voq_set* voq_set) override;
    la_status set_stack_remote_logical_port_queueing_enabled(const la_system_port* system_port, bool enabled) override;
    la_status clear_system_port_voq_set(const la_system_port* system_port) override;
    la_status get_system_port_voq_set(const la_system_port* system_port, la_voq_set*& out_voq_set) const override;
    la_status get_voq_sets(la_sysport_voq_vec_t& out_voq_sets) const override;
    la_status set_tc_profile(la_tc_profile* tc_profile) override;
    la_status get_tc_profile(const la_tc_profile*& out_tc_profile) const override;
    la_status set_csc_enabled(bool enabled) override;
    la_status get_csc_enabled(bool& out_enabled) const override;
    la_status set_drop_counter_offset(la_stage_e stage, size_t offset) override;
    la_status get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const override;
    la_status add_virtual_mac(const la_mac_addr_t& out_mac_addr) override;
    la_status remove_virtual_mac(const la_mac_addr_t& out_mac_addr) override;
    la_status get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const override;

    virtual la_status update_fallback_vrf();
    la_status set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode);
    la_mpls_ttl_inheritance_mode_e get_ttl_inheritance_mode() const;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    /// @brief  Update L3 DLP attributes
    la_status update_l3_lp_attributes(la_slice_id_t slice,
                                      const npl_base_l3_lp_attributes_t& attribs,
                                      const npl_l3_lp_additional_attributes_t& additional_attribs);
    la_status get_l3_lp_qos_and_attributes(la_slice_pair_id_t pair_idx, npl_l3_dlp_qos_and_attributes_t& attrib) const;

    /// @brief  Update L3 DLP attributes in service mapping tcam
    la_status update_l3_lp_attributes_tcam(la_slice_id_t slice,
                                           const npl_mac_lp_attributes_payload_t& payload,
                                           const uint32_t relay_id);

    bool is_lp_queueing_enabled() const;
    bool is_aggregate() const;
    la_status get_bvn_profile(la_bvn_profile_t& out_bvn_profile) const;
    la_voq_set* get_voq_set() const;
    la_status set_service_mapping_type();

    la_status get_filter_group(const la_filter_group*& out_filter_group) const override;
    la_status set_filter_group(la_filter_group* filter_group) override;

private:
    struct slice_data {
        /// LP attributes table entry
        npl_service_lp_attributes_table_entry_wptr_t lp_attributes_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data);
    using l3_ac_voq_map_t = std::map<la_system_port_wcptr, la_voq_set_wptr>;

    /// @brief Default c'tor - disallowed, allowed only for serialization purposes.
    la_l3_ac_port_impl() = default;

    l3_ac_voq_map_t m_voq_map;
    l3_ac_voq_map_t::const_iterator find_in_voq_map(const la_system_port_wcptr& sys_port) const;

    // Device that created the port
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    /// L3 global ID of this port
    la_l3_port_gid_t m_gid;

    /// Attached ethernet port
    la_ethernet_port_base_wptr m_ethernet_port;

    /// Port's MAC address
    la_mac_addr_t m_mac_addr;

    /// mLDP bud node termination
    bool m_mldp_budnode_terminate = false;

    /// Attached VRF object
    la_vrf_impl_wcptr m_vrf;

    /// Per-slice-pair data
    std::vector<slice_data> m_slice_data;

    // The router-port implementation object
    std::shared_ptr<la_vrf_port_common_base> m_vrf_port_common;

    /// Common AC port implementation object
    la_ac_port_common m_ac_port_common;

    la_ethernet_port::service_mapping_type_e m_service_mapping_type;

private:
    /// Manage the LP attributes table
    la_status configure_lp_attributes_table(la_slice_id_t slice_idx);
    la_status teardown_lp_attributes_table(la_slice_id_t slice_idx);

    la_status configure_lp_over_lag_table(const la_system_port_base_wcptr& sp, const la_voq_set_wptr& voq_set);
    la_status clear_lp_over_lag_table(const la_system_port_base_wcptr& sp);
    // IFG management
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    // Attributes management
    la_status update_dependent_attributes(dependency_management_op op);

    // Helper function for filling the mymac fields in the LP attributes table
    la_status populate_mymac_fields(la_mac_addr_t mac_addr, npl_mac_lp_attributes_payload_t& out_payload);

    // Helper function for setting the mldp budnode field in the LP attributes table
    la_status populate_mldp_budnode_flag(bool enabled, npl_mac_lp_attributes_payload_t& out_payload);

    // Helper functions for adding/removing attribute dependency
    void register_vrf_dependency(const la_vrf_impl_wcptr& vrf);
    void deregister_vrf_dependency(const la_vrf_impl_wcptr& vrf);
    void register_service_mapping_dependency(const la_ethernet_port_base_wptr& ethernet_port);
    void deregister_service_mapping_dependency(const la_ethernet_port_base_wptr& ethernet_port);

    // Helper function for configuring PFC source MAC
    la_status configure_pfc_src_mac(la_mac_addr_t mac_addr);

    // TC profile
    la_tc_profile_wcptr m_tc_profile;
};

} // namespace silicon_one

#endif // __LA_L3_AC_PORT_IMPL_H_
