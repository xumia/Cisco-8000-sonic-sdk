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

#ifndef __LA_SVI_PORT_BASE_H__
#define __LA_SVI_PORT_BASE_H__

#include <map>
#include <vector>

#include "api/npu/la_svi_port.h"
#include "api/system/la_mirror_command.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_filter_group_impl.h"
#include "npu/la_next_hop_base.h"
#include "npu/la_switch_impl.h"

namespace silicon_one
{
class la_vrf_port_common_base;

class la_svi_port_base : public la_svi_port, public dependency_listener
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    explicit la_svi_port_base(const la_device_impl_wptr& device);
    ~la_svi_port_base() override;

    // Dependency management
    la_status notify_change(dependency_management_op op) override;

    // Object life-cycle management
    la_status initialize(la_object_id_t oid,
                         la_l3_port_gid_t gid,
                         la_mac_addr_t mac_addr,
                         const la_switch* sw,
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

    la_status set_csc_enabled(bool enabled) override;
    la_status get_csc_enabled(bool& out_enabled) const override;

    // Mirror Command API-s
    la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;

    // svi_port API-s
    la_status set_mac(const la_mac_addr_t& out_mac_addr) override;
    la_status get_mac(la_mac_addr_t& out_mac_addr) const override;
    la_status add_virtual_mac(const la_mac_addr_t& out_mac_addr) override;
    la_status remove_virtual_mac(const la_mac_addr_t& out_mac_addr) override;
    la_status get_virtual_macs(la_mac_addr_vec& out_mac_addresses) const override;
    la_status set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2) override;
    la_status get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const override;

    la_status get_switch(const la_switch*& out_switch) const override;
    la_status get_vrf(const la_vrf*& out_vrf) const override;
    la_status add_ipv4_subnet(la_ipv4_prefix_t subnet) override;
    la_status delete_ipv4_subnet(la_ipv4_prefix_t subnet) override;
    la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    virtual la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override = 0;
    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override = 0;
    la_status delete_ipv4_host(la_ipv4_addr_t ip_addr) override;
    la_status get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const override;
    la_status get_ipv4_host_and_class_id(la_ipv4_addr_t ip_addr,
                                         la_mac_addr_t& out_mac_addr,
                                         la_class_id_t& out_class_id) const override;
    la_status get_ipv4_hosts(la_mac_addr_vec& out_mac_addresses) const override;
    la_status get_ipv4_hosts(la_ipv4_addr_vec& out_ipv4_addresses) const override;
    la_status get_ipv4_subnets(la_ipv4_prefix_vec_t& out_subnets) const override;
    la_status add_ipv6_subnet(la_ipv6_prefix_t subnet) override;
    la_status delete_ipv6_subnet(la_ipv6_prefix_t subnet) override;
    la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    virtual la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override = 0;
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override = 0;
    la_status get_ipv6_subnets(la_ipv6_prefix_vec_t& out_subnets) const override;
    la_status delete_ipv6_host(la_ipv6_addr_t ip_addr) override;
    la_status get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addres) const override;
    la_status get_ipv6_host_and_class_id(la_ipv6_addr_t ip_addr,
                                         la_mac_addr_t& out_mac_addr,
                                         la_class_id_t& out_class_id) const override;
    la_status get_ipv6_hosts(la_mac_addr_vec& out_mac_addresses) const override;
    la_status get_ipv6_hosts(la_ipv6_addr_vec& out_ipv6_addresses) const override;
    la_status update_fallback_vrf();
    la_status set_drop_counter_offset(la_stage_e stage, size_t offset) override;
    la_status get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const override;
    la_status set_inject_up_source_port(la_l2_service_port* inject_up_source_port) override;
    la_status get_inject_up_source_port(la_l2_service_port*& out_inject_up_source_port) const override;
    la_status set_egress_dhcp_snooping_enabled(bool enabled) override;
    la_status get_egress_dhcp_snooping_enabled(bool& out_enabled) const override;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    /// @brief  Upate L3 DLP attributes
    la_status update_l3_lp_attributes(la_slice_id_t slice,
                                      const npl_base_l3_lp_attributes_t& attribs,
                                      const npl_l3_lp_additional_attributes_t& additional_attribs);
    virtual la_status update_additional_l3_lp_attributes(const npl_l3_lp_additional_attributes_t& additional_attribs) = 0;
    la_status get_l3_lp_qos_and_attributes(la_slice_pair_id_t pair_idx, npl_l3_dlp_qos_and_attributes_t& attrib) const;

    la_status set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode);
    la_mpls_ttl_inheritance_mode_e get_ttl_inheritance_mode() const;
    la_status add_mac_move_nh(la_mac_addr_t nh_mac, la_next_hop_base* nh);
    la_status delete_mac_move_nh(la_mac_addr_t nh_mac, la_next_hop_base* nh);

    int get_vxlan_shared_overlay_nh_count();
    void update_vxlan_shared_overlay_nh_count(int delta);
    la_mac_addr_t get_vxlan_shared_overlay_nh_mac();
    void set_vxlan_shared_overlay_nh_mac(la_mac_addr_t nh_mac);

    la_status update_no_da_termination_table_entry();
    la_status update_no_da_termination_table_entry(la_slice_id_t slice);
    la_status update_no_da_termination_table_entry(la_slice_id_t slice, const npl_base_l3_lp_attributes_t& attribs);
    la_status remove_no_da_termination_table_entry();
    la_status remove_no_da_termination_table_entry(la_slice_id_t slice);

    la_status set_rcy_sm_vlans(la_vlan_id_t vid1, la_vlan_id_t vid2);
    la_status get_rcy_sm_vlans(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2);
    la_status get_inject_up_source_port_dsp(la_l2_port_gid_t& out_npp_gid) const;
    la_status get_inject_up_source_port_gid(la_l2_port_gid_t& out_port_gid) const;
    la_status set_vrf(const la_vrf* vrf) override;
    la_status get_filter_group(const la_filter_group*& out_filter_group) const override;
    la_status set_filter_group(la_filter_group* filter_group) override;

protected:
    la_svi_port_base() = default; // Needed for cereal
    la_status add_ipv4_host_with_class_id(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id);
    la_status modify_ipv4_host_with_class_id(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id);
    la_status add_ipv6_host_with_class_id(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id);
    la_status modify_ipv6_host_with_class_id(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id);

    struct slice_data {
        /// Address of entry of the mac_termination_em_table
        npl_mac_termination_em_table_entry_wptr_t mac_termination_em_table_entry;
        npl_mac_mc_em_termination_attributes_table_entry_wptr_t mac_termination_mc_table_entry;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(slice_data);

    // Device that created the port
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Object ID
    la_object_id_t m_oid = LA_OBJECT_ID_INVALID;
    // Global L3 port ID
    la_l3_port_gid_t m_gid;

    // The router and the switch attached by the port
    la_vrf_impl_wcptr m_vrf;
    la_switch_impl_wcptr m_sw;

    // vxlan encap counter
    la_counter_set_wptr m_vxlan_encap_counter;

    // shared nh on the vxlan dummy svi port
    int m_vxlan_shared_overlay_nh_count;

    // vxlan shared nh mac address
    la_mac_addr_t m_vxlan_shared_overlay_nh_mac;

    // MAC address of the port
    la_mac_addr_t m_mac_addr;

    // Virtual MAC addresses of the port
    std::vector<la_mac_addr_t> m_virtual_mac_addr;

    // The router-port implementation object
    std::shared_ptr<la_vrf_port_common_base> m_vrf_port_common;

    // Slice data
    std::vector<slice_data> m_slice_data;

    struct la_ipv4_hosts_t {
        la_ipv4_hosts_t()
        {
        }
        la_ipv4_hosts_t(la_ipv4_addr_t h, la_class_id_t cid) : host(h), class_id(cid)
        {
        }
        la_ipv4_addr_t host;
        la_class_id_t class_id;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(la_ipv4_hosts_t);

    struct la_ipv6_hosts_t {
        la_ipv6_hosts_t()
        {
        }
        la_ipv6_hosts_t(la_ipv6_addr_t h, la_class_id_t cid) : host(h), class_id(cid)
        {
        }
        la_ipv6_addr_t host;
        la_class_id_t class_id;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(la_ipv6_hosts_t);

    struct ipv4_address_key_less {
        bool operator()(const la_ipv4_hosts_t& a, const la_ipv4_hosts_t& b) const
        {
            return (a.host.s_addr < b.host.s_addr);
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ipv4_address_key_less);

    struct ipv6_address_key_less {
        bool operator()(const la_ipv6_hosts_t& a, const la_ipv6_hosts_t& b) const
        {
            return (a.host.s_addr < b.host.s_addr);
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ipv6_address_key_less);

    using la_nh_set_t = std::set<la_next_hop_base_wptr>;
    using la_ipv4_addr_set_t = std::set<la_ipv4_hosts_t, ipv4_address_key_less>;
    using la_ipv6_addr_set_t = std::set<la_ipv6_hosts_t, ipv6_address_key_less>;

    struct la_nhs_hosts {
        la_nh_set_t nhs;
        la_ipv4_addr_set_t ipv4_hosts;
        la_ipv6_addr_set_t ipv6_hosts;
        bool empty()
        {
            return (nhs.empty() && ipv4_hosts.empty() && ipv6_hosts.empty());
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(la_nhs_hosts);

    struct la_mac_addr_key_less {
        bool operator()(const la_mac_addr_t& m1, const la_mac_addr_t& m2) const
        {
            return (m1.flat < m2.flat);
        }
    };

    using mac_move_map_t = std::map<la_mac_addr_t, la_nhs_hosts, la_mac_addr_key_less>;
    mac_move_map_t m_mac_move_map;

    // SVI Flood
    la_l2_service_port_base_wptr m_inject_up_port = nullptr;
    la_vlan_id_t m_rcy_sm_vid1;
    la_vlan_id_t m_rcy_sm_vid2;

    /// Filter group
    la_filter_group_impl_wcptr m_filter_group;

private:
    // Mac termination table management
    la_status init_mac_termination_table(la_slice_id_t slice);
    la_status teardown_mac_termination_table(la_slice_id_t slice);
    la_status init_virtual_mac_termination_table(la_slice_id_t slice);
    la_status teardown_virtual_mac_termination_table(la_slice_id_t slice);
    la_status add_virtual_mac_termination_table(la_slice_id_t slice, const la_mac_addr_t& mac_addr);
    la_status remove_virtual_mac_termination_table(la_slice_id_t slice, const la_mac_addr_t& mac_addr);

    // IFG management
    la_status add_ifg(la_slice_ifg ifg);
    la_status remove_ifg(la_slice_ifg ifg);

    // Attributes management
    la_status update_dependent_attributes(attribute_management_details attribute);
    la_status process_mac_move_notification(la_mac_addr_t mac_addr);
    la_status add_mac_move_ipv4_host(la_mac_addr_t mac_addr, la_ipv4_addr_t ipv4_host, la_class_id_t class_id);
    la_status delete_mac_move_ipv4_host(la_ipv4_addr_t ipv4_host);
    la_status add_mac_move_ipv6_host(la_mac_addr_t mac_addr, la_ipv6_addr_t ipv6_host, la_class_id_t class_id);
    la_status delete_mac_move_ipv6_host(la_ipv6_addr_t ipv6_host);
    la_status update_virtual_mac_payload(la_slice_id_t slice, const npl_base_l3_lp_attributes_t& attribs);
    void register_vrf_dependency(const la_vrf_impl_wcptr& vrf);
    void deregister_vrf_dependency(const la_vrf_impl_wcptr& vrf);

    // SVI egress flood
    virtual la_status populate_recycled_inject_up_info_table(const la_l2_service_port_base_wptr& inject_up_port) = 0;
    virtual la_status clear_recycled_inject_up_info_table() = 0;
    la_status validate_and_set_rcy_sm_vlans(const la_l2_service_port_base_wptr& inject_up_port);

    // NPL key population
    virtual void fill_npl_mac_termination_em_table_key(la_switch_gid_t sw_gid,
                                                       const la_mac_addr_t& mac_addr,
                                                       uint64_t prefix,
                                                       npl_mac_termination_em_table_key_t& out_key)
        = 0;
};
}

#endif // __LA_SVI_PORT_BASE_H__
