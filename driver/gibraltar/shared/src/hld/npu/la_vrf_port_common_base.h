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

// la_vrf_port_common_... models the shared part betweeen la_svi_port_base and la_l3_ac_port_impl, among others
//
#ifndef __LA_VRF_PORT_COMMON_BASE_H__
#define __LA_VRF_PORT_COMMON_BASE_H__

#include <array>
#include <bitset>
#include <map>
#include <vector>

#include "api/npu/la_acl.h"
#include "api/npu/la_svi_port.h"
#include "api/system/la_mirror_command.h"
#include "hld_types.h"
#include "hld_types_fwd.h"
#include "hld_utils.h"
#include "ifg_use_count.h"
#include "nplapi/nplapi_tables.h"
#include "npu/la_acl_group_base.h"

#ifdef ENABLE_SERIALIZATION
#include <cereal/types/unordered_map.hpp>
#endif

namespace silicon_one
{
class la_vrf_port_common_base : public dependency_listener, public std::enable_shared_from_this<la_vrf_port_common_base>
{
    CEREAL_SUPPORT_PRIVATE_MEMBERS

public:
    la_vrf_port_common_base(const la_device_impl_wptr& device, la_l3_port_wptr parent);
    virtual ~la_vrf_port_common_base();

    // IFG management
    virtual la_status add_ifg(la_slice_ifg ifg) = 0;
    virtual la_status remove_ifg(la_slice_ifg ifg) = 0;

    // Object life-cycle management
    virtual la_status initialize(la_l3_port_gid_t gid,
                                 la_mac_addr_t mac_addr,
                                 const la_switch_impl_wcptr& sw,
                                 const la_vrf_impl_wcptr& vrf,
                                 const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                                 const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl)
        = 0;
    la_status destroy();

    // Dependency management
    la_status notify_change(dependency_management_op op);

    // l3_port API-s
    virtual la_status set_active(bool active) = 0;
    virtual la_status do_set_active(bool active, npl_base_l3_lp_attributes_t& attribs) = 0;
    la_status get_active(bool& out_active) const;
    virtual la_status set_port_egress_mode(bool active) = 0;

    la_status get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const;
    la_status set_protocol_enabled(la_l3_protocol_e protocol, bool enabled);
    la_status get_event_enabled(la_event_e event, bool& out_enabled) const;
    la_status set_event_enabled(la_event_e event, bool enabled);
    virtual la_status get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const = 0;
    virtual la_status set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode) = 0;

    la_status set_ingress_qos_profile(la_ingress_qos_profile* ingress_qos_profile);
    la_status get_ingress_qos_profile(la_ingress_qos_profile*& out_ingress_qos_profile) const;
    virtual la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) = 0;
    la_status get_egress_qos_profile(la_egress_qos_profile*& out_egress_qos_profile) const;

    virtual la_status set_ecn_remark_enabled(bool enabled) = 0;
    la_status get_ecn_remark_enabled(bool& out_enabled) const;

    virtual la_status set_mac(const la_mac_addr_t& mac_addr) = 0;
    virtual la_status set_vrf(const la_vrf_impl_wcptr& vrf) = 0;

    la_status set_acl_group(la_acl_direction_e dir, la_acl_group* acl_group);
    la_status get_acl_group(la_acl_direction_e dir, la_acl_group*& out_acl_group) const;
    la_status clear_acl_group(la_acl_direction_e dir);

    la_status set_pbr_enabled(bool enabled);
    la_status get_pbr_enabled(bool& out_enabled) const;

    virtual la_status set_source_based_forwarding(const la_l3_destination* l3_destination, bool label_present, la_mpls_label label)
        = 0;
    virtual la_status clear_source_based_forwarding() = 0;
    virtual la_status get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                                  bool& out_label_present,
                                                  la_mpls_label& out_label) const = 0;

    // Mirror Command API-s
    virtual la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) = 0;
    la_status get_egress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const;
    virtual la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) = 0;
    virtual la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const = 0;

    virtual la_status update_fallback_vrf();

    virtual la_status set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode) = 0;
    virtual la_mpls_ttl_inheritance_mode_e get_ttl_inheritance_mode() const = 0;
    la_status set_qos_inheritance_mode(la_mpls_qos_inheritance_mode_e mode);
    la_mpls_qos_inheritance_mode_e get_qos_inheritance_mode() const;
    virtual la_status set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e mode) = 0;
    virtual la_lp_attribute_inheritance_mode_e get_lp_attribute_inheritance_mode() const = 0;
    la_status set_ingress_counter(la_counter_set::type_e type, la_counter_set* counter);
    la_status get_ingress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const;
    la_status set_egress_counter(la_counter_set::type_e type, la_counter_set* counter);
    la_status get_egress_counter(la_counter_set::type_e type, la_counter_set*& out_counter) const;
    virtual la_status set_ecn_counting_enabled(bool enabled) = 0;
    la_status get_ecn_counting_enabled(bool& out_enabled) const;
    la_status set_load_balancing_profile(la_l3_port::lb_profile_e lb_profile);
    la_status get_load_balancing_profile(la_l3_port::lb_profile_e& out_lb_profile) const;

    // svi_port API-s
    la_status get_mac(la_mac_addr_t& out_mac_addr) const;
    virtual la_status set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2) = 0;
    la_status get_egress_vlan_tag(la_vlan_tag_t& out_tag1, la_vlan_tag_t& out_tag2) const;
    la_status get_switch(const la_switch*& out_switch) const;
    la_status get_vrf(const la_vrf*& out_vrf) const;
    la_status add_ipv4_subnet(la_ipv4_prefix_t subnet);
    la_status delete_ipv4_subnet(la_ipv4_prefix_t subnet);
    la_status get_ipv4_subnets(la_ipv4_prefix_vec_t& out_subnets) const;
    la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr);
    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) = 0;
    virtual la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;
    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;
    la_status delete_ipv4_host(la_ipv4_addr_t ip_addr);
    la_status get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const;
    la_status get_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t& out_mac_addr, la_class_id_t& out_class_id) const;
    la_status get_ipv4_hosts(la_mac_addr_vec& out_mac_addresses) const;
    la_status get_ipv4_hosts(la_ipv4_addr_vec_t& out_ip_addrs) const;
    la_status add_ipv6_subnet(la_ipv6_prefix_t subnet);
    la_status delete_ipv6_subnet(la_ipv6_prefix_t subnet);
    la_status get_ipv6_subnets(la_ipv6_prefix_vec_t& out_subnets) const;
    la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr);
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) = 0;
    virtual la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) = 0;
    la_status delete_ipv6_host(la_ipv6_addr_t ip_addr);
    la_status get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addr) const;
    la_status get_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t& out_mac_addr, la_class_id_t& out_class_id) const;
    la_status get_ipv6_hosts(la_mac_addr_vec& out_mac_addresses) const;
    la_status get_ipv6_hosts(la_ipv6_addr_vec_t& out_ip_addrs) const;
    virtual la_status set_rcy_sm_vlans(la_vlan_id_t vid1, la_vlan_id_t vid2) = 0;
    virtual la_status get_rcy_sm_vlans(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const = 0;
    virtual la_status set_egress_dhcp_snooping_enabled(bool enabled) = 0;
    la_status get_egress_dhcp_snooping_enabled(bool& out_enabled) const;

    // svi_port and l3_port common API-s
    la_status set_drop_counter_offset(la_stage_e stage, size_t offset);
    la_status get_drop_counter_offset(la_stage_e stage, size_t& out_offset) const;

    /// @brief Get a list of active IFGs
    ///
    /// @retval  A vector that holds the active IFGs
    slice_ifg_vec_t get_ifgs() const;

    // Populate the given key
    virtual la_status get_mac_termination_table_key(la_switch_gid_t sw_id, npl_mac_termination_em_table_key_t& out_key) const = 0;

    // Helper function to check if port has subnets
    bool has_subnets();

    // Set meter
    la_status set_meter(la_meter_set* meter);

    // Get meter
    la_status get_meter(const la_meter_set*& out_meter) const;

    // sFlow
    la_status set_ingress_sflow_enabled(bool enabled);
    la_status get_ingress_sflow_enabled(bool& out_enabled) const;
    la_status set_egress_sflow_enabled(bool enabled);
    la_status get_egress_sflow_enabled(bool& out_enabled) const;

    // Get L3 dlp attributes
    la_status get_l3_lp_qos_and_attributes(la_slice_pair_id_t pair_idx, npl_l3_dlp_qos_and_attributes_t& attrib) const;

    // CSC (Carrier supporting Carrier)
    la_status set_csc_enabled(bool enabled);
    la_status get_csc_enabled(bool& out_enabled) const;

    la_status validate_set_acl_group(la_acl_direction_e dir, const la_acl_group_wcptr& acl_group) const;
    la_status validate_direction(la_acl_direction_e dir, la_acl_direction_e acl_key_dir) const;

    virtual la_status set_filter_group(const la_filter_group_impl_wcptr& filter_group) = 0;

public:
    enum {
        INVALID_SWITCH_ID = 0,
    };

    enum { RECYCLE_AC_SMAC = 0x000000000001 };

protected:
    la_vrf_port_common_base() = default;

    // Device that created the port
    la_device_impl_wptr m_device;

    // IFG manager
    ifg_use_count_uptr m_ifg_use_count;

    // Containing object
    la_l3_port_wptr m_parent;

    // Global L3 port ID
    la_l3_port_gid_t m_gid;

    // The router attached to the port
    la_vrf_impl_wcptr m_vrf;

    // The switch attached to the port, if any
    la_switch_impl_wcptr m_sw;

    // Bitset for profiles configuration
    std::bitset<(size_t)la_l3_protocol_e::LAST> m_protocols;

    // MAC address of the port
    la_mac_addr_t m_mac_addr;

    // Use count of registered subnets
    struct subnet_count_map_key_t {
        subnet_count_map_key_t() = default;
        size_t bytes_in_address;
        size_t prefix_length;
        union _u {
            la_uint8_t addr[sizeof(la_ipv6_addr_t)];
            la_ipv4_addr_t ipv4_addr;
            la_ipv6_addr_t ipv6_addr;
        } u;
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(subnet_count_map_key_t);
    CEREAL_SUPPORT_PRIVATE_CLASS(subnet_count_map_key_t::_u);

    class ip_host_data
    {
        CEREAL_SUPPORT_PRIVATE_MEMBERS
    private:
        la_mac_addr_t mac_addr;
        la_class_id_t class_id;
        bool is_set_class_id;

    public:
        ip_host_data()
        {
            class_id = 0;
            is_set_class_id = false;
        }

        void set_class_id(la_class_id_t cid)
        {
            class_id = cid;
            is_set_class_id = true;
        }

        void clear_class_id()
        {
            class_id = 0;
            is_set_class_id = false;
        }

        bool get_is_set_class_id() const
        {
            return is_set_class_id;
        }

        void set_mac_addr(la_mac_addr_t mac)
        {
            mac_addr = mac;
        }

        la_mac_addr_t get_mac_addr() const
        {
            return mac_addr;
        }

        la_class_id_t get_class_id() const
        {
            return class_id;
        }
    };
    CEREAL_SUPPORT_PRIVATE_CLASS(ip_host_data);

    struct subnet_count_map_key_less {
        bool operator()(const subnet_count_map_key_t& a, const subnet_count_map_key_t& b) const
        {
            if (a.bytes_in_address != b.bytes_in_address) {
                return a.bytes_in_address < b.bytes_in_address;
            }

            if (a.prefix_length != b.prefix_length) {
                return a.prefix_length < b.prefix_length;
            }

            return memcmp(a.u.addr, b.u.addr, sizeof(a.u.addr)) < 0;
        }
    };

    template <class _AddrType>
    struct address_key_less {
        bool operator()(const _AddrType& a, const _AddrType& b) const
        {
            return (a.s_addr < b.s_addr);
        }
    };

    template <class _AddrType>
    using ip_host_map = std::map<_AddrType, ip_host_data, address_key_less<_AddrType> >;

    template <class _AddrType>
    using subnet_ip_map_t = std::map<subnet_count_map_key_t, ip_host_map<_AddrType>, subnet_count_map_key_less>;

    template <class _AddrType>
    struct la_port_host {
        ip_host_map<_AddrType> pending_hosts_map;

        subnet_ip_map_t<_AddrType> m_subnet_ip_map;

        void add_to_pending_list(_AddrType ip_addr, la_mac_addr_t mac_addr)
        {
            ip_host_data data;

            data.set_mac_addr(mac_addr);

            pending_hosts_map[ip_addr] = data;
        }

        void add_to_pending_list(_AddrType ip_addr, la_mac_addr_t mac_addr, la_class_id_t id)
        {
            ip_host_data data;

            data.set_mac_addr(mac_addr);
            data.set_class_id(id);

            pending_hosts_map[ip_addr] = data;
        }

        void remove_host_from_pending_list(_AddrType ip_addr)
        {
            pending_hosts_map.erase(ip_addr);
        }

        bool pending_list_has_host(_AddrType ip_addr) const
        {
            return pending_hosts_map.find(ip_addr) != pending_hosts_map.end();
        }

        ip_host_data get_ip_host_data_from_pending_list(_AddrType ip_addr) const
        {
            return pending_hosts_map.at(ip_addr);
        }

#ifdef ENABLE_SERIALIZATION
        template <class Archive>
        void save(Archive& ar) const
        {
            ar(::cereal::make_nvp("map", pending_hosts_map));
            ar(::cereal::make_nvp("m_subnet_ip_map", m_subnet_ip_map));
        }

        template <class Archive>
        void load(Archive& ar)
        {
            ar(::cereal::make_nvp("map", pending_hosts_map));
            ar(::cereal::make_nvp("m_subnet_ip_map", m_subnet_ip_map));
        }
#endif
    };

    la_port_host<la_ipv4_addr_t> m_subnet_ipv4;
    la_port_host<la_ipv6_addr_t> m_subnet_ipv6;

    // Port VLAN
    la_vlan_tag_t m_tag1;
    la_vlan_tag_t m_tag2;

    // Port active flag
    bool m_is_active;

    // L3 LP attributes
    npl_base_l3_lp_attributes_t m_l3_lp_attributes;
    npl_l3_lp_additional_attributes_t m_l3_lp_additional_attributes;

    // SLP based forwarding result
    la_l3_destination_wptr m_slp_based_forwarding_destination;
    bool m_slp_based_forwarding_mpls_label_present;
    la_mpls_label m_slp_based_forwarding_mpls_label;

    // Counters
    std::array<la_counter_set_impl_wptr, COUNTER_DIRECTION_NUM> m_p_counter;
    std::array<la_counter_set_impl_wptr, COUNTER_DIRECTION_NUM> m_q_counter;

    /// ECN remark
    bool m_enable_ecn_remark;

    /// Enable ECN counting
    bool m_enable_ecn_counting;

    /// Egress Mirror command
    la_mirror_command_wcptr m_egress_mirror_cmd;

    /// Port mirror type
    npl_port_mirror_type_e m_egress_port_mirror_type;

    /// Ingress QoS profile
    la_ingress_qos_profile_impl_wptr m_ingress_qos_profile;

    /// Egress QoS profile
    la_egress_qos_profile_impl_wptr m_egress_qos_profile;

    /// Acls attached to ethernet/ipv4/ipv6 ingress/egress
    std::vector<la_acl_delegate_wptr> m_delegate_acls[(int)la_acl_packet_format_e::LAST][(int)la_acl_direction_e::LAST];

    // Meter
    la_meter_set_impl_wptr m_meter;

    // Egress ACL drop offset
    size_t m_egress_acl_drop_offset;

    // by default PBR (flowspec) is enabled on all l3 ports
    bool m_pbr_enabled;

    // sFlow
    bool m_egress_sflow_enabled;

    la_acl_group_wptr m_ingress_acl_group;
    la_acl_group_wptr m_egress_acl_group;

    la_status update_dependent_attributes(dependency_management_op op);
    la_status handle_acl_group_change(const la_object* changed_acl_group, la_acl_packet_format_e packet_format);

    // is recyle AC
    bool m_is_recycle_ac;

    // Egress DHCP snooping
    bool m_egress_dhcp_snooping;

    /// Filter group
    la_filter_group_impl_wcptr m_filter_group;

protected:
    // Initialization helpers
    virtual npl_port_mirror_type_e get_initial_l3_lp_mirror_type() const = 0;
    virtual void set_l3_lp_mirror_type(npl_port_mirror_type_e l3_lp_mirror_type) = 0;
    virtual void set_disable_mpls(uint64_t disable_mpls) = 0;
    virtual void set_disable_mpls(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_mpls) = 0;
    virtual uint64_t get_disable_mpls() const = 0;
    virtual void set_disable_ipv4_mc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv4_mc) = 0;
    virtual void set_disable_ipv4_mc(uint64_t disable_ipv4_mc) = 0;
    virtual uint64_t get_disable_ipv4_mc() const = 0;
    virtual void set_disable_ipv6_uc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv4_mc) = 0;
    virtual void set_disable_ipv6_uc(uint64_t disable_ipv6_uc) = 0;
    virtual uint64_t get_disable_ipv6_uc() const = 0;
    virtual la_status do_get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const = 0;
    virtual la_status update_protocol_enabled(la_l3_protocol_e protocol, bool enabled) = 0;

    virtual void set_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs) = 0;
    virtual la_status set_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs, la_l3_protocol_e protocol) = 0;
    virtual la_status set_l3_lp_attributes_to_param(npl_base_l3_lp_attributes_t& attribs, la_l3_protocol_e protocol, bool enabled)
        = 0;
    virtual void set_disable_ipv4_uc(uint64_t disable_ipv4_uc) = 0;
    virtual void set_disable_ipv4_uc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv4_uc) = 0;
    virtual uint64_t get_disable_ipv4_uc() const = 0;
    virtual void set_disable_ipv6_mc(uint64_t disable_ipv6_mc) = 0;
    virtual void set_disable_ipv6_mc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv6_mc) = 0;
    virtual uint64_t get_disable_ipv6_mc() const = 0;

    // Manage the L3-DLP table
    virtual la_status configure_l3_dlp_attributes(la_slice_pair_id_t pair_idx) = 0;
    virtual la_status configure_l3_dlp_table(la_slice_pair_id_t pair_idx) = 0;
    virtual la_status teardown_l3_dlp_table(la_slice_pair_id_t pair_idx) = 0;
    virtual la_status configure_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair) = 0;

    // Calculate the 5-bits prefix for a given mac-addr/type used in the termination tables
    la_status calculate_prefix(npl_mac_da_type_e da_type, uint64_t& out_prefix);

    // Do the actual work for set_protocol_enabled
    la_status do_set_protocol_enabled(la_l3_protocol_e protocol, bool enabled);

    // Update the given l3_dlp_table entry with the given VLAN tag.
    virtual la_status do_set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2, npl_l3_dlp_table_entry_wptr_t& entry);

    // EM table insertion helpers
    virtual la_status get_em_table_dest_gid(la_mac_addr_t mac_addr, la_l2_destination_gid_t& out_dest_gid) const = 0;
    virtual la_status get_em_table_lpm_result_type(uint64_t& out_lpm_result_type) const = 0;

    // Return an iterator in the subnet list that match the given address
    template <class _AddrType>
    la_status get_addr_subnet(subnet_ip_map_t<_AddrType>& subnet_map,
                              _AddrType ip_addr,
                              typename subnet_ip_map_t<_AddrType>::iterator& out_it);

    // Update the parent's L3 DLP attributes
    la_status update_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs);
    la_status update_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs, npl_l3_lp_additional_attributes_t& additional_attribs);
    la_status update_l3_lp_attributes_per_slice(la_slice_id_t slice, npl_base_l3_lp_attributes_t& attribs);
    virtual la_status update_l3_lp_attributes_per_slice(la_slice_id_t slice,
                                                        npl_base_l3_lp_attributes_t& attribs,
                                                        npl_l3_lp_additional_attributes_t& additional_attribs)
        = 0;

    // update RTF
    la_status update_l3_attrib_rtf_conf_set_and_stages_per_slice(la_slice_id_t slice,
                                                                 acl_group_rtf_conf_set_id_t rtf_conf_set_id,
                                                                 const la_acl_group_base_wcptr& acl_group_base);

    la_status set_acl_group_by_packet_format(la_acl_direction_e dir,
                                             la_acl_packet_format_e packet_format,
                                             const la_acl_group_wcptr& acl_group);

    // Helper function for setting the global-VRF mode
    la_status update_global_vrf_mode(bool enabled);

    // Helper function for setting the uRPF mode
    virtual la_status update_urpf_mode(la_l3_port::urpf_mode_e urpf_mode) = 0;

    // Helper function for destroy all routes
    la_status clear_routes_and_hosts();

    // Get a subnet-count map key for the given prefix
    template <class _PrefixType>
    subnet_count_map_key_t get_subnet_count_map_key(_PrefixType prefix) const;

    // Extract subnet struct from a given subnet_count_map_key_t
    template <class _PrefixType>
    void populate_subnet_prefix_from_count_map_key(const subnet_count_map_key_t& subnet_count_map_key,
                                                   _PrefixType& out_subnet) const;

    // Check if the given address is in the subnet held in the given element
    // of subnet-count map
    template <class _AddrType>
    bool is_addr_in_subnet(const _AddrType& ip_addr, const subnet_count_map_key_t& key) const;

    // Populate EM DIP table keys
    template <class _AddrType, class _KeyType>
    void populate_em_table_key(_AddrType ip_addr, _KeyType& out_em_key) const;

    // Populate EM DIP table keys
    template <class _TableType, class _AddrType>
    la_status populate_em_table_value(const std::shared_ptr<_TableType>& table,
                                      const _AddrType& ip_addr,
                                      typename _TableType::value_type& out_value) const;

    // Insert the given destination to the EM table
    virtual la_status insert_to_em(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                   la_ipv4_addr_t ip_addr,
                                   la_mac_addr_t mac_addr,
                                   bool override_entry)
        = 0;
    virtual la_status insert_to_em(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                   la_ipv6_addr_t ip_addr,
                                   la_mac_addr_t mac_addr,
                                   bool override_entry)
        = 0;

    template <class _TableType, class _AddrType>
    la_status add_ip_host(const std::shared_ptr<_TableType>& table,
                          _AddrType ip_addr,
                          la_mac_addr_t mac_addr,
                          la_port_host<_AddrType>& port_hosts);

    virtual la_status modify_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                     la_ipv4_addr_t ip_addr,
                                     la_mac_addr_t mac_addr)
        = 0;
    virtual la_status modify_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                     la_ipv6_addr_t ip_addr,
                                     la_mac_addr_t mac_addr)
        = 0;

    template <class _PrefixType, class _AddrType>
    la_status add_ip_subnet(subnet_ip_map_t<_AddrType>& subnet_map, _PrefixType subnet);

    template <class _TableType, class _PrefixType, class _AddrType>
    la_status add_ip_subnet(const std::shared_ptr<_TableType>& table, la_port_host<_AddrType>& port_hosts, _PrefixType subnet);

    template <class _AddrType, class _PrefixType>
    la_status get_ip_subnets(const subnet_ip_map_t<_AddrType>& subnet_map, std::vector<_PrefixType>& out_subnets) const;

    template <class _PrefixType>
    la_status add_subnet_to_vrf(_PrefixType subnet);

    template <class _PrefixType>
    la_status remove_subnet_from_vrf(_PrefixType subnet);

    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv4_addr_t>& port_hosts,
                                  la_ipv4_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr) const = 0;

    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv4_addr_t>& port_hosts,
                                  la_ipv4_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr,
                                  la_class_id_t& out_class_id) const = 0;

    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv6_addr_t>& port_hosts,
                                  la_ipv6_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr) const = 0;

    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv6_addr_t>& port_hosts,
                                  la_ipv6_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr,
                                  la_class_id_t& out_class_id) const = 0;

    virtual la_status get_ip_hosts(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                   const la_port_host<la_ipv4_addr_t>& port_hosts,
                                   la_mac_addr_vec& out_mac_addresses) const = 0;

    virtual la_status get_ip_hosts(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                   const la_port_host<la_ipv6_addr_t>& port_hosts,
                                   la_mac_addr_vec& out_mac_addresses) const = 0;

    template <class _TableType, class _AddrType>
    la_status delete_ip_hosts(const std::shared_ptr<_TableType>& table, la_port_host<_AddrType>& port_hosts);

    template <class _TableType, class _AddrType>
    la_status delete_ip_host(const std::shared_ptr<_TableType>& table, _AddrType ip_addr, la_port_host<_AddrType>& port_hosts);

    template <class _AddrType, class _PrefixType>
    la_status delete_ip_subnet(subnet_ip_map_t<_AddrType>& subnet_map, _PrefixType subnet);

    template <class _TableType, class _AddrType, class _PrefixType>
    la_status delete_ip_subnet(const std::shared_ptr<_TableType>& table, la_port_host<_AddrType>& port_hosts, _PrefixType subnet);

    // Helper function for counter
    la_counter_set_impl_wptr get_curr_counter(la_counter_set::type_e counter_type, counter_direction_e direction) const;
    la_status do_set_counter(const la_counter_set_impl_wptr& new_counter,
                             la_counter_set::type_e counter_type,
                             counter_direction_e direction);
    bool is_counter_set_size_valid(const la_counter_set_impl_wptr& counter, la_counter_set::type_e counter_type) const;
    la_status verify_set_counter_parameters(const la_counter_set_impl_wptr& new_counter, la_counter_set::type_e counter_type) const;
    virtual la_status configure_ingress_counter() = 0;
    virtual la_status configure_egress_counter(const la_counter_set_impl_wptr& new_counter, la_counter_set::type_e counter_type)
        = 0;
    la_status configure_ingress_drop_counter_offset(size_t offset);
    virtual la_status configure_egress_drop_counter_offset(size_t offset) = 0;

    // Helper functions for slp based forwarding
    la_status set_slp_based_forwarding_enabled(bool enabled);
    virtual la_status set_slp_based_forwarding_destination(const la_l3_destination_wptr& destination) = 0;
    virtual la_status clear_slp_based_forwarding_destination() = 0;
    la_acl_delegate_wptr get_and_clear_acl_at_stage(la_acl::stage_e stage, la_acl_key_type_e new_key_type);
    virtual void populate_em_table_key_ipv4_address(la_ipv4_addr_t ip_addr, npl_ipv4_vrf_dip_em_table_key_t& out_em_key) const = 0;

    // sFlow
    template <class _PrefixType>
    la_status update_subnet(_PrefixType subnet);
    template <class _AddrType, class _PrefixType>
    la_status set_egress_sflow_enabled_host(const subnet_ip_map_t<_AddrType>& subnet_map);

    // Helper function to determine if mirror_cmd's type is the intended one (second argument)
    la_status verify_matching_mirror_types(const la_mirror_command* mirror_cmd, mirror_type_e type);

    virtual la_status add_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                  la_port_host<la_ipv4_addr_t>& port_hosts,
                                  la_ipv4_addr_t ip_addr,
                                  la_mac_addr_t mac_addr,
                                  la_class_id_t class_id)
        = 0;
    virtual la_status add_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                  la_port_host<la_ipv6_addr_t>& port_hosts,
                                  la_ipv6_addr_t ip_addr,
                                  la_mac_addr_t mac_addr,
                                  la_class_id_t class_id)
        = 0;

    virtual npl_l3_dlp_table_key_t get_l3_dlp_table_key() = 0;
};

} // namespace silicon_one

#endif // __LA_VRF_PORT_COMMON_BASE_H__
