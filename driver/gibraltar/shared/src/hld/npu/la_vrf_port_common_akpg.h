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

#ifndef __LA_VRF_PORT_COMMON_AKPG_H__
#define __LA_VRF_PORT_COMMON_AKPG_H__

#include "npu/la_vrf_port_common_base.h"

namespace silicon_one
{

class la_vrf_port_common_akpg : public la_vrf_port_common_base
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_vrf_port_common_akpg() = default;
    //////////////////////////////

public:
    la_vrf_port_common_akpg(const la_device_impl_wptr& device, la_l3_port_wptr parent);
    virtual ~la_vrf_port_common_akpg();
    la_status initialize(la_l3_port_gid_t gid,
                         la_mac_addr_t mac_addr,
                         const la_switch_impl_wcptr& sw,
                         const la_vrf_impl_wcptr& vrf,
                         const la_ingress_qos_profile_impl_wptr& ingress_qos_profile_impl,
                         const la_egress_qos_profile_impl_wptr& egress_qos_profile_impl) override;

    la_status set_source_based_forwarding(const la_l3_destination* l3_destination,
                                          bool label_present,
                                          la_mpls_label label) override;
    la_status clear_source_based_forwarding() override;
    la_status get_source_based_forwarding(const la_l3_destination*& out_l3_destination,
                                          bool& out_label_present,
                                          la_mpls_label& out_label) const override;

    la_status set_rcy_sm_vlans(la_vlan_id_t vid1, la_vlan_id_t vid2) override;
    la_status get_rcy_sm_vlans(la_vlan_id_t& out_vid1, la_vlan_id_t& out_vid2) const override;

    // IFG management
    la_status add_ifg(la_slice_ifg ifg) override;
    la_status remove_ifg(la_slice_ifg ifg) override;

    // l3_port API-s
    la_status set_active(bool active) override;
    la_status set_port_egress_mode(bool active) override;

    la_status set_egress_qos_profile(la_egress_qos_profile* egress_qos_profile) override;

    la_status set_ecn_remark_enabled(bool enabled) override;
    la_status set_mac(const la_mac_addr_t& mac_addr) override;

    // Mirror Command API-s
    la_status set_egress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_ecn_counting_enabled(bool enabled) override;

    la_status set_egress_vlan_tag(la_vlan_tag_t tag1, la_vlan_tag_t tag2) override;

    // Populate the given key
    la_status get_mac_termination_table_key(la_switch_gid_t sw_id, npl_mac_termination_em_table_key_t& out_key) const override;

    // Egress DHCP snooping
    la_status set_egress_dhcp_snooping_enabled(bool enabled) override;

    la_status set_filter_group(const la_filter_group_impl_wcptr& filter_group) override;

private:
    struct slice_data {
        /// Address of entry of the l3-dlp table
        npl_l3_dlp_table_entry_wptr_t l3_dlp_table_entry = nullptr;
    };

    // Slice data
    std::vector<slice_data> m_slice_data;

private:
    void set_disable_ipv4_uc(uint64_t disable_ipv4_uc) override;
    void set_disable_ipv4_uc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv4_uc) override;
    uint64_t get_disable_ipv4_uc() const override;
    void set_disable_ipv6_mc(uint64_t disable_ipv6_mc) override;
    void set_disable_ipv6_mc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv6_mc) override;
    uint64_t get_disable_ipv6_mc() const override;

    la_status set_ttl_inheritance_mode(la_mpls_ttl_inheritance_mode_e mode) override;
    la_mpls_ttl_inheritance_mode_e get_ttl_inheritance_mode() const override;
    la_status set_vrf(const la_vrf_impl_wcptr& vrf) override;
    // Initialization helper
    npl_port_mirror_type_e get_initial_l3_lp_mirror_type() const override;
    void set_disable_mpls(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_mpls) override;
    void set_disable_mpls(uint64_t disable_mpls) override;
    uint64_t get_disable_mpls() const override;
    void set_disable_ipv4_mc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv4_mc) override;
    void set_disable_ipv4_mc(uint64_t disable_ipv4_mc) override;
    uint64_t get_disable_ipv4_mc() const override;
    void set_disable_ipv6_uc(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_ipv6_uc) override;
    void set_disable_ipv6_uc(uint64_t disable_ipv6_uc) override;
    uint64_t get_disable_ipv6_uc() const override;
    void set_l3_lp_mirror_type(npl_port_mirror_type_e l3_lp_mirror_type) override;
    la_status do_get_protocol_enabled(la_l3_protocol_e protocol, bool& out_enabled) const override;
    la_status update_protocol_enabled(la_l3_protocol_e protocol, bool enabled) override;
    la_status do_set_active(bool active, npl_base_l3_lp_attributes_t& attribs) override;

    void set_disable_mc_tunnel_decap(npl_base_l3_lp_attributes_t& attribs, uint64_t disable_mc_tunnel_decap);
    void set_disable_mc_tunnel_decap(uint64_t disable_mac_tunnel_decap);
    uint64_t get_disable_mc_tunnel_decap() const;

    void set_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs) override;
    la_status set_l3_lp_attributes(npl_base_l3_lp_attributes_t& attribs, la_l3_protocol_e protocol) override;
    la_status set_l3_lp_attributes_to_param(npl_base_l3_lp_attributes_t& attribs, la_l3_protocol_e protocol, bool enabled) override;

    // Manage the L3-DLP table
    la_status configure_txpp_dlp_profile_table(la_slice_pair_id_t slice_pair) override;

    // Update the parent's L3 DLP attributes
    la_status update_l3_lp_attributes_per_slice(la_slice_id_t slice,
                                                npl_base_l3_lp_attributes_t& attribs,
                                                npl_l3_lp_additional_attributes_t& additional_attribs) override;

    // EM table insertion helpers
    la_status get_em_table_dest_gid(la_mac_addr_t mac_addr, la_l2_destination_gid_t& out_dest_gid) const override;
    la_status get_em_table_lpm_result_type(uint64_t& out_lpm_result_type) const override;
    la_status populate_dsp_or_dspa_gid(const la_l2_destination_wcptr& l2_dest, la_l2_destination_gid_t& out_dest_gid) const;
    la_status populate_l2_dest_gid(const la_l2_destination_wcptr& l2_dest, la_l2_destination_gid_t& out_dest_gid) const;
    la_status populate_l2_flood_dest_gid(la_l2_destination_gid_t& out_dest_gid) const;

    la_status set_lp_attribute_inheritance_mode(la_lp_attribute_inheritance_mode_e mode) override;
    la_lp_attribute_inheritance_mode_e get_lp_attribute_inheritance_mode() const override;

    // Helper function for counter
    la_status configure_egress_counter(const la_counter_set_impl_wptr& new_counter, la_counter_set::type_e counter_type) override;

    // Helper functions for slp based forwarding
    la_status set_slp_based_forwarding_destination(const la_l3_destination_wptr& destination) override;
    la_status clear_slp_based_forwarding_destination() override;
    void populate_em_table_key_ipv4_address(la_ipv4_addr_t ip_addr, npl_ipv4_vrf_dip_em_table_key_t& out_em_key) const override;

    virtual la_status insert_to_em(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                   la_ipv4_addr_t ip_addr,
                                   la_mac_addr_t mac_addr,
                                   bool override_entry) override;
    virtual la_status insert_to_em(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                   la_ipv6_addr_t ip_addr,
                                   la_mac_addr_t mac_addr,
                                   bool override_entry) override;
    template <class _TableType, class _AddrType>
    la_status insert_to_em_with_class_id(const std::shared_ptr<_TableType>& table,
                                         _AddrType ip_addr,
                                         la_mac_addr_t mac_addr,
                                         la_class_id_t class_id,
                                         bool override_entry);
    template <class _TableType, class _AddrType>
    la_status add_ip_host_with_class_id(const std::shared_ptr<_TableType>& table,
                                        la_port_host<_AddrType>& port_hosts,
                                        _AddrType ip_addr,
                                        la_mac_addr_t mac_addr,
                                        la_class_id_t class_id);
    template <class _TableType, class _AddrType>
    la_status modify_ip_host_with_class_id(const std::shared_ptr<_TableType>& table,
                                           la_port_host<_AddrType>& port_hosts,
                                           _AddrType ip_addr,
                                           la_mac_addr_t mac_addr,
                                           la_class_id_t class_id);
    la_status check_class_id_and_dest_gid(la_class_id_t class_id, la_l2_destination_gid_t dest_gid) const;

    virtual la_status modify_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                     la_ipv4_addr_t ip_addr,
                                     la_mac_addr_t mac_addr) override;
    virtual la_status modify_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                     la_ipv6_addr_t ip_addr,
                                     la_mac_addr_t mac_addr) override;
    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv4_addr_t>& port_hosts,
                                  la_ipv4_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr) const override;
    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv4_addr_t>& port_hosts,
                                  la_ipv4_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr,
                                  la_class_id_t& out_class_id) const override;
    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv6_addr_t>& port_hosts,
                                  la_ipv6_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr) const override;
    virtual la_status get_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                  const la_port_host<la_ipv6_addr_t>& port_hosts,
                                  la_ipv6_addr_t ip_addr,
                                  la_mac_addr_t& out_mac_addr,
                                  la_class_id_t& out_class_id) const override;
    virtual la_status get_ip_hosts(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                   const la_port_host<la_ipv4_addr_t>& port_hosts,
                                   la_mac_addr_vec& out_mac_addresses) const override;
    virtual la_status get_ip_hosts(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                   const la_port_host<la_ipv6_addr_t>& port_hosts,
                                   la_mac_addr_vec& out_mac_addresses) const override;

    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr) override;
    virtual la_status add_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    virtual la_status modify_ipv4_host(la_ipv4_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    virtual la_status add_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    virtual la_status modify_ipv6_host(la_ipv6_addr_t ip_addr, la_mac_addr_t mac_addr, la_class_id_t class_id) override;
    virtual la_status update_urpf_mode(la_l3_port::urpf_mode_e urpf_mode) override;
    virtual la_status get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const override;
    virtual la_status set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode) override;

    // Manage the L3-DLP table
    la_status configure_l3_dlp_attributes(la_slice_id_t pair_idx) override;
    virtual la_status configure_l3_dlp_table(la_slice_id_t pair_idx) override;
    la_status teardown_l3_dlp_table(la_slice_id_t pair_idx) override;

    // Helper function for counter
    la_status configure_ingress_counter() override;
    la_status configure_egress_drop_counter_offset(size_t offset) override;
    virtual la_status add_ip_host(const std::shared_ptr<npl_ipv4_vrf_dip_em_table_t>& table,
                                  la_port_host<la_ipv4_addr_t>& port_hosts,
                                  la_ipv4_addr_t ip_addr,
                                  la_mac_addr_t mac_addr,
                                  la_class_id_t class_id) override;

    virtual la_status add_ip_host(const std::shared_ptr<npl_ipv6_vrf_dip_em_table_t>& table,
                                  la_port_host<la_ipv6_addr_t>& port_hosts,
                                  la_ipv6_addr_t ip_addr,
                                  la_mac_addr_t mac_addr,
                                  la_class_id_t class_id) override;

    virtual npl_l3_dlp_table_key_t get_l3_dlp_table_key() override;
};

} // namespace silicon_one

#endif // __LA_VRF_PORT_COMMON_AKPG_H__
