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

#ifndef __LA_VRF_PORT_COMMON_PACIFIC_H__
#define __LA_VRF_PORT_COMMON_PACIFIC_H__

#include "npu/la_vrf_port_common_pacgb.h"

namespace silicon_one
{

class la_vrf_port_common_pacific : public la_vrf_port_common_pacgb
{
    /////// Cereal ///////////////
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    la_vrf_port_common_pacific() = default;
    //////////////////////////////

public:
    la_vrf_port_common_pacific(const la_device_impl_wptr& device, la_l3_port_wptr parent);
    virtual ~la_vrf_port_common_pacific();

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

    la_status set_ingress_mirror_command(const la_mirror_command* mirror_cmd, bool is_acl_conditioned) override;
    la_status get_ingress_mirror_command(const la_mirror_command*& out_mirror_cmd, bool& out_is_acl_conditioned) const override;
    la_status set_filter_group(const la_filter_group_impl_wcptr& filter_group) override;

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
    la_status instantiate_slp_based_forwarding_destination(const la_l3_destination_wptr& destination);
    la_status uninstantiate_slp_based_forwarding_destination(const la_l3_destination_wptr& destination);
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
    virtual la_status update_urpf_mode(la_l3_port::urpf_mode_e urpf_mode) override;
    virtual la_status get_urpf_mode(la_l3_port::urpf_mode_e& out_urpf_mode) const override;
    virtual la_status set_urpf_mode(la_l3_port::urpf_mode_e urpf_mode) override;
};

} // namespace silicon_one

#endif // __LA_VRF_PORT_COMMON_PACIFIC_H__
