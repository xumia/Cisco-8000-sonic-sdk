// BEGIN_LEGAL
//
// Copyright (c) 2020-current, Cisco Systems, Inc. ("Cisco"). All Rights Reserved.
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

#ifndef __HLD_TYPES_FWD_H__
#define __HLD_TYPES_FWD_H__

#include "common/cereal_utils.h"
#include "common/weak_ptr_unsafe.h"

#include <memory>

// Smart pointer definitions
namespace silicon_one

{

// API classes
class la_system_port_scheduler;
using la_system_port_scheduler_sptr = std::shared_ptr<la_system_port_scheduler>;
using la_system_port_scheduler_scptr = std::shared_ptr<const la_system_port_scheduler>;
using la_system_port_scheduler_wptr = weak_ptr_unsafe<la_system_port_scheduler>;
using la_system_port_scheduler_wcptr = weak_ptr_unsafe<const la_system_port_scheduler>;

class la_interface_scheduler;
using la_interface_scheduler_sptr = std::shared_ptr<la_interface_scheduler>;
using la_interface_scheduler_scptr = std::shared_ptr<const la_interface_scheduler>;
using la_interface_scheduler_wptr = weak_ptr_unsafe<la_interface_scheduler>;
using la_interface_scheduler_wcptr = weak_ptr_unsafe<const la_interface_scheduler>;

class la_tc_profile;
using la_tc_profile_sptr = std::shared_ptr<la_tc_profile>;
using la_tc_profile_scptr = std::shared_ptr<const la_tc_profile>;
using la_tc_profile_wptr = weak_ptr_unsafe<la_tc_profile>;
using la_tc_profile_wcptr = weak_ptr_unsafe<const la_tc_profile>;

class la_logical_port_scheduler;
using la_logical_port_scheduler_sptr = std::shared_ptr<la_logical_port_scheduler>;
using la_logical_port_scheduler_scptr = std::shared_ptr<const la_logical_port_scheduler>;
using la_logical_port_scheduler_wptr = weak_ptr_unsafe<la_logical_port_scheduler>;
using la_logical_port_scheduler_wcptr = weak_ptr_unsafe<const la_logical_port_scheduler>;

class la_ifg_scheduler;
using la_ifg_scheduler_sptr = std::shared_ptr<la_ifg_scheduler>;
using la_ifg_scheduler_scptr = std::shared_ptr<const la_ifg_scheduler>;
using la_ifg_scheduler_wptr = weak_ptr_unsafe<la_ifg_scheduler>;
using la_ifg_scheduler_wcptr = weak_ptr_unsafe<const la_ifg_scheduler>;

class la_output_queue_scheduler;
using la_output_queue_scheduler_sptr = std::shared_ptr<la_output_queue_scheduler>;
using la_output_queue_scheduler_scptr = std::shared_ptr<const la_output_queue_scheduler>;
using la_output_queue_scheduler_wptr = weak_ptr_unsafe<la_output_queue_scheduler>;
using la_output_queue_scheduler_wcptr = weak_ptr_unsafe<const la_output_queue_scheduler>;

class la_fabric_port_scheduler;
using la_fabric_port_scheduler_sptr = std::shared_ptr<la_fabric_port_scheduler>;
using la_fabric_port_scheduler_scptr = std::shared_ptr<const la_fabric_port_scheduler>;
using la_fabric_port_scheduler_wptr = weak_ptr_unsafe<la_fabric_port_scheduler>;
using la_fabric_port_scheduler_wcptr = weak_ptr_unsafe<const la_fabric_port_scheduler>;

class la_voq_set;
using la_voq_set_sptr = std::shared_ptr<la_voq_set>;
using la_voq_set_scptr = std::shared_ptr<const la_voq_set>;
using la_voq_set_wptr = weak_ptr_unsafe<la_voq_set>;
using la_voq_set_wcptr = weak_ptr_unsafe<const la_voq_set>;

class la_voq_set_base;
using la_voq_set_base_sptr = std::shared_ptr<la_voq_set_base>;
using la_voq_set_base_scptr = std::shared_ptr<const la_voq_set_base>;
using la_voq_set_base_wptr = weak_ptr_unsafe<la_voq_set_base>;
using la_voq_set_base_wcptr = weak_ptr_unsafe<const la_voq_set_base>;

class la_interface_scheduler;
using la_interface_scheduler_sptr = std::shared_ptr<la_interface_scheduler>;
using la_interface_scheduler_scptr = std::shared_ptr<const la_interface_scheduler>;
using la_interface_scheduler_wptr = weak_ptr_unsafe<la_interface_scheduler>;
using la_interface_scheduler_wcptr = weak_ptr_unsafe<const la_interface_scheduler>;

class la_l3_fec;
using la_l3_fec_sptr = std::shared_ptr<la_l3_fec>;
using la_l3_fec_scptr = std::shared_ptr<const la_l3_fec>;
using la_l3_fec_wptr = weak_ptr_unsafe<la_l3_fec>;
using la_l3_fec_wcptr = weak_ptr_unsafe<const la_l3_fec>;

class la_ip_tunnel_port;
using la_ip_tunnel_port_sptr = std::shared_ptr<la_ip_tunnel_port>;
using la_ip_tunnel_port_scptr = std::shared_ptr<const la_ip_tunnel_port>;
using la_ip_tunnel_port_wptr = weak_ptr_unsafe<la_ip_tunnel_port>;
using la_ip_tunnel_port_wcptr = weak_ptr_unsafe<const la_ip_tunnel_port>;

class la_acl_key_profile;
using la_acl_key_profile_sptr = std::shared_ptr<la_acl_key_profile>;
using la_acl_key_profile_scptr = std::shared_ptr<const la_acl_key_profile>;
using la_acl_key_profile_wptr = weak_ptr_unsafe<la_acl_key_profile>;
using la_acl_key_profile_wcptr = weak_ptr_unsafe<const la_acl_key_profile>;

class la_acl_key_profile_base;
using la_acl_key_profile_base_sptr = std::shared_ptr<la_acl_key_profile_base>;
using la_acl_key_profile_base_scptr = std::shared_ptr<const la_acl_key_profile_base>;
using la_acl_key_profile_base_wptr = weak_ptr_unsafe<la_acl_key_profile_base>;
using la_acl_key_profile_base_wcptr = weak_ptr_unsafe<const la_acl_key_profile_base>;

class la_acl_key_profile_akpg;
using la_acl_key_profile_akpg_sptr = std::shared_ptr<la_acl_key_profile_akpg>;
using la_acl_key_profile_akpg_scptr = std::shared_ptr<const la_acl_key_profile_akpg>;
using la_acl_key_profile_akpg_wptr = weak_ptr_unsafe<la_acl_key_profile_akpg>;
using la_acl_key_profile_akpg_wcptr = weak_ptr_unsafe<const la_acl_key_profile_akpg>;

class la_acl_key_profile_pacific;
using la_acl_key_profile_pacific_sptr = std::shared_ptr<la_acl_key_profile_pacific>;
using la_acl_key_profile_pacific_scptr = std::shared_ptr<const la_acl_key_profile_pacific>;
using la_acl_key_profile_pacific_wptr = weak_ptr_unsafe<la_acl_key_profile_pacific>;
using la_acl_key_profile_pacific_wcptr = weak_ptr_unsafe<const la_acl_key_profile_pacific>;

class la_acl_key_profile_gibraltar;
using la_acl_key_profile_gibraltar_sptr = std::shared_ptr<la_acl_key_profile_gibraltar>;
using la_acl_key_profile_gibraltar_scptr = std::shared_ptr<const la_acl_key_profile_gibraltar>;
using la_acl_key_profile_gibraltar_wptr = weak_ptr_unsafe<la_acl_key_profile_gibraltar>;
using la_acl_key_profile_gibraltar_wcptr = weak_ptr_unsafe<const la_acl_key_profile_gibraltar>;

class la_acl_command_profile;
using la_acl_command_profile_sptr = std::shared_ptr<la_acl_command_profile>;
using la_acl_command_profile_scptr = std::shared_ptr<const la_acl_command_profile>;
using la_acl_command_profile_wptr = weak_ptr_unsafe<la_acl_command_profile>;
using la_acl_command_profile_wcptr = weak_ptr_unsafe<const la_acl_command_profile>;

class la_acl_command_profile_base;
using la_acl_command_profile_base_sptr = std::shared_ptr<la_acl_command_profile_base>;
using la_acl_command_profile_base_scptr = std::shared_ptr<const la_acl_command_profile_base>;
using la_acl_command_profile_base_wptr = weak_ptr_unsafe<la_acl_command_profile_base>;
using la_acl_command_profile_base_wcptr = weak_ptr_unsafe<const la_acl_command_profile_base>;

class la_acl_group;
using la_acl_group_sptr = std::shared_ptr<la_acl_group>;
using la_acl_group_scptr = std::shared_ptr<const la_acl_group>;
using la_acl_group_wptr = weak_ptr_unsafe<la_acl_group>;
using la_acl_group_wcptr = weak_ptr_unsafe<const la_acl_group>;

class la_acl_group_base;
using la_acl_group_base_sptr = std::shared_ptr<la_acl_group_base>;
using la_acl_group_base_scptr = std::shared_ptr<const la_acl_group_base>;
using la_acl_group_base_wptr = weak_ptr_unsafe<la_acl_group_base>;
using la_acl_group_base_wcptr = weak_ptr_unsafe<const la_acl_group_base>;

class la_acl_group_pacific;
using la_acl_group_pacific_sptr = std::shared_ptr<la_acl_group_pacific>;
using la_acl_group_pacific_scptr = std::shared_ptr<const la_acl_group_pacific>;
using la_acl_group_pacific_wptr = weak_ptr_unsafe<la_acl_group_pacific>;
using la_acl_group_pacific_wcptr = weak_ptr_unsafe<const la_acl_group_pacific>;

class la_acl_group_gibraltar;
using la_acl_group_gibraltar_sptr = std::shared_ptr<la_acl_group_gibraltar>;
using la_acl_group_gibraltar_scptr = std::shared_ptr<const la_acl_group_gibraltar>;
using la_acl_group_gibraltar_wptr = weak_ptr_unsafe<la_acl_group_gibraltar>;
using la_acl_group_gibraltar_wcptr = weak_ptr_unsafe<const la_acl_group_gibraltar>;

class la_l3_protection_group;
using la_l3_protection_group_sptr = std::shared_ptr<la_l3_protection_group>;
using la_l3_protection_group_scptr = std::shared_ptr<const la_l3_protection_group>;
using la_l3_protection_group_wptr = weak_ptr_unsafe<la_l3_protection_group>;
using la_l3_protection_group_wcptr = weak_ptr_unsafe<const la_l3_protection_group>;

class la_protection_monitor;
using la_protection_monitor_sptr = std::shared_ptr<la_protection_monitor>;
using la_protection_monitor_scptr = std::shared_ptr<const la_protection_monitor>;
using la_protection_monitor_wptr = weak_ptr_unsafe<la_protection_monitor>;
using la_protection_monitor_wcptr = weak_ptr_unsafe<const la_protection_monitor>;

class la_rate_limiter_set;
using la_rate_limiter_set_sptr = std::shared_ptr<la_rate_limiter_set>;
using la_rate_limiter_set_scptr = std::shared_ptr<const la_rate_limiter_set>;
using la_rate_limiter_set_wptr = weak_ptr_unsafe<la_rate_limiter_set>;
using la_rate_limiter_set_wcptr = weak_ptr_unsafe<const la_rate_limiter_set>;

class la_fabric_multicast_group;
using la_fabric_multicast_group_sptr = std::shared_ptr<la_fabric_multicast_group>;
using la_fabric_multicast_group_scptr = std::shared_ptr<const la_fabric_multicast_group>;
using la_fabric_multicast_group_wptr = weak_ptr_unsafe<la_fabric_multicast_group>;
using la_fabric_multicast_group_wcptr = weak_ptr_unsafe<const la_fabric_multicast_group>;

class la_lpts;
using la_lpts_sptr = std::shared_ptr<la_lpts>;
using la_lpts_scptr = std::shared_ptr<const la_lpts>;
using la_lpts_wptr = weak_ptr_unsafe<la_lpts>;
using la_lpts_wcptr = weak_ptr_unsafe<const la_lpts>;

class la_og_lpts_application;
using la_og_lpts_application_sptr = std::shared_ptr<la_og_lpts_application>;
using la_og_lpts_application_scptr = std::shared_ptr<const la_og_lpts_application>;
using la_og_lpts_application_wptr = weak_ptr_unsafe<la_og_lpts_application>;
using la_og_lpts_application_wcptr = weak_ptr_unsafe<const la_og_lpts_application>;

class la_svi_port;
using la_svi_port_sptr = std::shared_ptr<la_svi_port>;
using la_svi_port_scptr = std::shared_ptr<const la_svi_port>;
using la_svi_port_wptr = weak_ptr_unsafe<la_svi_port>;
using la_svi_port_wcptr = weak_ptr_unsafe<const la_svi_port>;

class la_l2_service_port;
using la_l2_service_port_sptr = std::shared_ptr<la_l2_service_port>;
using la_l2_service_port_scptr = std::shared_ptr<const la_l2_service_port>;
using la_l2_service_port_wptr = weak_ptr_unsafe<la_l2_service_port>;
using la_l2_service_port_wcptr = weak_ptr_unsafe<const la_l2_service_port>;

class la_l3_port;
using la_l3_port_sptr = std::shared_ptr<la_l3_port>;
using la_l3_port_scptr = std::shared_ptr<const la_l3_port>;
using la_l3_port_wptr = weak_ptr_unsafe<la_l3_port>;
using la_l3_port_wcptr = weak_ptr_unsafe<const la_l3_port>;

class la_lsr;
using la_lsr_sptr = std::shared_ptr<la_lsr>;
using la_lsr_scptr = std::shared_ptr<const la_lsr>;
using la_lsr_wptr = weak_ptr_unsafe<la_lsr>;
using la_lsr_wcptr = weak_ptr_unsafe<const la_lsr>;

class la_counter_set;
using la_counter_set_sptr = std::shared_ptr<la_counter_set>;
using la_counter_set_scptr = std::shared_ptr<const la_counter_set>;
using la_counter_set_wptr = weak_ptr_unsafe<la_counter_set>;
using la_counter_set_wcptr = weak_ptr_unsafe<const la_counter_set>;

class la_vrf;
using la_vrf_sptr = std::shared_ptr<la_vrf>;
using la_vrf_scptr = std::shared_ptr<const la_vrf>;
using la_vrf_wptr = weak_ptr_unsafe<la_vrf>;
using la_vrf_wcptr = weak_ptr_unsafe<const la_vrf>;

class la_destination_pe;
using la_destination_pe_sptr = std::shared_ptr<la_destination_pe>;
using la_destination_pe_scptr = std::shared_ptr<const la_destination_pe>;
using la_destination_pe_wptr = weak_ptr_unsafe<la_destination_pe>;
using la_destination_pe_wcptr = weak_ptr_unsafe<const la_destination_pe>;

class la_acl_scaled;
using la_acl_scaled_sptr = std::shared_ptr<la_acl_scaled>;
using la_acl_scaled_scptr = std::shared_ptr<const la_acl_scaled>;
using la_acl_scaled_wptr = weak_ptr_unsafe<la_acl_scaled>;
using la_acl_scaled_wcptr = weak_ptr_unsafe<const la_acl_scaled>;

class la_l2_destination;
using la_l2_destination_sptr = std::shared_ptr<la_l2_destination>;
using la_l2_destination_scptr = std::shared_ptr<const la_l2_destination>;
using la_l2_destination_wptr = weak_ptr_unsafe<la_l2_destination>;
using la_l2_destination_wcptr = weak_ptr_unsafe<const la_l2_destination>;

class la_next_hop;
using la_next_hop_sptr = std::shared_ptr<la_next_hop>;
using la_next_hop_scptr = std::shared_ptr<const la_next_hop>;
using la_next_hop_wptr = weak_ptr_unsafe<la_next_hop>;
using la_next_hop_wcptr = weak_ptr_unsafe<const la_next_hop>;

class la_vxlan_next_hop;
using la_vxlan_next_hop_sptr = std::shared_ptr<la_vxlan_next_hop>;
using la_vxlan_next_hop_scptr = std::shared_ptr<const la_vxlan_next_hop>;
using la_vxlan_next_hop_wptr = weak_ptr_unsafe<la_vxlan_next_hop>;
using la_vxlan_next_hop_wcptr = weak_ptr_unsafe<const la_vxlan_next_hop>;

class la_gre_port;
using la_gre_port_sptr = std::shared_ptr<la_gre_port>;
using la_gre_port_scptr = std::shared_ptr<const la_gre_port>;
using la_gre_port_wptr = weak_ptr_unsafe<la_gre_port>;
using la_gre_port_wcptr = weak_ptr_unsafe<const la_gre_port>;

class la_gue_port;
using la_gue_port_sptr = std::shared_ptr<la_gue_port>;
using la_gue_port_scptr = std::shared_ptr<const la_gue_port>;
using la_gue_port_wptr = weak_ptr_unsafe<la_gue_port>;
using la_gue_port_wcptr = weak_ptr_unsafe<const la_gue_port>;

class la_ethernet_port;
using la_ethernet_port_sptr = std::shared_ptr<la_ethernet_port>;
using la_ethernet_port_scptr = std::shared_ptr<const la_ethernet_port>;
using la_ethernet_port_wptr = weak_ptr_unsafe<la_ethernet_port>;
using la_ethernet_port_wcptr = weak_ptr_unsafe<const la_ethernet_port>;

class la_forus_destination;
using la_forus_destination_sptr = std::shared_ptr<la_forus_destination>;
using la_forus_destination_scptr = std::shared_ptr<const la_forus_destination>;
using la_forus_destination_wptr = weak_ptr_unsafe<la_forus_destination>;
using la_forus_destination_wcptr = weak_ptr_unsafe<const la_forus_destination>;

class la_mpls_vpn_decap;
using la_mpls_vpn_decap_sptr = std::shared_ptr<la_mpls_vpn_decap>;
using la_mpls_vpn_decap_scptr = std::shared_ptr<const la_mpls_vpn_decap>;
using la_mpls_vpn_decap_wptr = weak_ptr_unsafe<la_mpls_vpn_decap>;
using la_mpls_vpn_decap_wcptr = weak_ptr_unsafe<const la_mpls_vpn_decap>;

class la_mldp_vpn_decap;
using la_mldp_vpn_decap_sptr = std::shared_ptr<la_mldp_vpn_decap>;
using la_mldp_vpn_decap_scptr = std::shared_ptr<const la_mldp_vpn_decap>;
using la_mldp_vpn_decap_wptr = weak_ptr_unsafe<la_mldp_vpn_decap>;
using la_mldp_vpn_decap_wcptr = weak_ptr_unsafe<const la_mldp_vpn_decap>;

class la_asbr_lsp;
using la_asbr_lsp_sptr = std::shared_ptr<la_asbr_lsp>;
using la_asbr_lsp_scptr = std::shared_ptr<const la_asbr_lsp>;
using la_asbr_lsp_wptr = weak_ptr_unsafe<la_asbr_lsp>;
using la_asbr_lsp_wcptr = weak_ptr_unsafe<const la_asbr_lsp>;

class la_mpls_nhlfe;
using la_mpls_nhlfe_sptr = std::shared_ptr<la_mpls_nhlfe>;
using la_mpls_nhlfe_scptr = std::shared_ptr<const la_mpls_nhlfe>;
using la_mpls_nhlfe_wptr = weak_ptr_unsafe<la_mpls_nhlfe>;
using la_mpls_nhlfe_wcptr = weak_ptr_unsafe<const la_mpls_nhlfe>;

class la_multicast_protection_group;
using la_multicast_protection_group_sptr = std::shared_ptr<la_multicast_protection_group>;
using la_multicast_protection_group_scptr = std::shared_ptr<const la_multicast_protection_group>;
using la_multicast_protection_group_wptr = weak_ptr_unsafe<la_multicast_protection_group>;
using la_multicast_protection_group_wcptr = weak_ptr_unsafe<const la_multicast_protection_group>;

class la_multicast_protection_monitor;
using la_multicast_protection_monitor_sptr = std::shared_ptr<la_multicast_protection_monitor>;
using la_multicast_protection_monitor_scptr = std::shared_ptr<const la_multicast_protection_monitor>;
using la_multicast_protection_monitor_wptr = weak_ptr_unsafe<la_multicast_protection_monitor>;
using la_multicast_protection_monitor_wcptr = weak_ptr_unsafe<const la_multicast_protection_monitor>;

class la_l3_ac_port;
using la_l3_ac_port_sptr = std::shared_ptr<la_l3_ac_port>;
using la_l3_ac_port_scptr = std::shared_ptr<const la_l3_ac_port>;
using la_l3_ac_port_wptr = weak_ptr_unsafe<la_l3_ac_port>;
using la_l3_ac_port_wcptr = weak_ptr_unsafe<const la_l3_ac_port>;

class la_prefix_object;
using la_prefix_object_sptr = std::shared_ptr<la_prefix_object>;
using la_prefix_object_scptr = std::shared_ptr<const la_prefix_object>;
using la_prefix_object_wptr = weak_ptr_unsafe<la_prefix_object>;
using la_prefix_object_wcptr = weak_ptr_unsafe<const la_prefix_object>;

class la_switch;
using la_switch_sptr = std::shared_ptr<la_switch>;
using la_switch_scptr = std::shared_ptr<const la_switch>;
using la_switch_wptr = weak_ptr_unsafe<la_switch>;
using la_switch_wcptr = weak_ptr_unsafe<const la_switch>;

class la_acl;
using la_acl_sptr = std::shared_ptr<la_acl>;
using la_acl_scptr = std::shared_ptr<const la_acl>;
using la_acl_wptr = weak_ptr_unsafe<la_acl>;
using la_acl_wcptr = weak_ptr_unsafe<const la_acl>;

class la_pcl;
using la_pcl_sptr = std::shared_ptr<la_pcl>;
using la_pcl_scptr = std::shared_ptr<const la_pcl>;
using la_pcl_wptr = weak_ptr_unsafe<la_pcl>;
using la_pcl_wcptr = weak_ptr_unsafe<const la_pcl>;

class la_l3_destination;
using la_l3_destination_sptr = std::shared_ptr<la_l3_destination>;
using la_l3_destination_scptr = std::shared_ptr<const la_l3_destination>;
using la_l3_destination_wptr = weak_ptr_unsafe<la_l3_destination>;
using la_l3_destination_wcptr = weak_ptr_unsafe<const la_l3_destination>;

class la_te_tunnel;
using la_te_tunnel_sptr = std::shared_ptr<la_te_tunnel>;
using la_te_tunnel_scptr = std::shared_ptr<const la_te_tunnel>;
using la_te_tunnel_wptr = weak_ptr_unsafe<la_te_tunnel>;
using la_te_tunnel_wcptr = weak_ptr_unsafe<const la_te_tunnel>;

class la_ip_over_ip_tunnel_port;
using la_ip_over_ip_tunnel_port_sptr = std::shared_ptr<la_ip_over_ip_tunnel_port>;
using la_ip_over_ip_tunnel_port_scptr = std::shared_ptr<const la_ip_over_ip_tunnel_port>;
using la_ip_over_ip_tunnel_port_wptr = weak_ptr_unsafe<la_ip_over_ip_tunnel_port>;
using la_ip_over_ip_tunnel_port_wcptr = weak_ptr_unsafe<const la_ip_over_ip_tunnel_port>;

class la_mpls_label_destination;
using la_mpls_label_destination_sptr = std::shared_ptr<la_mpls_label_destination>;
using la_mpls_label_destination_scptr = std::shared_ptr<const la_mpls_label_destination>;
using la_mpls_label_destination_wptr = weak_ptr_unsafe<la_mpls_label_destination>;
using la_mpls_label_destination_wcptr = weak_ptr_unsafe<const la_mpls_label_destination>;

class la_ip_multicast_group;
using la_ip_multicast_group_sptr = std::shared_ptr<la_ip_multicast_group>;
using la_ip_multicast_group_scptr = std::shared_ptr<const la_ip_multicast_group>;
using la_ip_multicast_group_wptr = weak_ptr_unsafe<la_ip_multicast_group>;
using la_ip_multicast_group_wcptr = weak_ptr_unsafe<const la_ip_multicast_group>;

class la_filter_group;
using la_filter_group_sptr = std::shared_ptr<la_filter_group>;
using la_filter_group_scptr = std::shared_ptr<const la_filter_group>;
using la_filter_group_wptr = weak_ptr_unsafe<la_filter_group>;
using la_filter_group_wcptr = weak_ptr_unsafe<const la_filter_group>;

class la_bfd_session;
using la_bfd_session_sptr = std::shared_ptr<la_bfd_session>;
using la_bfd_session_scptr = std::shared_ptr<const la_bfd_session>;
using la_bfd_session_wptr = weak_ptr_unsafe<la_bfd_session>;
using la_bfd_session_wcptr = weak_ptr_unsafe<const la_bfd_session>;

class la_ecmp_group;
using la_ecmp_group_sptr = std::shared_ptr<la_ecmp_group>;
using la_ecmp_group_scptr = std::shared_ptr<const la_ecmp_group>;
using la_ecmp_group_wptr = weak_ptr_unsafe<la_ecmp_group>;
using la_ecmp_group_wcptr = weak_ptr_unsafe<const la_ecmp_group>;

class la_ip_tunnel_destination;
using la_ip_tunnel_destination_sptr = std::shared_ptr<la_ip_tunnel_destination>;
using la_ip_tunnel_destination_scptr = std::shared_ptr<const la_ip_tunnel_destination>;
using la_ip_tunnel_destination_wptr = weak_ptr_unsafe<la_ip_tunnel_destination>;
using la_ip_tunnel_destination_wcptr = weak_ptr_unsafe<const la_ip_tunnel_destination>;

class la_mpls_vpn_encap;
using la_mpls_vpn_encap_sptr = std::shared_ptr<la_mpls_vpn_encap>;
using la_mpls_vpn_encap_scptr = std::shared_ptr<const la_mpls_vpn_encap>;
using la_mpls_vpn_encap_wptr = weak_ptr_unsafe<la_mpls_vpn_encap>;
using la_mpls_vpn_encap_wcptr = weak_ptr_unsafe<const la_mpls_vpn_encap>;

class la_l2_port;
using la_l2_port_sptr = std::shared_ptr<la_l2_port>;
using la_l2_port_scptr = std::shared_ptr<const la_l2_port>;
using la_l2_port_wptr = weak_ptr_unsafe<la_l2_port>;
using la_l2_port_wcptr = weak_ptr_unsafe<const la_l2_port>;

class la_l2_multicast_group;
using la_l2_multicast_group_sptr = std::shared_ptr<la_l2_multicast_group>;
using la_l2_multicast_group_scptr = std::shared_ptr<const la_l2_multicast_group>;
using la_l2_multicast_group_wptr = weak_ptr_unsafe<la_l2_multicast_group>;
using la_l2_multicast_group_wcptr = weak_ptr_unsafe<const la_l2_multicast_group>;

class la_mpls_multicast_group;
using la_mpls_multicast_group_sptr = std::shared_ptr<la_mpls_multicast_group>;
using la_mpls_multicast_group_scptr = std::shared_ptr<const la_mpls_multicast_group>;
using la_mpls_multicast_group_wptr = weak_ptr_unsafe<la_mpls_multicast_group>;
using la_mpls_multicast_group_wcptr = weak_ptr_unsafe<const la_mpls_multicast_group>;

class la_mac_table_iter;
using la_mac_table_iter_sptr = std::shared_ptr<la_mac_table_iter>;
using la_mac_table_iter_scptr = std::shared_ptr<const la_mac_table_iter>;
using la_mac_table_iter_wptr = weak_ptr_unsafe<la_mac_table_iter>;
using la_mac_table_iter_wcptr = weak_ptr_unsafe<const la_mac_table_iter>;

class la_ac_profile;
using la_ac_profile_sptr = std::shared_ptr<la_ac_profile>;
using la_ac_profile_scptr = std::shared_ptr<const la_ac_profile>;
using la_ac_profile_wptr = weak_ptr_unsafe<la_ac_profile>;
using la_ac_profile_wcptr = weak_ptr_unsafe<const la_ac_profile>;

class la_l2_protection_group;
using la_l2_protection_group_sptr = std::shared_ptr<la_l2_protection_group>;
using la_l2_protection_group_scptr = std::shared_ptr<const la_l2_protection_group>;
using la_l2_protection_group_wptr = weak_ptr_unsafe<la_l2_protection_group>;
using la_l2_protection_group_wcptr = weak_ptr_unsafe<const la_l2_protection_group>;

class la_voq_cgm_evicted_profile;
using la_voq_cgm_evicted_profile_sptr = std::shared_ptr<la_voq_cgm_evicted_profile>;
using la_voq_cgm_evicted_profile_scptr = std::shared_ptr<const la_voq_cgm_evicted_profile>;
using la_voq_cgm_evicted_profile_wptr = weak_ptr_unsafe<la_voq_cgm_evicted_profile>;
using la_voq_cgm_evicted_profile_wcptr = weak_ptr_unsafe<const la_voq_cgm_evicted_profile>;

class la_rx_cgm_sq_profile;
using la_rx_cgm_sq_profile_sptr = std::shared_ptr<la_rx_cgm_sq_profile>;
using la_rx_cgm_sq_profile_scptr = std::shared_ptr<const la_rx_cgm_sq_profile>;
using la_rx_cgm_sq_profile_wptr = weak_ptr_unsafe<la_rx_cgm_sq_profile>;
using la_rx_cgm_sq_profile_wcptr = weak_ptr_unsafe<const la_rx_cgm_sq_profile>;

class la_voq_cgm_profile;
using la_voq_cgm_profile_sptr = std::shared_ptr<la_voq_cgm_profile>;
using la_voq_cgm_profile_scptr = std::shared_ptr<const la_voq_cgm_profile>;
using la_voq_cgm_profile_wptr = weak_ptr_unsafe<la_voq_cgm_profile>;
using la_voq_cgm_profile_wcptr = weak_ptr_unsafe<const la_voq_cgm_profile>;

class la_counter_or_meter_set;
using la_counter_or_meter_set_sptr = std::shared_ptr<la_counter_or_meter_set>;
using la_counter_or_meter_set_scptr = std::shared_ptr<const la_counter_or_meter_set>;
using la_counter_or_meter_set_wptr = weak_ptr_unsafe<la_counter_or_meter_set>;
using la_counter_or_meter_set_wcptr = weak_ptr_unsafe<const la_counter_or_meter_set>;

class la_object;
using la_object_sptr = std::shared_ptr<la_object>;
using la_object_scptr = std::shared_ptr<const la_object>;
using la_object_wptr = weak_ptr_unsafe<la_object>;
using la_object_wcptr = weak_ptr_unsafe<const la_object>;

class la_erspan_mirror_command;
using la_erspan_mirror_command_sptr = std::shared_ptr<la_erspan_mirror_command>;
using la_erspan_mirror_command_scptr = std::shared_ptr<const la_erspan_mirror_command>;
using la_erspan_mirror_command_wptr = weak_ptr_unsafe<la_erspan_mirror_command>;
using la_erspan_mirror_command_wcptr = weak_ptr_unsafe<const la_erspan_mirror_command>;

class la_mirror_command;
using la_mirror_command_sptr = std::shared_ptr<la_mirror_command>;
using la_mirror_command_scptr = std::shared_ptr<const la_mirror_command>;
using la_mirror_command_wptr = weak_ptr_unsafe<la_mirror_command>;
using la_mirror_command_wcptr = weak_ptr_unsafe<const la_mirror_command>;

class la_npu_host_port;
using la_npu_host_port_sptr = std::shared_ptr<la_npu_host_port>;
using la_npu_host_port_scptr = std::shared_ptr<const la_npu_host_port>;
using la_npu_host_port_wptr = weak_ptr_unsafe<la_npu_host_port>;
using la_npu_host_port_wcptr = weak_ptr_unsafe<const la_npu_host_port>;

class la_spa_port;
using la_spa_port_sptr = std::shared_ptr<la_spa_port>;
using la_spa_port_scptr = std::shared_ptr<const la_spa_port>;
using la_spa_port_wptr = weak_ptr_unsafe<la_spa_port>;
using la_spa_port_wcptr = weak_ptr_unsafe<const la_spa_port>;

class la_remote_port;
using la_remote_port_sptr = std::shared_ptr<la_remote_port>;
using la_remote_port_scptr = std::shared_ptr<const la_remote_port>;
using la_remote_port_wptr = weak_ptr_unsafe<la_remote_port>;
using la_remote_port_wcptr = weak_ptr_unsafe<const la_remote_port>;

class la_remote_device;
using la_remote_device_sptr = std::shared_ptr<la_remote_device>;
using la_remote_device_scptr = std::shared_ptr<const la_remote_device>;
using la_remote_device_wptr = weak_ptr_unsafe<la_remote_device>;
using la_remote_device_wcptr = weak_ptr_unsafe<const la_remote_device>;

class la_device;
using la_device_sptr = std::shared_ptr<la_device>;
using la_device_scptr = std::shared_ptr<const la_device>;
using la_device_wptr = weak_ptr_unsafe<la_device>;
using la_device_wcptr = weak_ptr_unsafe<const la_device>;

class la_mac_port;
using la_mac_port_sptr = std::shared_ptr<la_mac_port>;
using la_mac_port_scptr = std::shared_ptr<const la_mac_port>;
using la_mac_port_wptr = weak_ptr_unsafe<la_mac_port>;
using la_mac_port_wcptr = weak_ptr_unsafe<const la_mac_port>;

class la_log;
using la_log_sptr = std::shared_ptr<la_log>;
using la_log_scptr = std::shared_ptr<const la_log>;
using la_log_wptr = weak_ptr_unsafe<la_log>;
using la_log_wcptr = weak_ptr_unsafe<const la_log>;

class la_l2_punt_destination;
using la_l2_punt_destination_sptr = std::shared_ptr<la_l2_punt_destination>;
using la_l2_punt_destination_scptr = std::shared_ptr<const la_l2_punt_destination>;
using la_l2_punt_destination_wptr = weak_ptr_unsafe<la_l2_punt_destination>;
using la_l2_punt_destination_wcptr = weak_ptr_unsafe<const la_l2_punt_destination>;

class la_l2_mirror_command;
using la_l2_mirror_command_sptr = std::shared_ptr<la_l2_mirror_command>;
using la_l2_mirror_command_scptr = std::shared_ptr<const la_l2_mirror_command>;
using la_l2_mirror_command_wptr = weak_ptr_unsafe<la_l2_mirror_command>;
using la_l2_mirror_command_wcptr = weak_ptr_unsafe<const la_l2_mirror_command>;

class la_hbm_handler;
using la_hbm_handler_sptr = std::shared_ptr<la_hbm_handler>;
using la_hbm_handler_scptr = std::shared_ptr<const la_hbm_handler>;
using la_hbm_handler_wptr = weak_ptr_unsafe<la_hbm_handler>;
using la_hbm_handler_wcptr = weak_ptr_unsafe<const la_hbm_handler>;

class la_ptp_handler;
using la_ptp_handler_sptr = std::shared_ptr<la_ptp_handler>;
using la_ptp_handler_scptr = std::shared_ptr<const la_ptp_handler>;
using la_ptp_handler_wptr = weak_ptr_unsafe<la_ptp_handler>;
using la_ptp_handler_wcptr = weak_ptr_unsafe<const la_ptp_handler>;

class la_flow_cache_handler;
using la_flow_cache_handler_sptr = std::shared_ptr<la_flow_cache_handler>;
using la_flow_cache_handler_scptr = std::shared_ptr<const la_flow_cache_handler>;
using la_flow_cache_handler_wptr = weak_ptr_unsafe<la_flow_cache_handler>;
using la_flow_cache_handler_wcptr = weak_ptr_unsafe<const la_flow_cache_handler>;

class la_punt_destination;
using la_punt_destination_sptr = std::shared_ptr<la_punt_destination>;
using la_punt_destination_scptr = std::shared_ptr<const la_punt_destination>;
using la_punt_destination_wptr = weak_ptr_unsafe<la_punt_destination>;
using la_punt_destination_wcptr = weak_ptr_unsafe<const la_punt_destination>;

class la_system_port;
using la_system_port_sptr = std::shared_ptr<la_system_port>;
using la_system_port_scptr = std::shared_ptr<const la_system_port>;
using la_system_port_wptr = weak_ptr_unsafe<la_system_port>;
using la_system_port_wcptr = weak_ptr_unsafe<const la_system_port>;

class la_punt_inject_port;
using la_punt_inject_port_sptr = std::shared_ptr<la_punt_inject_port>;
using la_punt_inject_port_scptr = std::shared_ptr<const la_punt_inject_port>;
using la_punt_inject_port_wptr = weak_ptr_unsafe<la_punt_inject_port>;
using la_punt_inject_port_wcptr = weak_ptr_unsafe<const la_punt_inject_port>;

class la_fabric_port;
using la_fabric_port_sptr = std::shared_ptr<la_fabric_port>;
using la_fabric_port_scptr = std::shared_ptr<const la_fabric_port>;
using la_fabric_port_wptr = weak_ptr_unsafe<la_fabric_port>;
using la_fabric_port_wcptr = weak_ptr_unsafe<const la_fabric_port>;

class la_recycle_port;
using la_recycle_port_sptr = std::shared_ptr<la_recycle_port>;
using la_recycle_port_scptr = std::shared_ptr<const la_recycle_port>;
using la_recycle_port_wptr = weak_ptr_unsafe<la_recycle_port>;
using la_recycle_port_wcptr = weak_ptr_unsafe<const la_recycle_port>;

class la_pci_port;
using la_pci_port_sptr = std::shared_ptr<la_pci_port>;
using la_pci_port_scptr = std::shared_ptr<const la_pci_port>;
using la_pci_port_wptr = weak_ptr_unsafe<la_pci_port>;
using la_pci_port_wcptr = weak_ptr_unsafe<const la_pci_port>;

class la_npu_host_destination;
using la_npu_host_destination_sptr = std::shared_ptr<la_npu_host_destination>;
using la_npu_host_destination_scptr = std::shared_ptr<const la_npu_host_destination>;
using la_npu_host_destination_wptr = weak_ptr_unsafe<la_npu_host_destination>;
using la_npu_host_destination_wcptr = weak_ptr_unsafe<const la_npu_host_destination>;

class la_meter_set;
using la_meter_set_sptr = std::shared_ptr<la_meter_set>;
using la_meter_set_scptr = std::shared_ptr<const la_meter_set>;
using la_meter_set_wptr = weak_ptr_unsafe<la_meter_set>;
using la_meter_set_wcptr = weak_ptr_unsafe<const la_meter_set>;

class la_meter_markdown_profile;
using la_meter_markdown_profile_sptr = std::shared_ptr<la_meter_markdown_profile>;
using la_meter_markdown_profile_scptr = std::shared_ptr<const la_meter_markdown_profile>;
using la_meter_markdown_profile_wptr = weak_ptr_unsafe<la_meter_markdown_profile>;
using la_meter_markdown_profile_wcptr = weak_ptr_unsafe<const la_meter_markdown_profile>;

class la_meter_profile;
using la_meter_profile_sptr = std::shared_ptr<la_meter_profile>;
using la_meter_profile_scptr = std::shared_ptr<const la_meter_profile>;
using la_meter_profile_wptr = weak_ptr_unsafe<la_meter_profile>;
using la_meter_profile_wcptr = weak_ptr_unsafe<const la_meter_profile>;

class la_meter_action_profile;
using la_meter_action_profile_sptr = std::shared_ptr<la_meter_action_profile>;
using la_meter_action_profile_scptr = std::shared_ptr<const la_meter_action_profile>;
using la_meter_action_profile_wptr = weak_ptr_unsafe<la_meter_action_profile>;
using la_meter_action_profile_wcptr = weak_ptr_unsafe<const la_meter_action_profile>;

class la_egress_qos_profile;
using la_egress_qos_profile_sptr = std::shared_ptr<la_egress_qos_profile>;
using la_egress_qos_profile_scptr = std::shared_ptr<const la_egress_qos_profile>;
using la_egress_qos_profile_wptr = weak_ptr_unsafe<la_egress_qos_profile>;
using la_egress_qos_profile_wcptr = weak_ptr_unsafe<const la_egress_qos_profile>;

class la_ingress_qos_profile;
using la_ingress_qos_profile_sptr = std::shared_ptr<la_ingress_qos_profile>;
using la_ingress_qos_profile_scptr = std::shared_ptr<const la_ingress_qos_profile>;
using la_ingress_qos_profile_wptr = weak_ptr_unsafe<la_ingress_qos_profile>;
using la_ingress_qos_profile_wcptr = weak_ptr_unsafe<const la_ingress_qos_profile>;

// impl classes

class la_mpls_multicast_group_impl;
using la_mpls_multicast_group_impl_sptr = std::shared_ptr<la_mpls_multicast_group_impl>;
using la_mpls_multicast_group_impl_scptr = std::shared_ptr<const la_mpls_multicast_group_impl>;
using la_mpls_multicast_group_impl_wptr = weak_ptr_unsafe<la_mpls_multicast_group_impl>;
using la_mpls_multicast_group_impl_wcptr = weak_ptr_unsafe<const la_mpls_multicast_group_impl>;

class la_counter_set_impl;
using la_counter_set_impl_sptr = std::shared_ptr<la_counter_set_impl>;
using la_counter_set_impl_scptr = std::shared_ptr<const la_counter_set_impl>;
using la_counter_set_impl_wptr = weak_ptr_unsafe<la_counter_set_impl>;
using la_counter_set_impl_wcptr = weak_ptr_unsafe<const la_counter_set_impl>;

class la_l2_multicast_group_base;
using la_l2_multicast_group_base_sptr = std::shared_ptr<la_l2_multicast_group_base>;
using la_l2_multicast_group_base_scptr = std::shared_ptr<const la_l2_multicast_group_base>;
using la_l2_multicast_group_base_wptr = weak_ptr_unsafe<la_l2_multicast_group_base>;
using la_l2_multicast_group_base_wcptr = weak_ptr_unsafe<const la_l2_multicast_group_base>;

class la_l2_multicast_group_pacific;
using la_l2_multicast_group_pacific_sptr = std::shared_ptr<la_l2_multicast_group_pacific>;
using la_l2_multicast_group_pacific_scptr = std::shared_ptr<const la_l2_multicast_group_pacific>;
using la_l2_multicast_group_pacific_wptr = weak_ptr_unsafe<la_l2_multicast_group_pacific>;
using la_l2_multicast_group_pacific_wcptr = weak_ptr_unsafe<const la_l2_multicast_group_pacific>;

class la_l2_multicast_group_gibraltar;
using la_l2_multicast_group_gibraltar_sptr = std::shared_ptr<la_l2_multicast_group_gibraltar>;
using la_l2_multicast_group_gibraltar_scptr = std::shared_ptr<const la_l2_multicast_group_gibraltar>;
using la_l2_multicast_group_gibraltar_wptr = weak_ptr_unsafe<la_l2_multicast_group_gibraltar>;
using la_l2_multicast_group_gibraltar_wcptr = weak_ptr_unsafe<const la_l2_multicast_group_gibraltar>;

class la_l2_multicast_group_akpg;
using la_l2_multicast_group_akpg_sptr = std::shared_ptr<la_l2_multicast_group_akpg>;
using la_l2_multicast_group_akpg_scptr = std::shared_ptr<const la_l2_multicast_group_akpg>;
using la_l2_multicast_group_akpg_wptr = weak_ptr_unsafe<la_l2_multicast_group_akpg>;
using la_l2_multicast_group_akpg_wcptr = weak_ptr_unsafe<const la_l2_multicast_group_akpg>;

class la_next_hop_base;
using la_next_hop_base_sptr = std::shared_ptr<la_next_hop_base>;
using la_next_hop_base_scptr = std::shared_ptr<const la_next_hop_base>;
using la_next_hop_base_wptr = weak_ptr_unsafe<la_next_hop_base>;
using la_next_hop_base_wcptr = weak_ptr_unsafe<const la_next_hop_base>;

class la_next_hop_pacific;
using la_next_hop_pacific_sptr = std::shared_ptr<la_next_hop_pacific>;
using la_next_hop_pacific_scptr = std::shared_ptr<const la_next_hop_pacific>;
using la_next_hop_pacific_wptr = weak_ptr_unsafe<la_next_hop_pacific>;
using la_next_hop_pacific_wcptr = weak_ptr_unsafe<const la_next_hop_pacific>;

class la_next_hop_gibraltar;
using la_next_hop_gibraltar_sptr = std::shared_ptr<la_next_hop_gibraltar>;
using la_next_hop_gibraltar_scptr = std::shared_ptr<const la_next_hop_gibraltar>;
using la_next_hop_gibraltar_wptr = weak_ptr_unsafe<la_next_hop_gibraltar>;
using la_next_hop_gibraltar_wcptr = weak_ptr_unsafe<const la_next_hop_gibraltar>;

class la_next_hop_akpg;
using la_next_hop_akpg_sptr = std::shared_ptr<la_next_hop_akpg>;
using la_next_hop_akpg_scptr = std::shared_ptr<const la_next_hop_akpg>;
using la_next_hop_akpg_wptr = weak_ptr_unsafe<la_next_hop_akpg>;
using la_next_hop_akpg_wcptr = weak_ptr_unsafe<const la_next_hop_akpg>;

class la_vxlan_next_hop_base;
using la_vxlan_next_hop_base_sptr = std::shared_ptr<la_vxlan_next_hop_base>;
using la_vxlan_next_hop_base_scptr = std::shared_ptr<const la_vxlan_next_hop_base>;
using la_vxlan_next_hop_base_wptr = weak_ptr_unsafe<la_vxlan_next_hop_base>;
using la_vxlan_next_hop_base_wcptr = weak_ptr_unsafe<const la_vxlan_next_hop_base>;

class la_vxlan_next_hop_pacific;
using la_vxlan_next_hop_pacific_sptr = std::shared_ptr<la_vxlan_next_hop_pacific>;
using la_vxlan_next_hop_pacific_scptr = std::shared_ptr<const la_vxlan_next_hop_pacific>;
using la_vxlan_next_hop_pacific_wptr = weak_ptr_unsafe<la_vxlan_next_hop_pacific>;
using la_vxlan_next_hop_pacific_wcptr = weak_ptr_unsafe<const la_vxlan_next_hop_pacific>;

class la_vxlan_next_hop_gibraltar;
using la_vxlan_next_hop_gibraltar_sptr = std::shared_ptr<la_vxlan_next_hop_gibraltar>;
using la_vxlan_next_hop_gibraltar_scptr = std::shared_ptr<const la_vxlan_next_hop_gibraltar>;
using la_vxlan_next_hop_gibraltar_wptr = weak_ptr_unsafe<la_vxlan_next_hop_gibraltar>;
using la_vxlan_next_hop_gibraltar_wcptr = weak_ptr_unsafe<const la_vxlan_next_hop_gibraltar>;

class la_vxlan_next_hop_akpg;
using la_vxlan_next_hop_akpg_sptr = std::shared_ptr<la_vxlan_next_hop_akpg>;
using la_vxlan_next_hop_akpg_scptr = std::shared_ptr<const la_vxlan_next_hop_akpg>;
using la_vxlan_next_hop_akpg_wptr = weak_ptr_unsafe<la_vxlan_next_hop_akpg>;
using la_vxlan_next_hop_akpg_wcptr = weak_ptr_unsafe<const la_vxlan_next_hop_akpg>;

class la_mpls_vpn_encap_impl;
using la_mpls_vpn_encap_impl_sptr = std::shared_ptr<la_mpls_vpn_encap_impl>;
using la_mpls_vpn_encap_impl_scptr = std::shared_ptr<const la_mpls_vpn_encap_impl>;
using la_mpls_vpn_encap_impl_wptr = weak_ptr_unsafe<la_mpls_vpn_encap_impl>;
using la_mpls_vpn_encap_impl_wcptr = weak_ptr_unsafe<const la_mpls_vpn_encap_impl>;

class la_ip_multicast_group_impl;
using la_ip_multicast_group_impl_sptr = std::shared_ptr<la_ip_multicast_group_impl>;
using la_ip_multicast_group_impl_scptr = std::shared_ptr<const la_ip_multicast_group_impl>;
using la_ip_multicast_group_impl_wptr = weak_ptr_unsafe<la_ip_multicast_group_impl>;
using la_ip_multicast_group_impl_wcptr = weak_ptr_unsafe<const la_ip_multicast_group_impl>;

class la_ip_multicast_group_base;
using la_ip_multicast_group_base_sptr = std::shared_ptr<la_ip_multicast_group_base>;
using la_ip_multicast_group_base_scptr = std::shared_ptr<const la_ip_multicast_group_base>;
using la_ip_multicast_group_base_wptr = weak_ptr_unsafe<la_ip_multicast_group_base>;
using la_ip_multicast_group_base_wcptr = weak_ptr_unsafe<const la_ip_multicast_group_base>;

class la_ip_multicast_group_pacific;
using la_ip_multicast_group_pacific_sptr = std::shared_ptr<la_ip_multicast_group_pacific>;
using la_ip_multicast_group_pacific_scptr = std::shared_ptr<const la_ip_multicast_group_pacific>;
using la_ip_multicast_group_pacific_wptr = weak_ptr_unsafe<la_ip_multicast_group_pacific>;
using la_ip_multicast_group_pacific_wcptr = weak_ptr_unsafe<const la_ip_multicast_group_pacific>;

class la_ip_multicast_group_gibraltar;
using la_ip_multicast_group_gibraltar_sptr = std::shared_ptr<la_ip_multicast_group_gibraltar>;
using la_ip_multicast_group_gibraltar_scptr = std::shared_ptr<const la_ip_multicast_group_gibraltar>;
using la_ip_multicast_group_gibraltar_wptr = weak_ptr_unsafe<la_ip_multicast_group_gibraltar>;
using la_ip_multicast_group_gibraltar_wcptr = weak_ptr_unsafe<const la_ip_multicast_group_gibraltar>;

class la_ip_multicast_group_akpg;
using la_ip_multicast_group_akpg_sptr = std::shared_ptr<la_ip_multicast_group_akpg>;
using la_ip_multicast_group_akpg_scptr = std::shared_ptr<const la_ip_multicast_group_akpg>;
using la_ip_multicast_group_akpg_wptr = weak_ptr_unsafe<la_ip_multicast_group_akpg>;
using la_ip_multicast_group_akpg_wcptr = weak_ptr_unsafe<const la_ip_multicast_group_akpg>;

class la_ecmp_group_impl;
using la_ecmp_group_impl_sptr = std::shared_ptr<la_ecmp_group_impl>;
using la_ecmp_group_impl_scptr = std::shared_ptr<const la_ecmp_group_impl>;
using la_ecmp_group_impl_wptr = weak_ptr_unsafe<la_ecmp_group_impl>;
using la_ecmp_group_impl_wcptr = weak_ptr_unsafe<const la_ecmp_group_impl>;

class la_gre_port_impl;
using la_gre_port_impl_sptr = std::shared_ptr<la_gre_port_impl>;
using la_gre_port_impl_scptr = std::shared_ptr<const la_gre_port_impl>;
using la_gre_port_impl_wptr = weak_ptr_unsafe<la_gre_port_impl>;
using la_gre_port_impl_wcptr = weak_ptr_unsafe<const la_gre_port_impl>;

class la_gue_port_impl;
using la_gue_port_impl_sptr = std::shared_ptr<la_gue_port_impl>;
using la_gue_port_impl_scptr = std::shared_ptr<const la_gue_port_impl>;
using la_gue_port_impl_wptr = weak_ptr_unsafe<la_gue_port_impl>;
using la_gue_port_impl_wcptr = weak_ptr_unsafe<const la_gue_port_impl>;

class la_rate_limiter_set_base;
using la_rate_limiter_set_base_sptr = std::shared_ptr<la_rate_limiter_set_base>;
using la_rate_limiter_set_base_scptr = std::shared_ptr<const la_rate_limiter_set_base>;
using la_rate_limiter_set_base_wptr = weak_ptr_unsafe<la_rate_limiter_set_base>;
using la_rate_limiter_set_base_wcptr = weak_ptr_unsafe<const la_rate_limiter_set_base>;

class la_rate_limiter_set_pacific;
using la_rate_limiter_set_pacific_sptr = std::shared_ptr<la_rate_limiter_set_pacific>;
using la_rate_limiter_set_pacific_scptr = std::shared_ptr<const la_rate_limiter_set_pacific>;
using la_rate_limiter_set_pacific_wptr = weak_ptr_unsafe<la_rate_limiter_set_pacific>;
using la_rate_limiter_set_pacific_wcptr = weak_ptr_unsafe<const la_rate_limiter_set_pacific>;

class la_rate_limiter_set_gibraltar;
using la_rate_limiter_set_gibraltar_sptr = std::shared_ptr<la_rate_limiter_set_gibraltar>;
using la_rate_limiter_set_gibraltar_scptr = std::shared_ptr<const la_rate_limiter_set_gibraltar>;
using la_rate_limiter_set_gibraltar_wptr = weak_ptr_unsafe<la_rate_limiter_set_gibraltar>;
using la_rate_limiter_set_gibraltar_wcptr = weak_ptr_unsafe<const la_rate_limiter_set_gibraltar>;

class la_rate_limiter_set_asic5;
using la_rate_limiter_set_asic5_sptr = std::shared_ptr<la_rate_limiter_set_asic5>;
using la_rate_limiter_set_asic5_scptr = std::shared_ptr<const la_rate_limiter_set_asic5>;
using la_rate_limiter_set_asic5_wptr = weak_ptr_unsafe<la_rate_limiter_set_asic5>;
using la_rate_limiter_set_asic5_wcptr = weak_ptr_unsafe<const la_rate_limiter_set_asic5>;

class la_rate_limiter_set_asic6;
using la_rate_limiter_set_asic6_sptr = std::shared_ptr<la_rate_limiter_set_asic6>;
using la_rate_limiter_set_asic6_scptr = std::shared_ptr<const la_rate_limiter_set_asic6>;
using la_rate_limiter_set_asic6_wptr = weak_ptr_unsafe<la_rate_limiter_set_asic6>;
using la_rate_limiter_set_asic6_wcptr = weak_ptr_unsafe<const la_rate_limiter_set_asic6>;

class la_rate_limiter_set_asic4;
using la_rate_limiter_set_asic4_sptr = std::shared_ptr<la_rate_limiter_set_asic4>;
using la_rate_limiter_set_asic4_scptr = std::shared_ptr<const la_rate_limiter_set_asic4>;
using la_rate_limiter_set_asic4_wptr = weak_ptr_unsafe<la_rate_limiter_set_asic4>;
using la_rate_limiter_set_asic4_wcptr = weak_ptr_unsafe<const la_rate_limiter_set_asic4>;

class la_rate_limiter_set_asic3;
using la_rate_limiter_set_asic3_sptr = std::shared_ptr<la_rate_limiter_set_asic3>;
using la_rate_limiter_set_asic3_scptr = std::shared_ptr<const la_rate_limiter_set_asic3>;
using la_rate_limiter_set_asic3_wptr = weak_ptr_unsafe<la_rate_limiter_set_asic3>;
using la_rate_limiter_set_asic3_wcptr = weak_ptr_unsafe<const la_rate_limiter_set_asic3>;

class la_l2_protection_group_base;
using la_l2_protection_group_base_sptr = std::shared_ptr<la_l2_protection_group_base>;
using la_l2_protection_group_base_scptr = std::shared_ptr<const la_l2_protection_group_base>;
using la_l2_protection_group_base_wptr = weak_ptr_unsafe<la_l2_protection_group_base>;
using la_l2_protection_group_base_wcptr = weak_ptr_unsafe<const la_l2_protection_group_base>;

class la_l2_protection_group_pacific;
using la_l2_protection_group_pacific_sptr = std::shared_ptr<la_l2_protection_group_pacific>;
using la_l2_protection_group_pacific_scptr = std::shared_ptr<const la_l2_protection_group_pacific>;
using la_l2_protection_group_pacific_wptr = weak_ptr_unsafe<la_l2_protection_group_pacific>;
using la_l2_protection_group_pacific_wcptr = weak_ptr_unsafe<const la_l2_protection_group_pacific>;

class la_l2_protection_group_gibraltar;
using la_l2_protection_group_gibraltar_sptr = std::shared_ptr<la_l2_protection_group_gibraltar>;
using la_l2_protection_group_gibraltar_scptr = std::shared_ptr<const la_l2_protection_group_gibraltar>;
using la_l2_protection_group_gibraltar_wptr = weak_ptr_unsafe<la_l2_protection_group_gibraltar>;
using la_l2_protection_group_gibraltar_wcptr = weak_ptr_unsafe<const la_l2_protection_group_gibraltar>;

class la_l2_protection_group_akpg;
using la_l2_protection_group_akpg_sptr = std::shared_ptr<la_l2_protection_group_akpg>;
using la_l2_protection_group_akpg_scptr = std::shared_ptr<const la_l2_protection_group_akpg>;
using la_l2_protection_group_akpg_wptr = weak_ptr_unsafe<la_l2_protection_group_akpg>;
using la_l2_protection_group_akpg_wcptr = weak_ptr_unsafe<const la_l2_protection_group_akpg>;

class la_l2_protection_group_akpg;
using la_l2_protection_group_akpg_sptr = std::shared_ptr<la_l2_protection_group_akpg>;
using la_l2_protection_group_akpg_scptr = std::shared_ptr<const la_l2_protection_group_akpg>;
using la_l2_protection_group_akpg_wptr = weak_ptr_unsafe<la_l2_protection_group_akpg>;
using la_l2_protection_group_akpg_wcptr = weak_ptr_unsafe<const la_l2_protection_group_akpg>;

class la_l3_fec_impl;
using la_l3_fec_impl_sptr = std::shared_ptr<la_l3_fec_impl>;
using la_l3_fec_impl_scptr = std::shared_ptr<const la_l3_fec_impl>;
using la_l3_fec_impl_wptr = weak_ptr_unsafe<la_l3_fec_impl>;
using la_l3_fec_impl_wcptr = weak_ptr_unsafe<const la_l3_fec_impl>;

class la_te_tunnel_impl;
using la_te_tunnel_impl_sptr = std::shared_ptr<la_te_tunnel_impl>;
using la_te_tunnel_impl_scptr = std::shared_ptr<const la_te_tunnel_impl>;
using la_te_tunnel_impl_wptr = weak_ptr_unsafe<la_te_tunnel_impl>;
using la_te_tunnel_impl_wcptr = weak_ptr_unsafe<const la_te_tunnel_impl>;

class la_ip_over_ip_tunnel_port_impl;
using la_ip_over_ip_tunnel_port_impl_sptr = std::shared_ptr<la_ip_over_ip_tunnel_port_impl>;
using la_ip_over_ip_tunnel_port_impl_scptr = std::shared_ptr<const la_ip_over_ip_tunnel_port_impl>;
using la_ip_over_ip_tunnel_port_impl_wptr = weak_ptr_unsafe<la_ip_over_ip_tunnel_port_impl>;
using la_ip_over_ip_tunnel_port_impl_wcptr = weak_ptr_unsafe<const la_ip_over_ip_tunnel_port_impl>;

class la_protection_monitor_impl;
using la_protection_monitor_impl_sptr = std::shared_ptr<la_protection_monitor_impl>;
using la_protection_monitor_impl_scptr = std::shared_ptr<const la_protection_monitor_impl>;
using la_protection_monitor_impl_wptr = weak_ptr_unsafe<la_protection_monitor_impl>;
using la_protection_monitor_impl_wcptr = weak_ptr_unsafe<const la_protection_monitor_impl>;

class la_l2_service_port_base;
using la_l2_service_port_base_sptr = std::shared_ptr<la_l2_service_port_base>;
using la_l2_service_port_base_scptr = std::shared_ptr<const la_l2_service_port_base>;
using la_l2_service_port_base_wptr = weak_ptr_unsafe<la_l2_service_port_base>;
using la_l2_service_port_base_wcptr = weak_ptr_unsafe<const la_l2_service_port_base>;

class la_l2_service_port_pacific;
using la_l2_service_port_pacific_sptr = std::shared_ptr<la_l2_service_port_pacific>;
using la_l2_service_port_pacific_scptr = std::shared_ptr<const la_l2_service_port_pacific>;
using la_l2_service_port_pacific_wptr = weak_ptr_unsafe<la_l2_service_port_pacific>;
using la_l2_service_port_pacific_wcptr = weak_ptr_unsafe<const la_l2_service_port_pacific>;

class la_l2_service_port_gibraltar;
using la_l2_service_port_gibraltar_sptr = std::shared_ptr<la_l2_service_port_gibraltar>;
using la_l2_service_port_gibraltar_scptr = std::shared_ptr<const la_l2_service_port_gibraltar>;
using la_l2_service_port_gibraltar_wptr = weak_ptr_unsafe<la_l2_service_port_gibraltar>;
using la_l2_service_port_gibraltar_wcptr = weak_ptr_unsafe<const la_l2_service_port_gibraltar>;

class la_l2_service_port_asic4;
using la_l2_service_port_asic4_sptr = std::shared_ptr<la_l2_service_port_asic4>;
using la_l2_service_port_asic4_scptr = std::shared_ptr<const la_l2_service_port_asic4>;
using la_l2_service_port_asic4_wptr = weak_ptr_unsafe<la_l2_service_port_asic4>;
using la_l2_service_port_asic4_wcptr = weak_ptr_unsafe<const la_l2_service_port_asic4>;

class la_l2_service_port_akpg;
using la_l2_service_port_akpg_sptr = std::shared_ptr<la_l2_service_port_akpg>;
using la_l2_service_port_akpg_scptr = std::shared_ptr<const la_l2_service_port_akpg>;
using la_l2_service_port_akpg_wptr = weak_ptr_unsafe<la_l2_service_port_akpg>;
using la_l2_service_port_akpg_wcptr = weak_ptr_unsafe<const la_l2_service_port_akpg>;

class la_prefix_object_base;
using la_prefix_object_base_sptr = std::shared_ptr<la_prefix_object_base>;
using la_prefix_object_base_scptr = std::shared_ptr<const la_prefix_object_base>;
using la_prefix_object_base_wptr = weak_ptr_unsafe<la_prefix_object_base>;
using la_prefix_object_base_wcptr = weak_ptr_unsafe<const la_prefix_object_base>;

class la_prefix_object_pacific;
using la_prefix_object_pacific_sptr = std::shared_ptr<la_prefix_object_pacific>;
using la_prefix_object_pacific_scptr = std::shared_ptr<const la_prefix_object_pacific>;
using la_prefix_object_pacific_wptr = weak_ptr_unsafe<la_prefix_object_pacific>;
using la_prefix_object_pacific_wcptr = weak_ptr_unsafe<const la_prefix_object_pacific>;

class la_prefix_object_gibraltar;
using la_prefix_object_gibraltar_sptr = std::shared_ptr<la_prefix_object_gibraltar>;
using la_prefix_object_gibraltar_scptr = std::shared_ptr<const la_prefix_object_gibraltar>;
using la_prefix_object_gibraltar_wptr = weak_ptr_unsafe<la_prefix_object_gibraltar>;
using la_prefix_object_gibraltar_wcptr = weak_ptr_unsafe<const la_prefix_object_gibraltar>;

class la_prefix_object_akpg;
using la_prefix_object_akpg_sptr = std::shared_ptr<la_prefix_object_akpg>;
using la_prefix_object_akpg_scptr = std::shared_ptr<const la_prefix_object_akpg>;
using la_prefix_object_akpg_wptr = weak_ptr_unsafe<la_prefix_object_akpg>;
using la_prefix_object_akpg_wcptr = weak_ptr_unsafe<const la_prefix_object_akpg>;

class la_destination_pe_impl;
using la_destination_pe_impl_sptr = std::shared_ptr<la_destination_pe_impl>;
using la_destination_pe_impl_scptr = std::shared_ptr<const la_destination_pe_impl>;
using la_destination_pe_impl_wptr = weak_ptr_unsafe<la_destination_pe_impl>;
using la_destination_pe_impl_wcptr = weak_ptr_unsafe<const la_destination_pe_impl>;

class la_l3_ac_port_impl;
using la_l3_ac_port_impl_sptr = std::shared_ptr<la_l3_ac_port_impl>;
using la_l3_ac_port_impl_scptr = std::shared_ptr<const la_l3_ac_port_impl>;
using la_l3_ac_port_impl_wptr = weak_ptr_unsafe<la_l3_ac_port_impl>;
using la_l3_ac_port_impl_wcptr = weak_ptr_unsafe<const la_l3_ac_port_impl>;

class la_multicast_protection_monitor_base;
using la_multicast_protection_monitor_base_sptr = std::shared_ptr<la_multicast_protection_monitor_base>;
using la_multicast_protection_monitor_base_scptr = std::shared_ptr<const la_multicast_protection_monitor_base>;
using la_multicast_protection_monitor_base_wptr = weak_ptr_unsafe<la_multicast_protection_monitor_base>;
using la_multicast_protection_monitor_base_wcptr = weak_ptr_unsafe<const la_multicast_protection_monitor_base>;

class la_multicast_protection_group_base;
using la_multicast_protection_group_base_sptr = std::shared_ptr<la_multicast_protection_group_base>;
using la_multicast_protection_group_base_scptr = std::shared_ptr<const la_multicast_protection_group_base>;
using la_multicast_protection_group_base_wptr = weak_ptr_unsafe<la_multicast_protection_group_base>;
using la_multicast_protection_group_base_wcptr = weak_ptr_unsafe<const la_multicast_protection_group_base>;

class la_mpls_nhlfe_impl;
using la_mpls_nhlfe_impl_sptr = std::shared_ptr<la_mpls_nhlfe_impl>;
using la_mpls_nhlfe_impl_scptr = std::shared_ptr<const la_mpls_nhlfe_impl>;
using la_mpls_nhlfe_impl_wptr = weak_ptr_unsafe<la_mpls_nhlfe_impl>;
using la_mpls_nhlfe_impl_wcptr = weak_ptr_unsafe<const la_mpls_nhlfe_impl>;

class la_acl_impl;
using la_acl_impl_sptr = std::shared_ptr<la_acl_impl>;
using la_acl_impl_scptr = std::shared_ptr<const la_acl_impl>;
using la_acl_impl_wptr = weak_ptr_unsafe<la_acl_impl>;
using la_acl_impl_wcptr = weak_ptr_unsafe<const la_acl_impl>;

class la_pcl_impl;
using la_pcl_impl_sptr = std::shared_ptr<la_pcl_impl>;
using la_pcl_impl_scptr = std::shared_ptr<const la_pcl_impl>;
using la_pcl_impl_wptr = weak_ptr_unsafe<la_pcl_impl>;
using la_pcl_impl_wcptr = weak_ptr_unsafe<const la_pcl_impl>;

class la_mpls_label_destination_impl;
using la_mpls_label_destination_impl_sptr = std::shared_ptr<la_mpls_label_destination_impl>;
using la_mpls_label_destination_impl_scptr = std::shared_ptr<const la_mpls_label_destination_impl>;
using la_mpls_label_destination_impl_wptr = weak_ptr_unsafe<la_mpls_label_destination_impl>;
using la_mpls_label_destination_impl_wcptr = weak_ptr_unsafe<const la_mpls_label_destination_impl>;

class la_ip_tunnel_destination_impl;
using la_ip_tunnel_destination_impl_sptr = std::shared_ptr<la_ip_tunnel_destination_impl>;
using la_ip_tunnel_destination_impl_scptr = std::shared_ptr<const la_ip_tunnel_destination_impl>;
using la_ip_tunnel_destination_impl_wptr = weak_ptr_unsafe<la_ip_tunnel_destination_impl>;
using la_ip_tunnel_destination_impl_wcptr = weak_ptr_unsafe<const la_ip_tunnel_destination_impl>;

class la_switch_impl;
using la_switch_impl_sptr = std::shared_ptr<la_switch_impl>;
using la_switch_impl_scptr = std::shared_ptr<const la_switch_impl>;
using la_switch_impl_wptr = weak_ptr_unsafe<la_switch_impl>;
using la_switch_impl_wcptr = weak_ptr_unsafe<const la_switch_impl>;

class la_ac_profile_impl;
using la_ac_profile_impl_sptr = std::shared_ptr<la_ac_profile_impl>;
using la_ac_profile_impl_scptr = std::shared_ptr<const la_ac_profile_impl>;
using la_ac_profile_impl_wptr = weak_ptr_unsafe<la_ac_profile_impl>;
using la_ac_profile_impl_wcptr = weak_ptr_unsafe<const la_ac_profile_impl>;

class la_asbr_lsp_impl;
using la_asbr_lsp_impl_sptr = std::shared_ptr<la_asbr_lsp_impl>;
using la_asbr_lsp_impl_scptr = std::shared_ptr<const la_asbr_lsp_impl>;
using la_asbr_lsp_impl_wptr = weak_ptr_unsafe<la_asbr_lsp_impl>;
using la_asbr_lsp_impl_wcptr = weak_ptr_unsafe<const la_asbr_lsp_impl>;

class la_forus_destination_impl;
using la_forus_destination_impl_sptr = std::shared_ptr<la_forus_destination_impl>;
using la_forus_destination_impl_scptr = std::shared_ptr<const la_forus_destination_impl>;
using la_forus_destination_impl_wptr = weak_ptr_unsafe<la_forus_destination_impl>;
using la_forus_destination_impl_wcptr = weak_ptr_unsafe<const la_forus_destination_impl>;

class la_lsr_impl;
using la_lsr_impl_sptr = std::shared_ptr<la_lsr_impl>;
using la_lsr_impl_scptr = std::shared_ptr<const la_lsr_impl>;
using la_lsr_impl_wptr = weak_ptr_unsafe<la_lsr_impl>;
using la_lsr_impl_wcptr = weak_ptr_unsafe<const la_lsr_impl>;

class la_ethernet_port_base;
using la_ethernet_port_base_sptr = std::shared_ptr<la_ethernet_port_base>;
using la_ethernet_port_base_scptr = std::shared_ptr<const la_ethernet_port_base>;
using la_ethernet_port_base_wptr = weak_ptr_unsafe<la_ethernet_port_base>;
using la_ethernet_port_base_wcptr = weak_ptr_unsafe<const la_ethernet_port_base>;

class la_ethernet_port_pacific;
using la_ethernet_port_pacific_sptr = std::shared_ptr<la_ethernet_port_pacific>;
using la_ethernet_port_pacific_scptr = std::shared_ptr<const la_ethernet_port_pacific>;
using la_ethernet_port_pacific_wptr = weak_ptr_unsafe<la_ethernet_port_pacific>;
using la_ethernet_port_pacific_wcptr = weak_ptr_unsafe<const la_ethernet_port_pacific>;

class la_ethernet_port_gibraltar;
using la_ethernet_port_gibraltar_sptr = std::shared_ptr<la_ethernet_port_gibraltar>;
using la_ethernet_port_gibraltar_scptr = std::shared_ptr<const la_ethernet_port_gibraltar>;
using la_ethernet_port_gibraltar_wptr = weak_ptr_unsafe<la_ethernet_port_gibraltar>;
using la_ethernet_port_gibraltar_wcptr = weak_ptr_unsafe<const la_ethernet_port_gibraltar>;

class la_ethernet_port_akpg;
using la_ethernet_port_akpg_sptr = std::shared_ptr<la_ethernet_port_akpg>;
using la_ethernet_port_akpg_scptr = std::shared_ptr<const la_ethernet_port_akpg>;
using la_ethernet_port_akpg_wptr = weak_ptr_unsafe<la_ethernet_port_akpg>;
using la_ethernet_port_akpg_wcptr = weak_ptr_unsafe<const la_ethernet_port_akpg>;

class la_l3_protection_group_impl;
using la_l3_protection_group_impl_sptr = std::shared_ptr<la_l3_protection_group_impl>;
using la_l3_protection_group_impl_scptr = std::shared_ptr<const la_l3_protection_group_impl>;
using la_l3_protection_group_impl_wptr = weak_ptr_unsafe<la_l3_protection_group_impl>;
using la_l3_protection_group_impl_wcptr = weak_ptr_unsafe<const la_l3_protection_group_impl>;

class la_acl_egress_sec_ipv6;
using la_acl_egress_sec_ipv6_sptr = std::shared_ptr<la_acl_egress_sec_ipv6>;
using la_acl_egress_sec_ipv6_scptr = std::shared_ptr<const la_acl_egress_sec_ipv6>;
using la_acl_egress_sec_ipv6_wptr = weak_ptr_unsafe<la_acl_egress_sec_ipv6>;
using la_acl_egress_sec_ipv6_wcptr = weak_ptr_unsafe<const la_acl_egress_sec_ipv6>;

class la_mpls_vpn_decap_impl;
using la_mpls_vpn_decap_impl_sptr = std::shared_ptr<la_mpls_vpn_decap_impl>;
using la_mpls_vpn_decap_impl_scptr = std::shared_ptr<const la_mpls_vpn_decap_impl>;
using la_mpls_vpn_decap_impl_wptr = weak_ptr_unsafe<la_mpls_vpn_decap_impl>;
using la_mpls_vpn_decap_impl_wcptr = weak_ptr_unsafe<const la_mpls_vpn_decap_impl>;

class la_mldp_vpn_decap_impl;
using la_mldp_vpn_decap_impl_sptr = std::shared_ptr<la_mldp_vpn_decap_impl>;
using la_mldp_vpn_decap_impl_scptr = std::shared_ptr<const la_mldp_vpn_decap_impl>;
using la_mldp_vpn_decap_impl_wptr = weak_ptr_unsafe<la_mldp_vpn_decap_impl>;
using la_mldp_vpn_decap_impl_wcptr = weak_ptr_unsafe<const la_mldp_vpn_decap_impl>;

class la_fabric_multicast_group_impl;
using la_fabric_multicast_group_impl_sptr = std::shared_ptr<la_fabric_multicast_group_impl>;
using la_fabric_multicast_group_impl_scptr = std::shared_ptr<const la_fabric_multicast_group_impl>;
using la_fabric_multicast_group_impl_wptr = weak_ptr_unsafe<la_fabric_multicast_group_impl>;
using la_fabric_multicast_group_impl_wcptr = weak_ptr_unsafe<const la_fabric_multicast_group_impl>;

class la_acl_egress_sec_mac_default;
using la_acl_egress_sec_mac_default_sptr = std::shared_ptr<la_acl_egress_sec_mac_default>;
using la_acl_egress_sec_mac_default_scptr = std::shared_ptr<const la_acl_egress_sec_mac_default>;
using la_acl_egress_sec_mac_default_wptr = weak_ptr_unsafe<la_acl_egress_sec_mac_default>;
using la_acl_egress_sec_mac_default_wcptr = weak_ptr_unsafe<const la_acl_egress_sec_mac_default>;

class la_svi_port_base;
using la_svi_port_base_sptr = std::shared_ptr<la_svi_port_base>;
using la_svi_port_base_scptr = std::shared_ptr<const la_svi_port_base>;
using la_svi_port_base_wptr = weak_ptr_unsafe<la_svi_port_base>;
using la_svi_port_base_wcptr = weak_ptr_unsafe<const la_svi_port_base>;

class la_svi_port_pacific;
using la_svi_port_pacific_sptr = std::shared_ptr<la_svi_port_pacific>;
using la_svi_port_pacific_scptr = std::shared_ptr<const la_svi_port_pacific>;
using la_svi_port_pacific_wptr = weak_ptr_unsafe<la_svi_port_pacific>;
using la_svi_port_pacific_wcptr = weak_ptr_unsafe<const la_svi_port_pacific>;

class la_svi_port_gibraltar;
using la_svi_port_gibraltar_sptr = std::shared_ptr<la_svi_port_gibraltar>;
using la_svi_port_gibraltar_scptr = std::shared_ptr<const la_svi_port_gibraltar>;
using la_svi_port_gibraltar_wptr = weak_ptr_unsafe<la_svi_port_gibraltar>;
using la_svi_port_gibraltar_wcptr = weak_ptr_unsafe<const la_svi_port_gibraltar>;

class la_svi_port_akpg;
using la_svi_port_akpg_sptr = std::shared_ptr<la_svi_port_akpg>;
using la_svi_port_akpg_scptr = std::shared_ptr<const la_svi_port_akpg>;
using la_svi_port_akpg_wptr = weak_ptr_unsafe<la_svi_port_akpg>;
using la_svi_port_akpg_wcptr = weak_ptr_unsafe<const la_svi_port_akpg>;

class la_acl_delegate;
using la_acl_delegate_sptr = std::shared_ptr<la_acl_delegate>;
using la_acl_delegate_scptr = std::shared_ptr<const la_acl_delegate>;
using la_acl_delegate_wptr = weak_ptr_unsafe<la_acl_delegate>;
using la_acl_delegate_wcptr = weak_ptr_unsafe<const la_acl_delegate>;

class la_bfd_session_base;
using la_bfd_session_base_sptr = std::shared_ptr<la_bfd_session_base>;
using la_bfd_session_base_scptr = std::shared_ptr<const la_bfd_session_base>;
using la_bfd_session_base_wptr = weak_ptr_unsafe<la_bfd_session_base>;
using la_bfd_session_base_wcptr = weak_ptr_unsafe<const la_bfd_session_base>;

class la_bfd_session_pacific;
using la_bfd_session_pacific_sptr = std::shared_ptr<la_bfd_session_pacific>;
using la_bfd_session_pacific_scptr = std::shared_ptr<const la_bfd_session_pacific>;
using la_bfd_session_pacific_wptr = weak_ptr_unsafe<la_bfd_session_pacific>;
using la_bfd_session_pacific_wcptr = weak_ptr_unsafe<const la_bfd_session_pacific>;

class la_bfd_session_gibraltar;
using la_bfd_session_gibraltar_sptr = std::shared_ptr<la_bfd_session_gibraltar>;
using la_bfd_session_gibraltar_scptr = std::shared_ptr<const la_bfd_session_gibraltar>;
using la_bfd_session_gibraltar_wptr = weak_ptr_unsafe<la_bfd_session_gibraltar>;
using la_bfd_session_gibraltar_wcptr = weak_ptr_unsafe<const la_bfd_session_gibraltar>;

class la_vrf_impl;
using la_vrf_impl_sptr = std::shared_ptr<la_vrf_impl>;
using la_vrf_impl_scptr = std::shared_ptr<const la_vrf_impl>;
using la_vrf_impl_wptr = weak_ptr_unsafe<la_vrf_impl>;
using la_vrf_impl_wcptr = weak_ptr_unsafe<const la_vrf_impl>;

class la_acl_scaled_impl;
using la_acl_scaled_impl_sptr = std::shared_ptr<la_acl_scaled_impl>;
using la_acl_scaled_impl_scptr = std::shared_ptr<const la_acl_scaled_impl>;
using la_acl_scaled_impl_wptr = weak_ptr_unsafe<la_acl_scaled_impl>;
using la_acl_scaled_impl_wcptr = weak_ptr_unsafe<const la_acl_scaled_impl>;

class la_acl_egress_sec_ipv4;
using la_acl_egress_sec_ipv4_sptr = std::shared_ptr<la_acl_egress_sec_ipv4>;
using la_acl_egress_sec_ipv4_scptr = std::shared_ptr<const la_acl_egress_sec_ipv4>;
using la_acl_egress_sec_ipv4_wptr = weak_ptr_unsafe<la_acl_egress_sec_ipv4>;
using la_acl_egress_sec_ipv4_wcptr = weak_ptr_unsafe<const la_acl_egress_sec_ipv4>;

class la_acl_scaled_delegate;
using la_acl_scaled_delegate_sptr = std::shared_ptr<la_acl_scaled_delegate>;
using la_acl_scaled_delegate_scptr = std::shared_ptr<const la_acl_scaled_delegate>;
using la_acl_scaled_delegate_wptr = weak_ptr_unsafe<la_acl_scaled_delegate>;
using la_acl_scaled_delegate_wcptr = weak_ptr_unsafe<const la_acl_scaled_delegate>;

class la_filter_group_impl;
using la_filter_group_impl_sptr = std::shared_ptr<la_filter_group_impl>;
using la_filter_group_impl_scptr = std::shared_ptr<const la_filter_group_impl>;
using la_filter_group_impl_wptr = weak_ptr_unsafe<la_filter_group_impl>;
using la_filter_group_impl_wcptr = weak_ptr_unsafe<const la_filter_group_impl>;

class la_lpts_impl;
using la_lpts_impl_sptr = std::shared_ptr<la_lpts_impl>;
using la_lpts_impl_scptr = std::shared_ptr<const la_lpts_impl>;
using la_lpts_impl_wptr = weak_ptr_unsafe<la_lpts_impl>;
using la_lpts_impl_wcptr = weak_ptr_unsafe<const la_lpts_impl>;

class la_og_lpts_application_impl;
using la_og_lpts_application_impl_sptr = std::shared_ptr<la_og_lpts_application_impl>;
using la_og_lpts_application_impl_scptr = std::shared_ptr<const la_og_lpts_application_impl>;
using la_og_lpts_application_impl_wptr = weak_ptr_unsafe<la_og_lpts_application_impl>;
using la_og_lpts_application_impl_wcptr = weak_ptr_unsafe<const la_og_lpts_application_impl>;

class la_system_port_scheduler_impl;
using la_system_port_scheduler_impl_sptr = std::shared_ptr<la_system_port_scheduler_impl>;
using la_system_port_scheduler_impl_scptr = std::shared_ptr<const la_system_port_scheduler_impl>;
using la_system_port_scheduler_impl_wptr = weak_ptr_unsafe<la_system_port_scheduler_impl>;
using la_system_port_scheduler_impl_wcptr = weak_ptr_unsafe<const la_system_port_scheduler_impl>;

class voq_counter_set;
using voq_counter_set_sptr = std::shared_ptr<voq_counter_set>;
using voq_counter_set_scptr = std::shared_ptr<const voq_counter_set>;
using voq_counter_set_wptr = weak_ptr_unsafe<voq_counter_set>;
using voq_counter_set_wcptr = weak_ptr_unsafe<const voq_counter_set>;

class la_fabric_port_scheduler_impl;
using la_fabric_port_scheduler_impl_sptr = std::shared_ptr<la_fabric_port_scheduler_impl>;
using la_fabric_port_scheduler_impl_scptr = std::shared_ptr<const la_fabric_port_scheduler_impl>;
using la_fabric_port_scheduler_impl_wptr = weak_ptr_unsafe<la_fabric_port_scheduler_impl>;
using la_fabric_port_scheduler_impl_wcptr = weak_ptr_unsafe<const la_fabric_port_scheduler_impl>;

class la_ifg_scheduler_impl;
using la_ifg_scheduler_impl_sptr = std::shared_ptr<la_ifg_scheduler_impl>;
using la_ifg_scheduler_impl_scptr = std::shared_ptr<const la_ifg_scheduler_impl>;
using la_ifg_scheduler_impl_wptr = weak_ptr_unsafe<la_ifg_scheduler_impl>;
using la_ifg_scheduler_impl_wcptr = weak_ptr_unsafe<const la_ifg_scheduler_impl>;

class la_voq_set_impl;
using la_voq_set_impl_sptr = std::shared_ptr<la_voq_set_impl>;
using la_voq_set_impl_scptr = std::shared_ptr<const la_voq_set_impl>;
using la_voq_set_impl_wptr = weak_ptr_unsafe<la_voq_set_impl>;
using la_voq_set_impl_wcptr = weak_ptr_unsafe<const la_voq_set_impl>;

class la_interface_scheduler_impl;
using la_interface_scheduler_impl_sptr = std::shared_ptr<la_interface_scheduler_impl>;
using la_interface_scheduler_impl_scptr = std::shared_ptr<const la_interface_scheduler_impl>;
using la_interface_scheduler_impl_wptr = weak_ptr_unsafe<la_interface_scheduler_impl>;
using la_interface_scheduler_impl_wcptr = weak_ptr_unsafe<const la_interface_scheduler_impl>;

class la_logical_port_scheduler_impl;
using la_logical_port_scheduler_impl_sptr = std::shared_ptr<la_logical_port_scheduler_impl>;
using la_logical_port_scheduler_impl_scptr = std::shared_ptr<const la_logical_port_scheduler_impl>;
using la_logical_port_scheduler_impl_wptr = weak_ptr_unsafe<la_logical_port_scheduler_impl>;
using la_logical_port_scheduler_impl_wcptr = weak_ptr_unsafe<const la_logical_port_scheduler_impl>;

class la_output_queue_scheduler_impl;
using la_output_queue_scheduler_impl_sptr = std::shared_ptr<la_output_queue_scheduler_impl>;
using la_output_queue_scheduler_impl_scptr = std::shared_ptr<const la_output_queue_scheduler_impl>;
using la_output_queue_scheduler_impl_wptr = weak_ptr_unsafe<la_output_queue_scheduler_impl>;
using la_output_queue_scheduler_impl_wcptr = weak_ptr_unsafe<const la_output_queue_scheduler_impl>;

class la_tc_profile_impl;
using la_tc_profile_impl_sptr = std::shared_ptr<la_tc_profile_impl>;
using la_tc_profile_impl_scptr = std::shared_ptr<const la_tc_profile_impl>;
using la_tc_profile_impl_wptr = weak_ptr_unsafe<la_tc_profile_impl>;
using la_tc_profile_impl_wcptr = weak_ptr_unsafe<const la_tc_profile_impl>;

class la_voq_cgm_evicted_profile_impl;
using la_voq_cgm_evicted_profile_impl_sptr = std::shared_ptr<la_voq_cgm_evicted_profile_impl>;
using la_voq_cgm_evicted_profile_impl_scptr = std::shared_ptr<const la_voq_cgm_evicted_profile_impl>;
using la_voq_cgm_evicted_profile_impl_wptr = weak_ptr_unsafe<la_voq_cgm_evicted_profile_impl>;
using la_voq_cgm_evicted_profile_impl_wcptr = weak_ptr_unsafe<const la_voq_cgm_evicted_profile_impl>;

class la_voq_cgm_profile_impl;
using la_voq_cgm_profile_impl_sptr = std::shared_ptr<la_voq_cgm_profile_impl>;
using la_voq_cgm_profile_impl_scptr = std::shared_ptr<const la_voq_cgm_profile_impl>;
using la_voq_cgm_profile_impl_wptr = weak_ptr_unsafe<la_voq_cgm_profile_impl>;
using la_voq_cgm_profile_impl_wcptr = weak_ptr_unsafe<const la_voq_cgm_profile_impl>;

class la_rx_cgm_sq_profile_impl;
using la_rx_cgm_sq_profile_impl_sptr = std::shared_ptr<la_rx_cgm_sq_profile_impl>;
using la_rx_cgm_sq_profile_impl_scptr = std::shared_ptr<const la_rx_cgm_sq_profile_impl>;
using la_rx_cgm_sq_profile_impl_wptr = weak_ptr_unsafe<la_rx_cgm_sq_profile_impl>;
using la_rx_cgm_sq_profile_impl_wcptr = weak_ptr_unsafe<const la_rx_cgm_sq_profile_impl>;

class la_meter_set_exact_impl;
using la_meter_set_exact_impl_sptr = std::shared_ptr<la_meter_set_exact_impl>;
using la_meter_set_exact_impl_scptr = std::shared_ptr<const la_meter_set_exact_impl>;
using la_meter_set_exact_impl_wptr = weak_ptr_unsafe<la_meter_set_exact_impl>;
using la_meter_set_exact_impl_wcptr = weak_ptr_unsafe<const la_meter_set_exact_impl>;

class la_ingress_qos_profile_impl;
using la_ingress_qos_profile_impl_sptr = std::shared_ptr<la_ingress_qos_profile_impl>;
using la_ingress_qos_profile_impl_scptr = std::shared_ptr<const la_ingress_qos_profile_impl>;
using la_ingress_qos_profile_impl_wptr = weak_ptr_unsafe<la_ingress_qos_profile_impl>;
using la_ingress_qos_profile_impl_wcptr = weak_ptr_unsafe<const la_ingress_qos_profile_impl>;

class la_meter_set_impl;
using la_meter_set_impl_sptr = std::shared_ptr<la_meter_set_impl>;
using la_meter_set_impl_scptr = std::shared_ptr<const la_meter_set_impl>;
using la_meter_set_impl_wptr = weak_ptr_unsafe<la_meter_set_impl>;
using la_meter_set_impl_wcptr = weak_ptr_unsafe<const la_meter_set_impl>;

class la_egress_qos_profile_impl;
using la_egress_qos_profile_impl_sptr = std::shared_ptr<la_egress_qos_profile_impl>;
using la_egress_qos_profile_impl_scptr = std::shared_ptr<const la_egress_qos_profile_impl>;
using la_egress_qos_profile_impl_wptr = weak_ptr_unsafe<la_egress_qos_profile_impl>;
using la_egress_qos_profile_impl_wcptr = weak_ptr_unsafe<const la_egress_qos_profile_impl>;

class la_meter_set_statistical_impl;
using la_meter_set_statistical_impl_sptr = std::shared_ptr<la_meter_set_statistical_impl>;
using la_meter_set_statistical_impl_scptr = std::shared_ptr<const la_meter_set_statistical_impl>;
using la_meter_set_statistical_impl_wptr = weak_ptr_unsafe<la_meter_set_statistical_impl>;
using la_meter_set_statistical_impl_wcptr = weak_ptr_unsafe<const la_meter_set_statistical_impl>;

class la_meter_action_profile_impl;
using la_meter_action_profile_impl_sptr = std::shared_ptr<la_meter_action_profile_impl>;
using la_meter_action_profile_impl_scptr = std::shared_ptr<const la_meter_action_profile_impl>;
using la_meter_action_profile_impl_wptr = weak_ptr_unsafe<la_meter_action_profile_impl>;
using la_meter_action_profile_impl_wcptr = weak_ptr_unsafe<const la_meter_action_profile_impl>;

class la_meter_profile_impl;
using la_meter_profile_impl_sptr = std::shared_ptr<la_meter_profile_impl>;
using la_meter_profile_impl_scptr = std::shared_ptr<const la_meter_profile_impl>;
using la_meter_profile_impl_wptr = weak_ptr_unsafe<la_meter_profile_impl>;
using la_meter_profile_impl_wcptr = weak_ptr_unsafe<const la_meter_profile_impl>;

class la_meter_markdown_profile_impl;
using la_meter_markdown_profile_impl_sptr = std::shared_ptr<la_meter_markdown_profile_impl>;
using la_meter_markdown_profile_impl_scptr = std::shared_ptr<const la_meter_markdown_profile_impl>;
using la_meter_markdown_profile_impl_wptr = weak_ptr_unsafe<la_meter_markdown_profile_impl>;
using la_meter_markdown_profile_impl_wcptr = weak_ptr_unsafe<const la_meter_markdown_profile_impl>;

class la_erspan_mirror_command_base;
using la_erspan_mirror_command_base_sptr = std::shared_ptr<la_erspan_mirror_command_base>;
using la_erspan_mirror_command_base_scptr = std::shared_ptr<const la_erspan_mirror_command_base>;
using la_erspan_mirror_command_base_wptr = weak_ptr_unsafe<la_erspan_mirror_command_base>;
using la_erspan_mirror_command_base_wcptr = weak_ptr_unsafe<const la_erspan_mirror_command_base>;

class la_erspan_mirror_command_pacific;
using la_erspan_mirror_command_pacific_sptr = std::shared_ptr<la_erspan_mirror_command_pacific>;
using la_erspan_mirror_command_pacific_scptr = std::shared_ptr<const la_erspan_mirror_command_pacific>;
using la_erspan_mirror_command_pacific_wptr = weak_ptr_unsafe<la_erspan_mirror_command_pacific>;
using la_erspan_mirror_command_pacific_wcptr = weak_ptr_unsafe<const la_erspan_mirror_command_pacific>;

class la_erspan_mirror_command_gibraltar;
using la_erspan_mirror_command_gibraltar_sptr = std::shared_ptr<la_erspan_mirror_command_gibraltar>;
using la_erspan_mirror_command_gibraltar_scptr = std::shared_ptr<const la_erspan_mirror_command_gibraltar>;
using la_erspan_mirror_command_gibraltar_wptr = weak_ptr_unsafe<la_erspan_mirror_command_gibraltar>;
using la_erspan_mirror_command_gibraltar_wcptr = weak_ptr_unsafe<const la_erspan_mirror_command_gibraltar>;

class la_erspan_mirror_command_akpg;
using la_erspan_mirror_command_akpg_sptr = std::shared_ptr<la_erspan_mirror_command_akpg>;
using la_erspan_mirror_command_akpg_scptr = std::shared_ptr<const la_erspan_mirror_command_akpg>;
using la_erspan_mirror_command_akpg_wptr = weak_ptr_unsafe<la_erspan_mirror_command_akpg>;
using la_erspan_mirror_command_akpg_wcptr = weak_ptr_unsafe<const la_erspan_mirror_command_akpg>;

class la_hbm_handler_impl;
using la_hbm_handler_impl_sptr = std::shared_ptr<la_hbm_handler_impl>;
using la_hbm_handler_impl_scptr = std::shared_ptr<const la_hbm_handler_impl>;
using la_hbm_handler_impl_wptr = weak_ptr_unsafe<la_hbm_handler_impl>;
using la_hbm_handler_impl_wcptr = weak_ptr_unsafe<const la_hbm_handler_impl>;

class la_flow_cache_handler_impl;
using la_flow_cache_handler_impl_sptr = std::shared_ptr<la_flow_cache_handler_impl>;
using la_flow_cache_handler_impl_scptr = std::shared_ptr<const la_flow_cache_handler_impl>;
using la_flow_cache_handler_impl_wptr = weak_ptr_unsafe<la_flow_cache_handler_impl>;
using la_flow_cache_handler_impl_wcptr = weak_ptr_unsafe<const la_flow_cache_handler_impl>;

class la_l2_mirror_command_base;
using la_l2_mirror_command_base_sptr = std::shared_ptr<la_l2_mirror_command_base>;
using la_l2_mirror_command_base_scptr = std::shared_ptr<const la_l2_mirror_command_base>;
using la_l2_mirror_command_base_wptr = weak_ptr_unsafe<la_l2_mirror_command_base>;
using la_l2_mirror_command_base_wcptr = weak_ptr_unsafe<const la_l2_mirror_command_base>;

class la_l2_mirror_command_pacific;
using la_l2_mirror_command_pacific_sptr = std::shared_ptr<la_l2_mirror_command_pacific>;
using la_l2_mirror_command_pacific_scptr = std::shared_ptr<const la_l2_mirror_command_pacific>;
using la_l2_mirror_command_pacific_wptr = weak_ptr_unsafe<la_l2_mirror_command_pacific>;
using la_l2_mirror_command_pacific_wcptr = weak_ptr_unsafe<const la_l2_mirror_command_pacific>;

class la_l2_mirror_command_gibraltar;
using la_l2_mirror_command_gibraltar_sptr = std::shared_ptr<la_l2_mirror_command_gibraltar>;
using la_l2_mirror_command_gibraltar_scptr = std::shared_ptr<const la_l2_mirror_command_gibraltar>;
using la_l2_mirror_command_gibraltar_wptr = weak_ptr_unsafe<la_l2_mirror_command_gibraltar>;
using la_l2_mirror_command_gibraltar_wcptr = weak_ptr_unsafe<const la_l2_mirror_command_gibraltar>;

class la_l2_mirror_command_akpg;
using la_l2_mirror_command_akpg_sptr = std::shared_ptr<la_l2_mirror_command_akpg>;
using la_l2_mirror_command_akpg_scptr = std::shared_ptr<const la_l2_mirror_command_akpg>;
using la_l2_mirror_command_akpg_wptr = weak_ptr_unsafe<la_l2_mirror_command_akpg>;
using la_l2_mirror_command_akpg_wcptr = weak_ptr_unsafe<const la_l2_mirror_command_akpg>;

class la_spa_port_base;
using la_spa_port_base_sptr = std::shared_ptr<la_spa_port_base>;
using la_spa_port_base_scptr = std::shared_ptr<const la_spa_port_base>;
using la_spa_port_base_wptr = weak_ptr_unsafe<la_spa_port_base>;
using la_spa_port_base_wcptr = weak_ptr_unsafe<const la_spa_port_base>;

class la_spa_port_pacific;
using la_spa_port_pacific_sptr = std::shared_ptr<la_spa_port_pacific>;
using la_spa_port_pacific_scptr = std::shared_ptr<const la_spa_port_pacific>;
using la_spa_port_pacific_wptr = weak_ptr_unsafe<la_spa_port_pacific>;
using la_spa_port_pacific_wcptr = weak_ptr_unsafe<const la_spa_port_pacific>;

class la_spa_port_gibraltar;
using la_spa_port_gibraltar_sptr = std::shared_ptr<la_spa_port_gibraltar>;
using la_spa_port_gibraltar_scptr = std::shared_ptr<const la_spa_port_gibraltar>;
using la_spa_port_gibraltar_wptr = weak_ptr_unsafe<la_spa_port_gibraltar>;
using la_spa_port_gibraltar_wcptr = weak_ptr_unsafe<const la_spa_port_gibraltar>;

class la_spa_port_akpg;
using la_spa_port_akpg_sptr = std::shared_ptr<la_spa_port_akpg>;
using la_spa_port_akpg_scptr = std::shared_ptr<const la_spa_port_akpg>;
using la_spa_port_akpg_wptr = weak_ptr_unsafe<la_spa_port_akpg>;
using la_spa_port_akpg_wcptr = weak_ptr_unsafe<const la_spa_port_akpg>;

class la_punt_inject_port_base;
using la_punt_inject_port_base_sptr = std::shared_ptr<la_punt_inject_port_base>;
using la_punt_inject_port_base_scptr = std::shared_ptr<const la_punt_inject_port_base>;
using la_punt_inject_port_base_wptr = weak_ptr_unsafe<la_punt_inject_port_base>;
using la_punt_inject_port_base_wcptr = weak_ptr_unsafe<const la_punt_inject_port_base>;

class la_punt_inject_port_pacific;
using la_punt_inject_port_pacific_sptr = std::shared_ptr<la_punt_inject_port_pacific>;
using la_punt_inject_port_pacific_scptr = std::shared_ptr<const la_punt_inject_port_pacific>;
using la_punt_inject_port_pacific_wptr = weak_ptr_unsafe<la_punt_inject_port_pacific>;
using la_punt_inject_port_pacific_wcptr = weak_ptr_unsafe<const la_punt_inject_port_pacific>;

class la_punt_inject_port_gibraltar;
using la_punt_inject_port_gibraltar_sptr = std::shared_ptr<la_punt_inject_port_gibraltar>;
using la_punt_inject_port_gibraltar_scptr = std::shared_ptr<const la_punt_inject_port_gibraltar>;
using la_punt_inject_port_gibraltar_wptr = weak_ptr_unsafe<la_punt_inject_port_gibraltar>;
using la_punt_inject_port_gibraltar_wcptr = weak_ptr_unsafe<const la_punt_inject_port_gibraltar>;

class la_punt_inject_port_akpg;
using la_punt_inject_port_akpg_sptr = std::shared_ptr<la_punt_inject_port_akpg>;
using la_punt_inject_port_akpg_scptr = std::shared_ptr<const la_punt_inject_port_akpg>;
using la_punt_inject_port_akpg_wptr = weak_ptr_unsafe<la_punt_inject_port_akpg>;
using la_punt_inject_port_akpg_wcptr = weak_ptr_unsafe<const la_punt_inject_port_akpg>;

class la_fabric_port_impl;
using la_fabric_port_impl_sptr = std::shared_ptr<la_fabric_port_impl>;
using la_fabric_port_impl_scptr = std::shared_ptr<const la_fabric_port_impl>;
using la_fabric_port_impl_wptr = weak_ptr_unsafe<la_fabric_port_impl>;
using la_fabric_port_impl_wcptr = weak_ptr_unsafe<const la_fabric_port_impl>;

class la_npu_host_destination_impl;
using la_npu_host_destination_impl_sptr = std::shared_ptr<la_npu_host_destination_impl>;
using la_npu_host_destination_impl_scptr = std::shared_ptr<const la_npu_host_destination_impl>;
using la_npu_host_destination_impl_wptr = weak_ptr_unsafe<la_npu_host_destination_impl>;
using la_npu_host_destination_impl_wcptr = weak_ptr_unsafe<const la_npu_host_destination_impl>;

class la_pbts_map_profile_impl;
using la_pbts_map_profile_impl_sptr = std::shared_ptr<la_pbts_map_profile_impl>;
using la_pbts_map_profile_impl_scptr = std::shared_ptr<const la_pbts_map_profile_impl>;
using la_pbts_map_profile_impl_wptr = weak_ptr_unsafe<la_pbts_map_profile_impl>;
using la_pbts_map_profile_impl_wcptr = weak_ptr_unsafe<const la_pbts_map_profile_impl>;

class la_pbts_group_impl;
using la_pbts_group_impl_sptr = std::shared_ptr<la_pbts_group_impl>;
using la_pbts_group_impl_scptr = std::shared_ptr<const la_pbts_group_impl>;
using la_pbts_group_impl_wptr = weak_ptr_unsafe<la_pbts_group_impl>;
using la_pbts_group_impl_wcptr = weak_ptr_unsafe<const la_pbts_group_impl>;

class aapl_impl;
using aapl_impl_sptr = std::shared_ptr<aapl_impl>;
using aapl_impl_scptr = std::shared_ptr<const aapl_impl>;
using aapl_impl_wptr = weak_ptr_unsafe<aapl_impl>;
using aapl_impl_wcptr = weak_ptr_unsafe<const aapl_impl>;

class counter_logical_bank;
using counter_logical_bank_sptr = std::shared_ptr<counter_logical_bank>;
using counter_logical_bank_scptr = std::shared_ptr<const counter_logical_bank>;
using counter_logical_bank_wptr = weak_ptr_unsafe<counter_logical_bank>;
using counter_logical_bank_wcptr = weak_ptr_unsafe<const counter_logical_bank>;

class la_recycle_port_base;
using la_recycle_port_base_sptr = std::shared_ptr<la_recycle_port_base>;
using la_recycle_port_base_scptr = std::shared_ptr<const la_recycle_port_base>;
using la_recycle_port_base_wptr = weak_ptr_unsafe<la_recycle_port_base>;
using la_recycle_port_base_wcptr = weak_ptr_unsafe<const la_recycle_port_base>;

class la_recycle_port_pacific;
using la_recycle_port_pacific_sptr = std::shared_ptr<la_recycle_port_pacific>;
using la_recycle_port_pacific_scptr = std::shared_ptr<const la_recycle_port_pacific>;
using la_recycle_port_pacific_wptr = weak_ptr_unsafe<la_recycle_port_pacific>;
using la_recycle_port_pacific_wcptr = weak_ptr_unsafe<const la_recycle_port_pacific>;

class la_recycle_port_gibraltar;
using la_recycle_port_gibraltar_sptr = std::shared_ptr<la_recycle_port_gibraltar>;
using la_recycle_port_gibraltar_scptr = std::shared_ptr<const la_recycle_port_gibraltar>;
using la_recycle_port_gibraltar_wptr = weak_ptr_unsafe<la_recycle_port_gibraltar>;
using la_recycle_port_gibraltar_wcptr = weak_ptr_unsafe<const la_recycle_port_gibraltar>;

class la_recycle_port_akpg;
using la_recycle_port_akpg_sptr = std::shared_ptr<la_recycle_port_akpg>;
using la_recycle_port_akpg_scptr = std::shared_ptr<const la_recycle_port_akpg>;
using la_recycle_port_akpg_wptr = weak_ptr_unsafe<la_recycle_port_akpg>;
using la_recycle_port_akpg_wcptr = weak_ptr_unsafe<const la_recycle_port_akpg>;

class la_device_impl;
using la_device_impl_sptr = std::shared_ptr<la_device_impl>;
using la_device_impl_scptr = std::shared_ptr<const la_device_impl>;
using la_device_impl_wptr = weak_ptr_unsafe<la_device_impl>;
using la_device_impl_wcptr = weak_ptr_unsafe<const la_device_impl>;

class la_device_impl_base;
using la_device_impl_base_sptr = std::shared_ptr<la_device_impl_base>;
using la_device_impl_base_scptr = std::shared_ptr<const la_device_impl_base>;
using la_device_impl_base_wptr = weak_ptr_unsafe<la_device_impl_base>;
using la_device_impl_base_wcptr = weak_ptr_unsafe<const la_device_impl_base>;

class counter_manager;
using counter_manager_sptr = std::shared_ptr<counter_manager>;
using counter_manager_scptr = std::shared_ptr<const counter_manager>;
using counter_manager_wptr = weak_ptr_unsafe<counter_manager>;
using counter_manager_wcptr = weak_ptr_unsafe<const counter_manager>;

class serdes_handler;
using serdes_handler_sptr = std::shared_ptr<serdes_handler>;
using serdes_handler_scptr = std::shared_ptr<const serdes_handler>;
using serdes_handler_wptr = weak_ptr_unsafe<serdes_handler>;
using serdes_handler_wcptr = weak_ptr_unsafe<const serdes_handler>;

class la_mac_port_base;
using la_mac_port_base_sptr = std::shared_ptr<la_mac_port_base>;
using la_mac_port_base_scptr = std::shared_ptr<const la_mac_port_base>;
using la_mac_port_base_wptr = weak_ptr_unsafe<la_mac_port_base>;
using la_mac_port_base_wcptr = weak_ptr_unsafe<const la_mac_port_base>;

class la_mac_port_pacific;
using la_mac_port_pacific_sptr = std::shared_ptr<la_mac_port_pacific>;
using la_mac_port_pacific_scptr = std::shared_ptr<const la_mac_port_pacific>;
using la_mac_port_pacific_wptr = weak_ptr_unsafe<la_mac_port_pacific>;
using la_mac_port_pacific_wcptr = weak_ptr_unsafe<const la_mac_port_pacific>;

class la_mac_port_gibraltar;
using la_mac_port_gibraltar_sptr = std::shared_ptr<la_mac_port_gibraltar>;
using la_mac_port_gibraltar_scptr = std::shared_ptr<const la_mac_port_gibraltar>;
using la_mac_port_gibraltar_wptr = weak_ptr_unsafe<la_mac_port_gibraltar>;
using la_mac_port_gibraltar_wcptr = weak_ptr_unsafe<const la_mac_port_gibraltar>;

class la_mac_port_akpg;
using la_mac_port_akpg_sptr = std::shared_ptr<la_mac_port_akpg>;
using la_mac_port_akpg_scptr = std::shared_ptr<const la_mac_port_akpg>;
using la_mac_port_akpg_wptr = weak_ptr_unsafe<la_mac_port_akpg>;
using la_mac_port_akpg_wcptr = weak_ptr_unsafe<const la_mac_port_akpg>;

class mac_pool_port;
using mac_pool_port_sptr = std::shared_ptr<mac_pool_port>;
using mac_pool_port_scptr = std::shared_ptr<const mac_pool_port>;
using mac_pool_port_wptr = weak_ptr_unsafe<mac_pool_port>;
using mac_pool_port_wcptr = weak_ptr_unsafe<const mac_pool_port>;

class mac_pool2_port;
using mac_pool2_port_sptr = std::shared_ptr<mac_pool2_port>;
using mac_pool2_port_scptr = std::shared_ptr<const mac_pool2_port>;
using mac_pool2_port_wptr = weak_ptr_unsafe<mac_pool2_port>;
using mac_pool2_port_wcptr = weak_ptr_unsafe<const mac_pool2_port>;

class la_remote_port_impl;
using la_remote_port_impl_sptr = std::shared_ptr<la_remote_port_impl>;
using la_remote_port_impl_scptr = std::shared_ptr<const la_remote_port_impl>;
using la_remote_port_impl_wptr = weak_ptr_unsafe<la_remote_port_impl>;
using la_remote_port_impl_wcptr = weak_ptr_unsafe<const la_remote_port_impl>;

class la_remote_device_base;
using la_remote_device_base_sptr = std::shared_ptr<la_remote_device_base>;
using la_remote_device_base_scptr = std::shared_ptr<const la_remote_device_base>;
using la_remote_device_base_wptr = weak_ptr_unsafe<la_remote_device_base>;
using la_remote_device_base_wcptr = weak_ptr_unsafe<const la_remote_device_base>;

class pacific_mac_pool;
using pacific_mac_pool_sptr = std::shared_ptr<pacific_mac_pool>;
using pacific_mac_pool_scptr = std::shared_ptr<const pacific_mac_pool>;
using pacific_mac_pool_wptr = weak_ptr_unsafe<pacific_mac_pool>;
using pacific_mac_pool_wcptr = weak_ptr_unsafe<const pacific_mac_pool>;

class la_mac_port_common_impl;
using la_mac_port_common_impl_sptr = std::shared_ptr<la_mac_port_common_impl>;
using la_mac_port_common_impl_scptr = std::shared_ptr<const la_mac_port_common_impl>;
using la_mac_port_common_impl_wptr = weak_ptr_unsafe<la_mac_port_common_impl>;
using la_mac_port_common_impl_wcptr = weak_ptr_unsafe<const la_mac_port_common_impl>;

class la_l2_punt_destination_impl;
using la_l2_punt_destination_impl_sptr = std::shared_ptr<la_l2_punt_destination_impl>;
using la_l2_punt_destination_impl_scptr = std::shared_ptr<const la_l2_punt_destination_impl>;
using la_l2_punt_destination_impl_wptr = weak_ptr_unsafe<la_l2_punt_destination_impl>;
using la_l2_punt_destination_impl_wcptr = weak_ptr_unsafe<const la_l2_punt_destination_impl>;

class la_stack_port;
using la_stack_port_sptr = std::shared_ptr<la_stack_port>;
using la_stack_port_scptr = std::shared_ptr<const la_stack_port>;
using la_stack_port_wptr = weak_ptr_unsafe<la_stack_port>;
using la_stack_port_wcptr = weak_ptr_unsafe<const la_stack_port>;

class la_system_port_base;
using la_system_port_base_sptr = std::shared_ptr<la_system_port_base>;
using la_system_port_base_scptr = std::shared_ptr<const la_system_port_base>;
using la_system_port_base_wptr = weak_ptr_unsafe<la_system_port_base>;
using la_system_port_base_wcptr = weak_ptr_unsafe<const la_system_port_base>;

class la_system_port_pacific;
using la_system_port_pacific_sptr = std::shared_ptr<la_system_port_pacific>;
using la_system_port_pacific_scptr = std::shared_ptr<const la_system_port_pacific>;
using la_system_port_pacific_wptr = weak_ptr_unsafe<la_system_port_pacific>;
using la_system_port_pacific_wcptr = weak_ptr_unsafe<const la_system_port_pacific>;

class la_system_port_gibraltar;
using la_system_port_gibraltar_sptr = std::shared_ptr<la_system_port_gibraltar>;
using la_system_port_gibraltar_scptr = std::shared_ptr<const la_system_port_gibraltar>;
using la_system_port_gibraltar_wptr = weak_ptr_unsafe<la_system_port_gibraltar>;
using la_system_port_gibraltar_wcptr = weak_ptr_unsafe<const la_system_port_gibraltar>;

class la_system_port_akpg;
using la_system_port_akpg_sptr = std::shared_ptr<la_system_port_akpg>;
using la_system_port_akpg_scptr = std::shared_ptr<const la_system_port_akpg>;
using la_system_port_akpg_wptr = weak_ptr_unsafe<la_system_port_akpg>;
using la_system_port_akpg_wcptr = weak_ptr_unsafe<const la_system_port_akpg>;

class la_system_port_pacgb;
using la_system_port_pacgb_sptr = std::shared_ptr<la_system_port_pacgb>;
using la_system_port_pacgb_scptr = std::shared_ptr<const la_system_port_pacgb>;
using la_system_port_pacgb_wptr = weak_ptr_unsafe<la_system_port_pacgb>;
using la_system_port_pacgb_wcptr = weak_ptr_unsafe<const la_system_port_pacgb>;

class resource_monitor;
using resource_monitor_sptr = std::shared_ptr<resource_monitor>;
using resource_monitor_scptr = std::shared_ptr<const resource_monitor>;
using resource_monitor_wptr = weak_ptr_unsafe<resource_monitor>;
using resource_monitor_wcptr = weak_ptr_unsafe<const resource_monitor>;

class la_npu_host_port_base;
using la_npu_host_port_base_sptr = std::shared_ptr<la_npu_host_port_base>;
using la_npu_host_port_base_scptr = std::shared_ptr<const la_npu_host_port_base>;
using la_npu_host_port_base_wptr = weak_ptr_unsafe<la_npu_host_port_base>;
using la_npu_host_port_base_wcptr = weak_ptr_unsafe<const la_npu_host_port_base>;

class la_vrf_port_common_base;
using la_vrf_port_common_base_sptr = std::shared_ptr<la_vrf_port_common_base>;
using la_vrf_port_common_base_scptr = std::shared_ptr<const la_vrf_port_common_base>;
using la_vrf_port_common_base_wptr = weak_ptr_unsafe<la_vrf_port_common_base>;
using la_vrf_port_common_base_wcptr = weak_ptr_unsafe<const la_vrf_port_common_base>;

class srm_serdes_handler;
using srm_serdes_handler_sptr = std::shared_ptr<srm_serdes_handler>;
using srm_serdes_handler_scptr = std::shared_ptr<const srm_serdes_handler>;
using srm_serdes_handler_wptr = weak_ptr_unsafe<srm_serdes_handler>;
using srm_serdes_handler_wcptr = weak_ptr_unsafe<const srm_serdes_handler>;

class srm_serdes_device_handler;
using srm_serdes_device_handler_sptr = std::shared_ptr<srm_serdes_device_handler>;
using srm_serdes_device_handler_scptr = std::shared_ptr<const srm_serdes_device_handler>;
using srm_serdes_device_handler_wptr = weak_ptr_unsafe<srm_serdes_device_handler>;
using srm_serdes_device_handler_wcptr = weak_ptr_unsafe<const srm_serdes_device_handler>;

class beagle_serdes_handler;
using beagle_serdes_handler_sptr = std::shared_ptr<beagle_serdes_handler>;
using beagle_serdes_handler_scptr = std::shared_ptr<const beagle_serdes_handler>;
using beagle_serdes_handler_wptr = weak_ptr_unsafe<beagle_serdes_handler>;
using beagle_serdes_handler_wcptr = weak_ptr_unsafe<const beagle_serdes_handler>;

class beagle_serdes_device_handler;
using beagle_serdes_device_handler_sptr = std::shared_ptr<beagle_serdes_device_handler>;
using beagle_serdes_device_handler_scptr = std::shared_ptr<const beagle_serdes_device_handler>;
using beagle_serdes_device_handler_wptr = weak_ptr_unsafe<beagle_serdes_device_handler>;
using beagle_serdes_device_handler_wcptr = weak_ptr_unsafe<const beagle_serdes_device_handler>;

class etp_serdes_handler;
using etp_serdes_handler_sptr = std::shared_ptr<etp_serdes_handler>;
using etp_serdes_handler_scptr = std::shared_ptr<const etp_serdes_handler>;
using etp_serdes_handler_wptr = weak_ptr_unsafe<etp_serdes_handler>;
using etp_serdes_handler_wcptr = weak_ptr_unsafe<const etp_serdes_handler>;

class etp_serdes_device_handler;
using etp_serdes_device_handler_sptr = std::shared_ptr<etp_serdes_device_handler>;
using etp_serdes_device_handler_scptr = std::shared_ptr<const etp_serdes_device_handler>;
using etp_serdes_device_handler_wptr = weak_ptr_unsafe<etp_serdes_device_handler>;
using etp_serdes_device_handler_wcptr = weak_ptr_unsafe<const etp_serdes_device_handler>;

class la_pcl;
using la_pcl_sptr = std::shared_ptr<la_pcl>;
using la_pcl_scptr = std::shared_ptr<const la_pcl>;
using la_pcl_wptr = weak_ptr_unsafe<la_pcl>;
using la_pcl_wcptr = weak_ptr_unsafe<const la_pcl>;

class resource_handler;
using resource_handler_sptr = std::shared_ptr<resource_handler>;
using resource_handler_scptr = std::shared_ptr<const resource_handler>;
using resource_handler_wptr = weak_ptr_unsafe<resource_handler>;
using resource_handler_wcptr = weak_ptr_unsafe<const resource_handler>;

class la_stack_port_base;
using la_stack_port_base_sptr = std::shared_ptr<la_stack_port_base>;
using la_stack_port_base_scptr = std::shared_ptr<const la_stack_port_base>;
using la_stack_port_base_wptr = weak_ptr_unsafe<la_stack_port_base>;
using la_stack_port_base_wcptr = weak_ptr_unsafe<const la_stack_port_base>;

class dependency_listener;
using dependency_listener_sptr = std::shared_ptr<dependency_listener>;
using dependency_listener_scptr = std::shared_ptr<const dependency_listener>;
using dependency_listener_wptr = weak_ptr_unsafe<dependency_listener>;
using dependency_listener_wcptr = weak_ptr_unsafe<const dependency_listener>;

class hld_notification_base;
using hld_notification_base_sptr = std::shared_ptr<hld_notification_base>;
using hld_notification_base_scptr = std::shared_ptr<const hld_notification_base>;
using hld_notification_base_wptr = weak_ptr_unsafe<hld_notification_base>;
using hld_notification_base_wcptr = weak_ptr_unsafe<const hld_notification_base>;

class la_pci_port_base;
using la_pci_port_base_sptr = std::shared_ptr<la_pci_port_base>;
using la_pci_port_base_scptr = std::shared_ptr<const la_pci_port_base>;
using la_pci_port_base_wptr = weak_ptr_unsafe<la_pci_port_base>;
using la_pci_port_base_wcptr = weak_ptr_unsafe<const la_pci_port_base>;

class la_pci_port_pacific;
using la_pci_port_pacific_sptr = std::shared_ptr<la_pci_port_pacific>;
using la_pci_port_pacific_scptr = std::shared_ptr<const la_pci_port_pacific>;
using la_pci_port_pacific_wptr = weak_ptr_unsafe<la_pci_port_pacific>;
using la_pci_port_pacific_wcptr = weak_ptr_unsafe<const la_pci_port_pacific>;

class la_pci_port_gibraltar;
using la_pci_port_gibraltar_sptr = std::shared_ptr<la_pci_port_gibraltar>;
using la_pci_port_gibraltar_scptr = std::shared_ptr<const la_pci_port_gibraltar>;
using la_pci_port_gibraltar_wptr = weak_ptr_unsafe<la_pci_port_gibraltar>;
using la_pci_port_gibraltar_wcptr = weak_ptr_unsafe<const la_pci_port_gibraltar>;

class la_pci_port_akpg;
using la_pci_port_akpg_sptr = std::shared_ptr<la_pci_port_akpg>;
using la_pci_port_akpg_scptr = std::shared_ptr<const la_pci_port_akpg>;
using la_pci_port_akpg_wptr = weak_ptr_unsafe<la_pci_port_akpg>;
using la_pci_port_akpg_wcptr = weak_ptr_unsafe<const la_pci_port_akpg>;

class slice_id_manager_base;
using slice_id_manager_base_sptr = std::shared_ptr<slice_id_manager_base>;
using slice_id_manager_base_scptr = std::shared_ptr<const slice_id_manager_base>;
using slice_id_manager_base_wptr = weak_ptr_unsafe<slice_id_manager_base>;
using slice_id_manager_base_wcptr = weak_ptr_unsafe<const slice_id_manager_base>;

class la_security_group_cell_base;
using la_security_group_cell_base_sptr = std::shared_ptr<la_security_group_cell_base>;
using la_security_group_cell_base_scptr = std::shared_ptr<const la_security_group_cell_base>;
using la_security_group_cell_base_wptr = weak_ptr_unsafe<la_security_group_cell_base>;
using la_security_group_cell_base_wcptr = weak_ptr_unsafe<const la_security_group_cell_base>;

class la_security_group_cell;
using la_security_group_cell_sptr = std::shared_ptr<la_security_group_cell>;
using la_security_group_cell_scptr = std::shared_ptr<const la_security_group_cell>;
using la_security_group_cell_wptr = weak_ptr_unsafe<la_security_group_cell>;
using la_security_group_cell_wcptr = weak_ptr_unsafe<const la_security_group_cell>;

class la_copc_base;
using la_copc_base_sptr = std::shared_ptr<la_copc_base>;
using la_copc_base_scptr = std::shared_ptr<const la_copc_base>;
using la_copc_base_wptr = weak_ptr_unsafe<la_copc_base>;
using la_copc_base_wcptr = weak_ptr_unsafe<const la_copc_base>;

class device_port_handler_base;
using device_port_handler_base_sptr = std::shared_ptr<device_port_handler_base>;
using device_port_handler_base_scptr = std::shared_ptr<const device_port_handler_base>;
using device_port_handler_base_wptr = weak_ptr_unsafe<device_port_handler_base>;
using device_port_handler_base_wcptr = weak_ptr_unsafe<const device_port_handler_base>;

class serdes_device_handler;
using serdes_device_handler_sptr = std::shared_ptr<serdes_device_handler>;
using serdes_device_handler_scptr = std::shared_ptr<const serdes_device_handler>;
using serdes_device_handler_wptr = weak_ptr_unsafe<serdes_device_handler>;
using serdes_device_handler_wcptr = weak_ptr_unsafe<const serdes_device_handler>;

class la_vrf_redirect_destination;
using la_vrf_redirect_destination_sptr = std::shared_ptr<la_vrf_redirect_destination>;
using la_vrf_redirect_destination_scptr = std::shared_ptr<const la_vrf_redirect_destination>;
using la_vrf_redirect_destination_wptr = weak_ptr_unsafe<la_vrf_redirect_destination>;
using la_vrf_redirect_destination_wcptr = weak_ptr_unsafe<const la_vrf_redirect_destination>;

class la_vrf_redirect_destination_impl;
using la_vrf_redirect_destination_impl_sptr = std::shared_ptr<la_vrf_redirect_destination_impl>;
using la_vrf_redirect_destination_impl_scptr = std::shared_ptr<const la_vrf_redirect_destination_impl>;
using la_vrf_redirect_destination_impl_wptr = weak_ptr_unsafe<la_vrf_redirect_destination_impl>;
using la_vrf_redirect_destination_impl_wcptr = weak_ptr_unsafe<const la_vrf_redirect_destination_impl>;

class la_acl_security_group;
using la_acl_security_group_sptr = std::shared_ptr<la_acl_security_group>;
using la_acl_security_group_scptr = std::shared_ptr<const la_acl_security_group>;
using la_acl_security_group_wptr = weak_ptr_unsafe<la_acl_security_group>;
using la_acl_security_group_wcptr = weak_ptr_unsafe<const la_acl_security_group>;

} // namespace silicon_one

#endif
