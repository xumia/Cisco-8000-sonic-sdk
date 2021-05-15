// This file has been automatically generated in nplapi package. Do not edit it manually.
// Generated by nplapi_utilities.py at 2021-05-12 16:16:10

#ifndef __DEVICE_TABLES_H__
#define __DEVICE_TABLES_H__


#include <memory>
#include "common/la_status.h"
#include "nplapi/nplapi_tables.h"
#include "nplapi/translator_creator.h"
#include "common/cereal_utils.h"

namespace silicon_one
{

/// @brief Collection of all supported NPL tables.
class device_tables
{
    
    CEREAL_SUPPORT_PRIVATE_MEMBERS
    
public:
explicit device_tables(la_device_id_t id) : m_device_id(id) {}
device_tables() = default; // Needed by cereal

la_status initialize_tables(translator_creator& creator);

la_device_id_t get_device_id() const
{
    return m_device_id;
}
public:

std::shared_ptr<npl_acl_map_fi_header_type_to_protocol_number_table_t> acl_map_fi_header_type_to_protocol_number_table[6];

std::shared_ptr<npl_additional_labels_table_t> additional_labels_table[3];

std::shared_ptr<npl_all_reachable_vector_t> all_reachable_vector;

std::shared_ptr<npl_bfd_desired_tx_interval_table_t> bfd_desired_tx_interval_table;

std::shared_ptr<npl_bfd_detection_multiple_table_t> bfd_detection_multiple_table;

std::shared_ptr<npl_bfd_event_queue_table_t> bfd_event_queue_table[6];

std::shared_ptr<npl_bfd_inject_inner_da_high_table_t> bfd_inject_inner_da_high_table;

std::shared_ptr<npl_bfd_inject_inner_da_low_table_t> bfd_inject_inner_da_low_table;

std::shared_ptr<npl_bfd_inject_inner_ethernet_header_static_table_t> bfd_inject_inner_ethernet_header_static_table;

std::shared_ptr<npl_bfd_inject_ttl_static_table_t> bfd_inject_ttl_static_table;

std::shared_ptr<npl_bfd_ipv6_sip_A_table_t> bfd_ipv6_sip_A_table;

std::shared_ptr<npl_bfd_ipv6_sip_B_table_t> bfd_ipv6_sip_B_table;

std::shared_ptr<npl_bfd_ipv6_sip_C_table_t> bfd_ipv6_sip_C_table;

std::shared_ptr<npl_bfd_ipv6_sip_D_table_t> bfd_ipv6_sip_D_table;

std::shared_ptr<npl_bfd_punt_encap_static_table_t> bfd_punt_encap_static_table[6];

std::shared_ptr<npl_bfd_required_tx_interval_table_t> bfd_required_tx_interval_table;

std::shared_ptr<npl_bfd_rx_table_t> bfd_rx_table;

std::shared_ptr<npl_bfd_set_inject_type_static_table_t> bfd_set_inject_type_static_table;

std::shared_ptr<npl_bfd_udp_port_map_static_table_t> bfd_udp_port_map_static_table[6];

std::shared_ptr<npl_bfd_udp_port_static_table_t> bfd_udp_port_static_table;

std::shared_ptr<npl_bitmap_oqg_map_table_t> bitmap_oqg_map_table;

std::shared_ptr<npl_bvn_tc_map_table_t> bvn_tc_map_table;

std::shared_ptr<npl_calc_checksum_enable_table_t> calc_checksum_enable_table[6];

std::shared_ptr<npl_ccm_flags_table_t> ccm_flags_table;

std::shared_ptr<npl_cif2npa_c_lri_macro_t> cif2npa_c_lri_macro;

std::shared_ptr<npl_cif2npa_c_mps_macro_t> cif2npa_c_mps_macro;

std::shared_ptr<npl_counters_block_config_table_t> counters_block_config_table;

std::shared_ptr<npl_counters_voq_block_map_table_t> counters_voq_block_map_table[6];

std::shared_ptr<npl_cud_is_multicast_bitmap_t> cud_is_multicast_bitmap;

std::shared_ptr<npl_cud_narrow_hw_table_t> cud_narrow_hw_table[6];

std::shared_ptr<npl_cud_wide_hw_table_t> cud_wide_hw_table[6];

std::shared_ptr<npl_default_egress_ipv4_sec_acl_table_t> default_egress_ipv4_sec_acl_table[6];

std::shared_ptr<npl_default_egress_ipv6_acl_sec_table_t> default_egress_ipv6_acl_sec_table[6];

std::shared_ptr<npl_destination_decoding_table_t> destination_decoding_table;

std::shared_ptr<npl_device_mode_table_t> device_mode_table;

std::shared_ptr<npl_dsp_l2_attributes_table_t> dsp_l2_attributes_table[6];

std::shared_ptr<npl_dsp_l3_attributes_table_t> dsp_l3_attributes_table[6];

std::shared_ptr<npl_dummy_dip_index_table_t> dummy_dip_index_table[6];

std::shared_ptr<npl_ecn_remark_static_table_t> ecn_remark_static_table[6];

std::shared_ptr<npl_egress_mac_ipv4_sec_acl_table_t> egress_mac_ipv4_sec_acl_table[6];

std::shared_ptr<npl_egress_nh_and_svi_direct0_table_t> egress_nh_and_svi_direct0_table[3];

std::shared_ptr<npl_egress_nh_and_svi_direct1_table_t> egress_nh_and_svi_direct1_table[3];

std::shared_ptr<npl_em_mp_table_t> em_mp_table;

std::shared_ptr<npl_em_pfc_cong_table_t> em_pfc_cong_table;

std::shared_ptr<npl_ene_byte_addition_static_table_t> ene_byte_addition_static_table[6];

std::shared_ptr<npl_ene_macro_code_tpid_profile_static_table_t> ene_macro_code_tpid_profile_static_table[6];

std::shared_ptr<npl_erpp_fabric_counters_offset_table_t> erpp_fabric_counters_offset_table[6];

std::shared_ptr<npl_erpp_fabric_counters_table_t> erpp_fabric_counters_table[6];

std::shared_ptr<npl_eth_meter_profile_mapping_table_t> eth_meter_profile_mapping_table[6];

std::shared_ptr<npl_eth_oam_set_da_mc2_static_table_t> eth_oam_set_da_mc2_static_table;

std::shared_ptr<npl_eth_oam_set_da_mc_static_table_t> eth_oam_set_da_mc_static_table;

std::shared_ptr<npl_eth_rtf_conf_set_mapping_table_t> eth_rtf_conf_set_mapping_table[6];

std::shared_ptr<npl_eve_byte_addition_static_table_t> eve_byte_addition_static_table[6];

std::shared_ptr<npl_eve_to_ethernet_ene_static_table_t> eve_to_ethernet_ene_static_table[6];

std::shared_ptr<npl_event_queue_table_t> event_queue_table[6];

std::shared_ptr<npl_external_aux_table_t> external_aux_table;

std::shared_ptr<npl_fabric_and_tm_header_size_static_table_t> fabric_and_tm_header_size_static_table[6];

std::shared_ptr<npl_fabric_header_ene_macro_table_t> fabric_header_ene_macro_table;

std::shared_ptr<npl_fabric_header_types_static_table_t> fabric_header_types_static_table[6];

std::shared_ptr<npl_fabric_headers_type_table_t> fabric_headers_type_table;

std::shared_ptr<npl_fabric_init_cfg_t> fabric_init_cfg;

std::shared_ptr<npl_fabric_npuh_size_calculation_static_table_t> fabric_npuh_size_calculation_static_table[6];

std::shared_ptr<npl_fabric_out_color_map_table_t> fabric_out_color_map_table;

std::shared_ptr<npl_fabric_rx_fwd_error_handling_counter_table_t> fabric_rx_fwd_error_handling_counter_table[6];

std::shared_ptr<npl_fabric_rx_fwd_error_handling_destination_table_t> fabric_rx_fwd_error_handling_destination_table[6];

std::shared_ptr<npl_fabric_rx_term_error_handling_counter_table_t> fabric_rx_term_error_handling_counter_table[6];

std::shared_ptr<npl_fabric_rx_term_error_handling_destination_table_t> fabric_rx_term_error_handling_destination_table[6];

std::shared_ptr<npl_fabric_scaled_mc_map_to_netork_slice_static_table_t> fabric_scaled_mc_map_to_netork_slice_static_table[6];

std::shared_ptr<npl_fabric_smcid_threshold_table_t> fabric_smcid_threshold_table[6];

std::shared_ptr<npl_fabric_term_error_checker_static_table_t> fabric_term_error_checker_static_table[6];

std::shared_ptr<npl_fabric_tm_headers_table_t> fabric_tm_headers_table;

std::shared_ptr<npl_fabric_transmit_error_checker_static_table_t> fabric_transmit_error_checker_static_table[6];

std::shared_ptr<npl_fe_broadcast_bmp_table_t> fe_broadcast_bmp_table;

std::shared_ptr<npl_fe_smcid_threshold_table_t> fe_smcid_threshold_table[6];

std::shared_ptr<npl_fe_smcid_to_mcid_table_t> fe_smcid_to_mcid_table[3];

std::shared_ptr<npl_fi_core_tcam_table_t> fi_core_tcam_table[7];

std::shared_ptr<npl_fi_macro_config_table_t> fi_macro_config_table[7];

std::shared_ptr<npl_filb_voq_mapping_t> filb_voq_mapping[6];

std::shared_ptr<npl_first_ene_static_table_t> first_ene_static_table[6];

std::shared_ptr<npl_frm_db_fabric_routing_table_t> frm_db_fabric_routing_table;

std::shared_ptr<npl_fwd_destination_to_tm_result_data_t> fwd_destination_to_tm_result_data;

std::shared_ptr<npl_fwd_type_to_ive_enable_table_t> fwd_type_to_ive_enable_table;

std::shared_ptr<npl_get_ecm_meter_ptr_table_t> get_ecm_meter_ptr_table;

std::shared_ptr<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_t> get_ingress_ptp_info_and_is_slp_dm_static_table[6];

std::shared_ptr<npl_get_l2_rtf_conf_set_and_init_stages_t> get_l2_rtf_conf_set_and_init_stages[6];

std::shared_ptr<npl_get_non_comp_mc_value_static_table_t> get_non_comp_mc_value_static_table[6];

std::shared_ptr<npl_gre_proto_static_table_t> gre_proto_static_table[6];

std::shared_ptr<npl_hmc_cgm_cgm_lut_table_t> hmc_cgm_cgm_lut_table;

std::shared_ptr<npl_hmc_cgm_profile_global_table_t> hmc_cgm_profile_global_table;

std::shared_ptr<npl_ibm_cmd_table_t> ibm_cmd_table;

std::shared_ptr<npl_ibm_mc_cmd_to_encap_data_table_t> ibm_mc_cmd_to_encap_data_table[6];

std::shared_ptr<npl_ibm_uc_cmd_to_encap_data_table_t> ibm_uc_cmd_to_encap_data_table[6];

std::shared_ptr<npl_ifgb_tc_lut_table_t> ifgb_tc_lut_table[6];

std::shared_ptr<npl_ingress_ip_qos_mapping_table_t> ingress_ip_qos_mapping_table[3];

std::shared_ptr<npl_ingress_rtf_eth_db1_160_f0_table_t> ingress_rtf_eth_db1_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_eth_db2_160_f0_table_t> ingress_rtf_eth_db2_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db1_160_f0_table_t> ingress_rtf_ipv4_db1_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db1_160_f1_table_t> ingress_rtf_ipv4_db1_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db1_320_f0_table_t> ingress_rtf_ipv4_db1_320_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db2_160_f0_table_t> ingress_rtf_ipv4_db2_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db2_160_f1_table_t> ingress_rtf_ipv4_db2_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db2_320_f0_table_t> ingress_rtf_ipv4_db2_320_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db3_160_f0_table_t> ingress_rtf_ipv4_db3_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db3_160_f1_table_t> ingress_rtf_ipv4_db3_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db3_320_f0_table_t> ingress_rtf_ipv4_db3_320_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db4_160_f0_table_t> ingress_rtf_ipv4_db4_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db4_160_f1_table_t> ingress_rtf_ipv4_db4_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv4_db4_320_f0_table_t> ingress_rtf_ipv4_db4_320_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db1_160_f0_table_t> ingress_rtf_ipv6_db1_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db1_160_f1_table_t> ingress_rtf_ipv6_db1_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db1_320_f0_table_t> ingress_rtf_ipv6_db1_320_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db2_160_f0_table_t> ingress_rtf_ipv6_db2_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db2_160_f1_table_t> ingress_rtf_ipv6_db2_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db2_320_f0_table_t> ingress_rtf_ipv6_db2_320_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db3_160_f0_table_t> ingress_rtf_ipv6_db3_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db3_160_f1_table_t> ingress_rtf_ipv6_db3_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db3_320_f0_table_t> ingress_rtf_ipv6_db3_320_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db4_160_f0_table_t> ingress_rtf_ipv6_db4_160_f0_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db4_160_f1_table_t> ingress_rtf_ipv6_db4_160_f1_table[6];

std::shared_ptr<npl_ingress_rtf_ipv6_db4_320_f0_table_t> ingress_rtf_ipv6_db4_320_f0_table[6];

std::shared_ptr<npl_inject_down_select_ene_static_table_t> inject_down_select_ene_static_table[6];

std::shared_ptr<npl_inject_down_tx_redirect_counter_table_t> inject_down_tx_redirect_counter_table[6];

std::shared_ptr<npl_inject_up_pif_ifg_init_data_table_t> inject_up_pif_ifg_init_data_table[6];

std::shared_ptr<npl_inject_up_ssp_init_data_table_t> inject_up_ssp_init_data_table[6];

std::shared_ptr<npl_inner_tpid_table_t> inner_tpid_table;

std::shared_ptr<npl_ip_fwd_header_mapping_to_ethtype_static_table_t> ip_fwd_header_mapping_to_ethtype_static_table[6];

std::shared_ptr<npl_ip_ingress_cmp_mcid_static_table_t> ip_ingress_cmp_mcid_static_table[6];

std::shared_ptr<npl_ip_mc_local_inject_type_static_table_t> ip_mc_local_inject_type_static_table[6];

std::shared_ptr<npl_ip_mc_next_macro_static_table_t> ip_mc_next_macro_static_table[6];

std::shared_ptr<npl_ip_meter_profile_mapping_table_t> ip_meter_profile_mapping_table[6];

std::shared_ptr<npl_ip_prefix_destination_table_t> ip_prefix_destination_table;

std::shared_ptr<npl_ip_relay_to_vni_table_t> ip_relay_to_vni_table[3];

std::shared_ptr<npl_ip_rx_global_counter_table_t> ip_rx_global_counter_table[6];

std::shared_ptr<npl_ip_ver_mc_static_table_t> ip_ver_mc_static_table[6];

std::shared_ptr<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_t> ipv4_acl_map_protocol_type_to_protocol_number_table[6];

std::shared_ptr<npl_ipv4_acl_sport_static_table_t> ipv4_acl_sport_static_table[6];

std::shared_ptr<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_t> ipv4_ip_tunnel_termination_dip_index_tt0_table[6];

std::shared_ptr<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_t> ipv4_ip_tunnel_termination_sip_dip_index_tt0_table[6];

std::shared_ptr<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_t> ipv4_ip_tunnel_termination_sip_dip_index_tt1_table[6];

std::shared_ptr<npl_ipv4_lpm_table_t> ipv4_lpm_table;

std::shared_ptr<npl_ipv4_lpts_table_t> ipv4_lpts_table[6];

std::shared_ptr<npl_ipv4_og_pcl_em_table_t> ipv4_og_pcl_em_table;

std::shared_ptr<npl_ipv4_og_pcl_lpm_table_t> ipv4_og_pcl_lpm_table;

std::shared_ptr<npl_ipv4_rtf_conf_set_mapping_table_t> ipv4_rtf_conf_set_mapping_table[6];

std::shared_ptr<npl_ipv4_vrf_dip_em_table_t> ipv4_vrf_dip_em_table;

std::shared_ptr<npl_ipv4_vrf_s_g_table_t> ipv4_vrf_s_g_table;

std::shared_ptr<npl_ipv6_acl_sport_static_table_t> ipv6_acl_sport_static_table[6];

std::shared_ptr<npl_ipv6_first_fragment_static_table_t> ipv6_first_fragment_static_table[6];

std::shared_ptr<npl_ipv6_lpm_table_t> ipv6_lpm_table;

std::shared_ptr<npl_ipv6_lpts_table_t> ipv6_lpts_table[6];

std::shared_ptr<npl_ipv6_mc_select_qos_id_t> ipv6_mc_select_qos_id[6];

std::shared_ptr<npl_ipv6_og_pcl_em_table_t> ipv6_og_pcl_em_table;

std::shared_ptr<npl_ipv6_og_pcl_lpm_table_t> ipv6_og_pcl_lpm_table;

std::shared_ptr<npl_ipv6_rtf_conf_set_mapping_table_t> ipv6_rtf_conf_set_mapping_table[6];

std::shared_ptr<npl_ipv6_sip_compression_table_t> ipv6_sip_compression_table;

std::shared_ptr<npl_ipv6_vrf_dip_em_table_t> ipv6_vrf_dip_em_table;

std::shared_ptr<npl_ipv6_vrf_s_g_table_t> ipv6_vrf_s_g_table;

std::shared_ptr<npl_is_pacific_b1_static_table_t> is_pacific_b1_static_table[6];

std::shared_ptr<npl_l2_dlp_table_t> l2_dlp_table[3];

std::shared_ptr<npl_l2_lp_profile_filter_table_t> l2_lp_profile_filter_table;

std::shared_ptr<npl_l2_lpts_ctrl_fields_static_table_t> l2_lpts_ctrl_fields_static_table[6];

std::shared_ptr<npl_l2_lpts_ip_fragment_static_table_t> l2_lpts_ip_fragment_static_table[6];

std::shared_ptr<npl_l2_lpts_ipv4_table_t> l2_lpts_ipv4_table[6];

std::shared_ptr<npl_l2_lpts_ipv6_table_t> l2_lpts_ipv6_table[6];

std::shared_ptr<npl_l2_lpts_mac_table_t> l2_lpts_mac_table[6];

std::shared_ptr<npl_l2_lpts_next_macro_static_table_t> l2_lpts_next_macro_static_table[6];

std::shared_ptr<npl_l2_lpts_protocol_table_t> l2_lpts_protocol_table;

std::shared_ptr<npl_l2_lpts_skip_p2p_static_table_t> l2_lpts_skip_p2p_static_table[6];

std::shared_ptr<npl_l2_termination_next_macro_static_table_t> l2_termination_next_macro_static_table[6];

std::shared_ptr<npl_l2_tunnel_term_next_macro_static_table_t> l2_tunnel_term_next_macro_static_table[6];

std::shared_ptr<npl_l3_dlp_p_counter_offset_table_t> l3_dlp_p_counter_offset_table;

std::shared_ptr<npl_l3_dlp_table_t> l3_dlp_table[3];

std::shared_ptr<npl_l3_termination_classify_ip_tunnels_table_t> l3_termination_classify_ip_tunnels_table[6];

std::shared_ptr<npl_l3_termination_next_macro_static_table_t> l3_termination_next_macro_static_table[6];

std::shared_ptr<npl_l3_tunnel_termination_next_macro_static_table_t> l3_tunnel_termination_next_macro_static_table[6];

std::shared_ptr<npl_l3_vxlan_overlay_sa_table_t> l3_vxlan_overlay_sa_table;

std::shared_ptr<npl_large_encap_global_lsp_prefix_table_t> large_encap_global_lsp_prefix_table[3];

std::shared_ptr<npl_large_encap_ip_tunnel_table_t> large_encap_ip_tunnel_table[3];

std::shared_ptr<npl_large_encap_mpls_he_no_ldp_table_t> large_encap_mpls_he_no_ldp_table[3];

std::shared_ptr<npl_large_encap_mpls_ldp_over_te_table_t> large_encap_mpls_ldp_over_te_table;

std::shared_ptr<npl_large_encap_te_he_tunnel_id_table_t> large_encap_te_he_tunnel_id_table[3];

std::shared_ptr<npl_learn_manager_cfg_max_learn_type_reg_t> learn_manager_cfg_max_learn_type_reg;

std::shared_ptr<npl_light_fi_fabric_table_t> light_fi_fabric_table[6];

std::shared_ptr<npl_light_fi_npu_base_table_t> light_fi_npu_base_table[6];

std::shared_ptr<npl_light_fi_npu_encap_table_t> light_fi_npu_encap_table[6];

std::shared_ptr<npl_light_fi_nw_0_table_t> light_fi_nw_0_table[6];

std::shared_ptr<npl_light_fi_nw_1_table_t> light_fi_nw_1_table[6];

std::shared_ptr<npl_light_fi_nw_2_table_t> light_fi_nw_2_table[6];

std::shared_ptr<npl_light_fi_nw_3_table_t> light_fi_nw_3_table[6];

std::shared_ptr<npl_light_fi_stages_cfg_table_t> light_fi_stages_cfg_table[6];

std::shared_ptr<npl_light_fi_tm_table_t> light_fi_tm_table[6];

std::shared_ptr<npl_link_relay_attributes_table_t> link_relay_attributes_table[6];

std::shared_ptr<npl_link_up_vector_t> link_up_vector;

std::shared_ptr<npl_lp_over_lag_table_t> lp_over_lag_table;

std::shared_ptr<npl_lpm_destination_prefix_map_table_t> lpm_destination_prefix_map_table;

std::shared_ptr<npl_lpts_2nd_lookup_table_t> lpts_2nd_lookup_table[6];

std::shared_ptr<npl_lpts_meter_table_t> lpts_meter_table[6];

std::shared_ptr<npl_lpts_og_application_table_t> lpts_og_application_table[6];

std::shared_ptr<npl_mac_af_npp_attributes_table_t> mac_af_npp_attributes_table[6];

std::shared_ptr<npl_mac_da_table_t> mac_da_table;

std::shared_ptr<npl_mac_ethernet_rate_limit_type_static_table_t> mac_ethernet_rate_limit_type_static_table[6];

std::shared_ptr<npl_mac_forwarding_table_t> mac_forwarding_table;

std::shared_ptr<npl_mac_mc_em_termination_attributes_table_t> mac_mc_em_termination_attributes_table[6];

std::shared_ptr<npl_mac_mc_tcam_termination_attributes_table_t> mac_mc_tcam_termination_attributes_table[6];

std::shared_ptr<npl_mac_qos_mapping_table_t> mac_qos_mapping_table[3];

std::shared_ptr<npl_mac_relay_g_ipv4_table_t> mac_relay_g_ipv4_table;

std::shared_ptr<npl_mac_relay_g_ipv6_table_t> mac_relay_g_ipv6_table;

std::shared_ptr<npl_mac_relay_to_vni_table_t> mac_relay_to_vni_table[3];

std::shared_ptr<npl_mac_termination_em_table_t> mac_termination_em_table[6];

std::shared_ptr<npl_mac_termination_next_macro_static_table_t> mac_termination_next_macro_static_table[6];

std::shared_ptr<npl_mac_termination_no_da_em_table_t> mac_termination_no_da_em_table[6];

std::shared_ptr<npl_mac_termination_tcam_table_t> mac_termination_tcam_table[6];

std::shared_ptr<npl_map_ene_subcode_to8bit_static_table_t> map_ene_subcode_to8bit_static_table[6];

std::shared_ptr<npl_map_inject_ccm_macro_static_table_t> map_inject_ccm_macro_static_table;

std::shared_ptr<npl_map_more_labels_static_table_t> map_more_labels_static_table[6];

std::shared_ptr<npl_map_recyle_tx_to_rx_data_on_pd_static_table_t> map_recyle_tx_to_rx_data_on_pd_static_table[6];

std::shared_ptr<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_t> map_tm_dp_ecn_to_wa_ecn_dp_static_table[6];

std::shared_ptr<npl_map_tx_punt_next_macro_static_table_t> map_tx_punt_next_macro_static_table[6];

std::shared_ptr<npl_map_tx_punt_rcy_next_macro_static_table_t> map_tx_punt_rcy_next_macro_static_table[6];

std::shared_ptr<npl_mc_bitmap_base_voq_lookup_table_t> mc_bitmap_base_voq_lookup_table;

std::shared_ptr<npl_mc_bitmap_tc_map_table_t> mc_bitmap_tc_map_table;

std::shared_ptr<npl_mc_copy_id_map_t> mc_copy_id_map[6];

std::shared_ptr<npl_mc_cud_is_wide_table_t> mc_cud_is_wide_table[6];

std::shared_ptr<npl_mc_em_db_t> mc_em_db;

std::shared_ptr<npl_mc_emdb_tc_map_table_t> mc_emdb_tc_map_table;

std::shared_ptr<npl_mc_fe_links_bmp_t> mc_fe_links_bmp;

std::shared_ptr<npl_mc_ibm_cud_mapping_table_t> mc_ibm_cud_mapping_table[6];

std::shared_ptr<npl_mc_slice_bitmap_table_t> mc_slice_bitmap_table[6];

std::shared_ptr<npl_meg_id_format_table_t> meg_id_format_table;

std::shared_ptr<npl_mep_address_prefix_table_t> mep_address_prefix_table;

std::shared_ptr<npl_mii_loopback_table_t> mii_loopback_table[6];

std::shared_ptr<npl_mirror_code_hw_table_t> mirror_code_hw_table;

std::shared_ptr<npl_mirror_egress_attributes_table_t> mirror_egress_attributes_table[6];

std::shared_ptr<npl_mirror_to_dsp_in_npu_soft_header_table_t> mirror_to_dsp_in_npu_soft_header_table;

std::shared_ptr<npl_mldp_protection_enabled_static_table_t> mldp_protection_enabled_static_table[6];

std::shared_ptr<npl_mldp_protection_table_t> mldp_protection_table[6];

std::shared_ptr<npl_mp_aux_data_table_t> mp_aux_data_table;

std::shared_ptr<npl_mp_data_table_t> mp_data_table;

std::shared_ptr<npl_mpls_encap_control_static_table_t> mpls_encap_control_static_table[6];

std::shared_ptr<npl_mpls_forwarding_table_t> mpls_forwarding_table;

std::shared_ptr<npl_mpls_header_offset_in_bytes_static_table_t> mpls_header_offset_in_bytes_static_table[6];

std::shared_ptr<npl_mpls_l3_lsp_static_table_t> mpls_l3_lsp_static_table[6];

std::shared_ptr<npl_mpls_labels_1_to_4_jump_offset_static_table_t> mpls_labels_1_to_4_jump_offset_static_table[6];

std::shared_ptr<npl_mpls_lsp_labels_config_static_table_t> mpls_lsp_labels_config_static_table[6];

std::shared_ptr<npl_mpls_qos_mapping_table_t> mpls_qos_mapping_table[3];

std::shared_ptr<npl_mpls_resolve_service_labels_static_table_t> mpls_resolve_service_labels_static_table[6];

std::shared_ptr<npl_mpls_termination_em0_table_t> mpls_termination_em0_table[6];

std::shared_ptr<npl_mpls_termination_em1_table_t> mpls_termination_em1_table[6];

std::shared_ptr<npl_mpls_vpn_enabled_static_table_t> mpls_vpn_enabled_static_table[6];

std::shared_ptr<npl_my_ipv4_table_t> my_ipv4_table[6];

std::shared_ptr<npl_native_ce_ptr_table_t> native_ce_ptr_table;

std::shared_ptr<npl_native_fec_table_t> native_fec_table;

std::shared_ptr<npl_native_fec_type_decoding_table_t> native_fec_type_decoding_table;

std::shared_ptr<npl_native_frr_table_t> native_frr_table;

std::shared_ptr<npl_native_frr_type_decoding_table_t> native_frr_type_decoding_table;

std::shared_ptr<npl_native_l2_lp_table_t> native_l2_lp_table;

std::shared_ptr<npl_native_l2_lp_type_decoding_table_t> native_l2_lp_type_decoding_table;

std::shared_ptr<npl_native_lb_group_size_table_t> native_lb_group_size_table;

std::shared_ptr<npl_native_lb_table_t> native_lb_table;

std::shared_ptr<npl_native_lb_type_decoding_table_t> native_lb_type_decoding_table;

std::shared_ptr<npl_native_lp_is_pbts_prefix_table_t> native_lp_is_pbts_prefix_table;

std::shared_ptr<npl_native_lp_pbts_map_table_t> native_lp_pbts_map_table[3];

std::shared_ptr<npl_native_protection_table_t> native_protection_table;

std::shared_ptr<npl_next_header_1_is_l4_over_ipv4_static_table_t> next_header_1_is_l4_over_ipv4_static_table[6];

std::shared_ptr<npl_nh_macro_code_to_id_l6_static_table_t> nh_macro_code_to_id_l6_static_table[6];

std::shared_ptr<npl_nhlfe_type_mapping_static_table_t> nhlfe_type_mapping_static_table[6];

std::shared_ptr<npl_null_rtf_next_macro_static_table_t> null_rtf_next_macro_static_table[6];

std::shared_ptr<npl_nw_smcid_threshold_table_t> nw_smcid_threshold_table[6];

std::shared_ptr<npl_oamp_drop_destination_static_table_t> oamp_drop_destination_static_table;

std::shared_ptr<npl_oamp_event_queue_table_t> oamp_event_queue_table[6];

std::shared_ptr<npl_oamp_redirect_get_counter_table_t> oamp_redirect_get_counter_table;

std::shared_ptr<npl_oamp_redirect_punt_eth_hdr_1_table_t> oamp_redirect_punt_eth_hdr_1_table;

std::shared_ptr<npl_oamp_redirect_punt_eth_hdr_2_table_t> oamp_redirect_punt_eth_hdr_2_table;

std::shared_ptr<npl_oamp_redirect_punt_eth_hdr_3_table_t> oamp_redirect_punt_eth_hdr_3_table;

std::shared_ptr<npl_oamp_redirect_punt_eth_hdr_4_table_t> oamp_redirect_punt_eth_hdr_4_table;

std::shared_ptr<npl_oamp_redirect_table_t> oamp_redirect_table;

std::shared_ptr<npl_obm_next_macro_static_table_t> obm_next_macro_static_table[6];

std::shared_ptr<npl_og_next_macro_static_table_t> og_next_macro_static_table[6];

std::shared_ptr<npl_outer_tpid_table_t> outer_tpid_table;

std::shared_ptr<npl_overlay_ipv4_sip_table_t> overlay_ipv4_sip_table[6];

std::shared_ptr<npl_pad_mtu_inj_check_static_table_t> pad_mtu_inj_check_static_table[6];

std::shared_ptr<npl_path_lb_type_decoding_table_t> path_lb_type_decoding_table;

std::shared_ptr<npl_path_lp_is_pbts_prefix_table_t> path_lp_is_pbts_prefix_table;

std::shared_ptr<npl_path_lp_pbts_map_table_t> path_lp_pbts_map_table[3];

std::shared_ptr<npl_path_lp_table_t> path_lp_table;

std::shared_ptr<npl_path_lp_type_decoding_table_t> path_lp_type_decoding_table;

std::shared_ptr<npl_path_protection_table_t> path_protection_table;

std::shared_ptr<npl_pdoq_oq_ifc_mapping_t> pdoq_oq_ifc_mapping[6];

std::shared_ptr<npl_pdvoq_slice_voq_properties_table_t> pdvoq_slice_voq_properties_table[6];

std::shared_ptr<npl_per_asbr_and_dpe_table_t> per_asbr_and_dpe_table;

std::shared_ptr<npl_per_pe_and_prefix_vpn_key_large_table_t> per_pe_and_prefix_vpn_key_large_table;

std::shared_ptr<npl_per_pe_and_vrf_vpn_key_large_table_t> per_pe_and_vrf_vpn_key_large_table;

std::shared_ptr<npl_per_port_destination_table_t> per_port_destination_table[6];

std::shared_ptr<npl_per_vrf_mpls_forwarding_table_t> per_vrf_mpls_forwarding_table;

std::shared_ptr<npl_pfc_destination_table_t> pfc_destination_table;

std::shared_ptr<npl_pfc_event_queue_table_t> pfc_event_queue_table[6];

std::shared_ptr<npl_pfc_filter_wd_table_t> pfc_filter_wd_table[6];

std::shared_ptr<npl_pfc_offset_from_vector_static_table_t> pfc_offset_from_vector_static_table;

std::shared_ptr<npl_pfc_ssp_slice_map_table_t> pfc_ssp_slice_map_table;

std::shared_ptr<npl_pfc_tc_latency_table_t> pfc_tc_latency_table;

std::shared_ptr<npl_pfc_tc_table_t> pfc_tc_table;

std::shared_ptr<npl_pfc_tc_wrap_latency_table_t> pfc_tc_wrap_latency_table;

std::shared_ptr<npl_pfc_vector_static_table_t> pfc_vector_static_table;

std::shared_ptr<npl_pin_start_offset_macros_t> pin_start_offset_macros;

std::shared_ptr<npl_pma_loopback_table_t> pma_loopback_table[6];

std::shared_ptr<npl_port_dspa_group_size_table_t> port_dspa_group_size_table;

std::shared_ptr<npl_port_dspa_table_t> port_dspa_table;

std::shared_ptr<npl_port_dspa_type_decoding_table_t> port_dspa_type_decoding_table;

std::shared_ptr<npl_port_npp_protection_table_t> port_npp_protection_table[6];

std::shared_ptr<npl_port_npp_protection_type_decoding_table_t> port_npp_protection_type_decoding_table;

std::shared_ptr<npl_port_protection_table_t> port_protection_table[6];

std::shared_ptr<npl_punt_ethertype_static_table_t> punt_ethertype_static_table[6];

std::shared_ptr<npl_punt_rcy_inject_header_ene_encap_table_t> punt_rcy_inject_header_ene_encap_table;

std::shared_ptr<npl_punt_select_nw_ene_static_table_t> punt_select_nw_ene_static_table[6];

std::shared_ptr<npl_punt_tunnel_transport_encap_table_t> punt_tunnel_transport_encap_table;

std::shared_ptr<npl_punt_tunnel_transport_extended_encap_table_t> punt_tunnel_transport_extended_encap_table;

std::shared_ptr<npl_punt_tunnel_transport_extended_encap_table2_t> punt_tunnel_transport_extended_encap_table2;

std::shared_ptr<npl_pwe_label_table_t> pwe_label_table[3];

std::shared_ptr<npl_pwe_to_l3_dest_table_t> pwe_to_l3_dest_table;

std::shared_ptr<npl_pwe_vpls_label_table_t> pwe_vpls_label_table[3];

std::shared_ptr<npl_pwe_vpls_tunnel_label_table_t> pwe_vpls_tunnel_label_table[3];

std::shared_ptr<npl_reassembly_source_port_map_table_t> reassembly_source_port_map_table[6];

std::shared_ptr<npl_recycle_override_table_t> recycle_override_table[6];

std::shared_ptr<npl_recycled_inject_up_info_table_t> recycled_inject_up_info_table[6];

std::shared_ptr<npl_redirect_destination_table_t> redirect_destination_table[6];

std::shared_ptr<npl_redirect_table_t> redirect_table;

std::shared_ptr<npl_resolution_pfc_select_table_t> resolution_pfc_select_table;

std::shared_ptr<npl_resolution_set_next_macro_table_t> resolution_set_next_macro_table;

std::shared_ptr<npl_rewrite_sa_prefix_index_table_t> rewrite_sa_prefix_index_table;

std::shared_ptr<npl_rmep_last_time_table_t> rmep_last_time_table;

std::shared_ptr<npl_rmep_state_table_t> rmep_state_table;

std::shared_ptr<npl_rpf_fec_access_map_table_t> rpf_fec_access_map_table;

std::shared_ptr<npl_rpf_fec_table_t> rpf_fec_table;

std::shared_ptr<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_t> rtf_conf_set_to_og_pcl_compress_bits_mapping_table[6];

std::shared_ptr<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_t> rtf_conf_set_to_og_pcl_ids_mapping_table[6];

std::shared_ptr<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_t> rtf_conf_set_to_post_fwd_stage_mapping_table[6];

std::shared_ptr<npl_rtf_next_macro_static_table_t> rtf_next_macro_static_table[6];

std::shared_ptr<npl_rx_counters_block_config_table_t> rx_counters_block_config_table;

std::shared_ptr<npl_rx_fwd_error_handling_counter_table_t> rx_fwd_error_handling_counter_table[6];

std::shared_ptr<npl_rx_fwd_error_handling_destination_table_t> rx_fwd_error_handling_destination_table[6];

std::shared_ptr<npl_rx_ip_p_counter_offset_static_table_t> rx_ip_p_counter_offset_static_table[6];

std::shared_ptr<npl_rx_map_npp_to_ssp_table_t> rx_map_npp_to_ssp_table[6];

std::shared_ptr<npl_rx_meter_block_meter_attribute_table_t> rx_meter_block_meter_attribute_table;

std::shared_ptr<npl_rx_meter_block_meter_profile_table_t> rx_meter_block_meter_profile_table;

std::shared_ptr<npl_rx_meter_block_meter_shaper_configuration_table_t> rx_meter_block_meter_shaper_configuration_table;

std::shared_ptr<npl_rx_meter_distributed_meter_profile_table_t> rx_meter_distributed_meter_profile_table;

std::shared_ptr<npl_rx_meter_exact_meter_decision_mapping_table_t> rx_meter_exact_meter_decision_mapping_table[6];

std::shared_ptr<npl_rx_meter_meter_profile_table_t> rx_meter_meter_profile_table;

std::shared_ptr<npl_rx_meter_meter_shaper_configuration_table_t> rx_meter_meter_shaper_configuration_table;

std::shared_ptr<npl_rx_meter_meters_attribute_table_t> rx_meter_meters_attribute_table;

std::shared_ptr<npl_rx_meter_rate_limiter_shaper_configuration_table_t> rx_meter_rate_limiter_shaper_configuration_table;

std::shared_ptr<npl_rx_meter_stat_meter_decision_mapping_table_t> rx_meter_stat_meter_decision_mapping_table[6];

std::shared_ptr<npl_rx_npu_to_tm_dest_table_t> rx_npu_to_tm_dest_table[6];

std::shared_ptr<npl_rx_obm_code_table_t> rx_obm_code_table[6];

std::shared_ptr<npl_rx_obm_punt_src_and_code_table_t> rx_obm_punt_src_and_code_table[6];

std::shared_ptr<npl_rx_redirect_code_ext_table_t> rx_redirect_code_ext_table[6];

std::shared_ptr<npl_rx_redirect_code_table_t> rx_redirect_code_table[6];

std::shared_ptr<npl_rx_redirect_next_macro_static_table_t> rx_redirect_next_macro_static_table[6];

std::shared_ptr<npl_rx_term_error_handling_counter_table_t> rx_term_error_handling_counter_table[6];

std::shared_ptr<npl_rx_term_error_handling_destination_table_t> rx_term_error_handling_destination_table[6];

std::shared_ptr<npl_rxpdr_dsp_lookup_table_t> rxpdr_dsp_lookup_table;

std::shared_ptr<npl_rxpdr_dsp_tc_map_t> rxpdr_dsp_tc_map;

std::shared_ptr<npl_sch_oqse_cfg_t> sch_oqse_cfg[6];

std::shared_ptr<npl_second_ene_static_table_t> second_ene_static_table[6];

std::shared_ptr<npl_select_inject_next_macro_static_table_t> select_inject_next_macro_static_table[6];

std::shared_ptr<npl_service_lp_attributes_table_t> service_lp_attributes_table[3];

std::shared_ptr<npl_service_mapping_em0_ac_port_table_t> service_mapping_em0_ac_port_table[6];

std::shared_ptr<npl_service_mapping_em0_ac_port_tag_table_t> service_mapping_em0_ac_port_tag_table[6];

std::shared_ptr<npl_service_mapping_em0_ac_port_tag_tag_table_t> service_mapping_em0_ac_port_tag_tag_table[6];

std::shared_ptr<npl_service_mapping_em0_pwe_tag_table_t> service_mapping_em0_pwe_tag_table[6];

std::shared_ptr<npl_service_mapping_em1_ac_port_tag_table_t> service_mapping_em1_ac_port_tag_table[6];

std::shared_ptr<npl_service_mapping_tcam_ac_port_table_t> service_mapping_tcam_ac_port_table[6];

std::shared_ptr<npl_service_mapping_tcam_ac_port_tag_table_t> service_mapping_tcam_ac_port_tag_table[6];

std::shared_ptr<npl_service_mapping_tcam_ac_port_tag_tag_table_t> service_mapping_tcam_ac_port_tag_tag_table[6];

std::shared_ptr<npl_service_mapping_tcam_pwe_tag_table_t> service_mapping_tcam_pwe_tag_table[6];

std::shared_ptr<npl_service_relay_attributes_table_t> service_relay_attributes_table;

std::shared_ptr<npl_set_ene_macro_and_bytes_to_remove_table_t> set_ene_macro_and_bytes_to_remove_table;

std::shared_ptr<npl_sgacl_table_t> sgacl_table[6];

std::shared_ptr<npl_sip_index_table_t> sip_index_table;

std::shared_ptr<npl_slice_modes_table_t> slice_modes_table;

std::shared_ptr<npl_slp_based_forwarding_table_t> slp_based_forwarding_table;

std::shared_ptr<npl_small_encap_mpls_he_asbr_table_t> small_encap_mpls_he_asbr_table[3];

std::shared_ptr<npl_small_encap_mpls_he_te_table_t> small_encap_mpls_he_te_table[3];

std::shared_ptr<npl_snoop_code_hw_table_t> snoop_code_hw_table;

std::shared_ptr<npl_snoop_table_t> snoop_table;

std::shared_ptr<npl_snoop_to_dsp_in_npu_soft_header_table_t> snoop_to_dsp_in_npu_soft_header_table;

std::shared_ptr<npl_source_pif_hw_table_t> source_pif_hw_table[6];

std::shared_ptr<npl_stage2_lb_group_size_table_t> stage2_lb_group_size_table;

std::shared_ptr<npl_stage2_lb_table_t> stage2_lb_table;

std::shared_ptr<npl_stage3_lb_group_size_table_t> stage3_lb_group_size_table;

std::shared_ptr<npl_stage3_lb_table_t> stage3_lb_table;

std::shared_ptr<npl_stage3_lb_type_decoding_table_t> stage3_lb_type_decoding_table;

std::shared_ptr<npl_svl_next_macro_static_table_t> svl_next_macro_static_table[6];

std::shared_ptr<npl_te_headend_lsp_counter_offset_table_t> te_headend_lsp_counter_offset_table;

std::shared_ptr<npl_termination_to_forwarding_fi_hardwired_table_t> termination_to_forwarding_fi_hardwired_table[6];

std::shared_ptr<npl_tm_ibm_cmd_to_destination_t> tm_ibm_cmd_to_destination;

std::shared_ptr<npl_ts_cmd_hw_static_table_t> ts_cmd_hw_static_table[6];

std::shared_ptr<npl_tunnel_dlp_p_counter_offset_table_t> tunnel_dlp_p_counter_offset_table[6];

std::shared_ptr<npl_tunnel_qos_static_table_t> tunnel_qos_static_table[6];

std::shared_ptr<npl_tx_counters_block_config_table_t> tx_counters_block_config_table;

std::shared_ptr<npl_tx_error_handling_counter_table_t> tx_error_handling_counter_table[6];

std::shared_ptr<npl_tx_punt_eth_encap_table_t> tx_punt_eth_encap_table;

std::shared_ptr<npl_tx_redirect_code_table_t> tx_redirect_code_table;

std::shared_ptr<npl_txpdr_mc_list_size_table_t> txpdr_mc_list_size_table[6];

std::shared_ptr<npl_txpdr_tc_map_table_t> txpdr_tc_map_table;

std::shared_ptr<npl_txpp_dlp_profile_table_t> txpp_dlp_profile_table[3];

std::shared_ptr<npl_txpp_encap_qos_mapping_table_t> txpp_encap_qos_mapping_table;

std::shared_ptr<npl_txpp_first_enc_type_to_second_enc_type_offset_t> txpp_first_enc_type_to_second_enc_type_offset;

std::shared_ptr<npl_txpp_fwd_header_type_is_l2_table_t> txpp_fwd_header_type_is_l2_table;

std::shared_ptr<npl_txpp_fwd_qos_mapping_table_t> txpp_fwd_qos_mapping_table;

std::shared_ptr<npl_txpp_initial_npe_macro_table_t> txpp_initial_npe_macro_table;

std::shared_ptr<npl_txpp_mapping_qos_tag_table_t> txpp_mapping_qos_tag_table[3];

std::shared_ptr<npl_uc_ibm_tc_map_table_t> uc_ibm_tc_map_table;

std::shared_ptr<npl_urpf_ipsa_dest_is_lpts_static_table_t> urpf_ipsa_dest_is_lpts_static_table[6];

std::shared_ptr<npl_vlan_edit_tpid1_profile_hw_table_t> vlan_edit_tpid1_profile_hw_table;

std::shared_ptr<npl_vlan_edit_tpid2_profile_hw_table_t> vlan_edit_tpid2_profile_hw_table;

std::shared_ptr<npl_vlan_format_table_t> vlan_format_table;

std::shared_ptr<npl_vni_table_t> vni_table[6];

std::shared_ptr<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_t> voq_cgm_slice_buffers_consumption_lut_for_enq_table[6];

std::shared_ptr<npl_voq_cgm_slice_dram_cgm_profile_table_t> voq_cgm_slice_dram_cgm_profile_table[6];

std::shared_ptr<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_t> voq_cgm_slice_pd_consumption_lut_for_enq_table[6];

std::shared_ptr<npl_voq_cgm_slice_profile_buff_region_thresholds_table_t> voq_cgm_slice_profile_buff_region_thresholds_table[6];

std::shared_ptr<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_t> voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table[6];

std::shared_ptr<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_t> voq_cgm_slice_profile_pkt_region_thresholds_table[6];

std::shared_ptr<npl_voq_cgm_slice_slice_cgm_profile_table_t> voq_cgm_slice_slice_cgm_profile_table[6];

std::shared_ptr<npl_vsid_table_t> vsid_table[6];

std::shared_ptr<npl_vxlan_l2_dlp_table_t> vxlan_l2_dlp_table[3];

std::shared_ptr<npl_inject_mact_ldb_to_output_lr_t> inject_mact_ldb_to_output_lr;

std::shared_ptr<npl_lr_filter_write_ptr_reg_t> lr_filter_write_ptr_reg;

std::shared_ptr<npl_lr_write_ptr_reg_t> lr_write_ptr_reg;


private:
la_device_id_t m_device_id;
};

} // namespace silicon_one
#endif
