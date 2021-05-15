
// This file has been automatically generated using nplc.py. Do not edit it manually.
// Version: 1.76.2_0.0.0.0 generated on devsrv15.leaba.local at 2021-05-12 16:09:15



#ifndef __NPL_TABLE_TRANSLATORS_H__
#define __NPL_TABLE_TRANSLATORS_H__

#include "nplapi/npl_table_types.h"
#include "nplapi_translator/npl_table_translator.h"
#include "nplapi_translator/npl_ternary_table_translator.h"
#include "nplapi_translator/npl_lpm_table_translator.h"

namespace silicon_one {
    
    /// table_translator for table: acl_map_fi_header_type_to_protocol_number_table
    
    typedef npl_table_translator<npl_acl_map_fi_header_type_to_protocol_number_table_key_t, npl_acl_map_fi_header_type_to_protocol_number_table_value_t> npl_acl_map_fi_header_type_to_protocol_number_table_table_translator_t;
    
    /// table_translator for table: additional_labels_table
    
    typedef npl_table_translator<npl_additional_labels_table_key_t, npl_additional_labels_table_value_t> npl_additional_labels_table_table_translator_t;
    
    /// table_translator for table: all_reachable_vector
    
    typedef npl_table_translator<npl_all_reachable_vector_key_t, npl_all_reachable_vector_value_t> npl_all_reachable_vector_table_translator_t;
    
    /// table_translator for table: bfd_desired_tx_interval_table
    
    typedef npl_table_translator<npl_bfd_desired_tx_interval_table_key_t, npl_bfd_desired_tx_interval_table_value_t> npl_bfd_desired_tx_interval_table_table_translator_t;
    
    /// table_translator for table: bfd_detection_multiple_table
    
    typedef npl_table_translator<npl_bfd_detection_multiple_table_key_t, npl_bfd_detection_multiple_table_value_t> npl_bfd_detection_multiple_table_table_translator_t;
    
    /// table_translator for table: bfd_event_queue_table
    
    typedef npl_table_translator<npl_bfd_event_queue_table_key_t, npl_bfd_event_queue_table_value_t> npl_bfd_event_queue_table_table_translator_t;
    
    /// table_translator for table: bfd_inject_inner_da_high_table
    
    typedef npl_table_translator<npl_bfd_inject_inner_da_high_table_key_t, npl_bfd_inject_inner_da_high_table_value_t> npl_bfd_inject_inner_da_high_table_table_translator_t;
    
    /// table_translator for table: bfd_inject_inner_da_low_table
    
    typedef npl_table_translator<npl_bfd_inject_inner_da_low_table_key_t, npl_bfd_inject_inner_da_low_table_value_t> npl_bfd_inject_inner_da_low_table_table_translator_t;
    
    /// table_translator for table: bfd_inject_inner_ethernet_header_static_table
    
    typedef npl_table_translator<npl_bfd_inject_inner_ethernet_header_static_table_key_t, npl_bfd_inject_inner_ethernet_header_static_table_value_t> npl_bfd_inject_inner_ethernet_header_static_table_table_translator_t;
    
    /// table_translator for table: bfd_inject_ttl_static_table
    
    typedef npl_table_translator<npl_bfd_inject_ttl_static_table_key_t, npl_bfd_inject_ttl_static_table_value_t> npl_bfd_inject_ttl_static_table_table_translator_t;
    
    /// table_translator for table: bfd_ipv6_sip_A_table
    
    typedef npl_table_translator<npl_bfd_ipv6_sip_A_table_key_t, npl_bfd_ipv6_sip_A_table_value_t> npl_bfd_ipv6_sip_A_table_table_translator_t;
    
    /// table_translator for table: bfd_ipv6_sip_B_table
    
    typedef npl_table_translator<npl_bfd_ipv6_sip_B_table_key_t, npl_bfd_ipv6_sip_B_table_value_t> npl_bfd_ipv6_sip_B_table_table_translator_t;
    
    /// table_translator for table: bfd_ipv6_sip_C_table
    
    typedef npl_table_translator<npl_bfd_ipv6_sip_C_table_key_t, npl_bfd_ipv6_sip_C_table_value_t> npl_bfd_ipv6_sip_C_table_table_translator_t;
    
    /// table_translator for table: bfd_ipv6_sip_D_table
    
    typedef npl_table_translator<npl_bfd_ipv6_sip_D_table_key_t, npl_bfd_ipv6_sip_D_table_value_t> npl_bfd_ipv6_sip_D_table_table_translator_t;
    
    /// table_translator for table: bfd_punt_encap_static_table
    
    typedef npl_table_translator<npl_bfd_punt_encap_static_table_key_t, npl_bfd_punt_encap_static_table_value_t> npl_bfd_punt_encap_static_table_table_translator_t;
    
    /// table_translator for table: bfd_required_tx_interval_table
    
    typedef npl_table_translator<npl_bfd_required_tx_interval_table_key_t, npl_bfd_required_tx_interval_table_value_t> npl_bfd_required_tx_interval_table_table_translator_t;
    
    /// table_translator for table: bfd_rx_table
    
    typedef npl_table_translator<npl_bfd_rx_table_key_t, npl_bfd_rx_table_value_t> npl_bfd_rx_table_table_translator_t;
    
    /// table_translator for table: bfd_set_inject_type_static_table
    
    typedef npl_table_translator<npl_bfd_set_inject_type_static_table_key_t, npl_bfd_set_inject_type_static_table_value_t> npl_bfd_set_inject_type_static_table_table_translator_t;
    
    /// table_translator for table: bfd_udp_port_map_static_table
    
    typedef npl_ternary_table_translator<npl_bfd_udp_port_map_static_table_key_t, npl_bfd_udp_port_map_static_table_value_t> npl_bfd_udp_port_map_static_table_table_translator_t;
    
    /// table_translator for table: bfd_udp_port_static_table
    
    typedef npl_table_translator<npl_bfd_udp_port_static_table_key_t, npl_bfd_udp_port_static_table_value_t> npl_bfd_udp_port_static_table_table_translator_t;
    
    /// table_translator for table: bitmap_oqg_map_table
    
    typedef npl_table_translator<npl_bitmap_oqg_map_table_key_t, npl_bitmap_oqg_map_table_value_t> npl_bitmap_oqg_map_table_table_translator_t;
    
    /// table_translator for table: bvn_tc_map_table
    
    typedef npl_table_translator<npl_bvn_tc_map_table_key_t, npl_bvn_tc_map_table_value_t> npl_bvn_tc_map_table_table_translator_t;
    
    /// table_translator for table: calc_checksum_enable_table
    
    typedef npl_table_translator<npl_calc_checksum_enable_table_key_t, npl_calc_checksum_enable_table_value_t> npl_calc_checksum_enable_table_table_translator_t;
    
    /// table_translator for table: ccm_flags_table
    
    typedef npl_table_translator<npl_ccm_flags_table_key_t, npl_ccm_flags_table_value_t> npl_ccm_flags_table_table_translator_t;
    
    /// table_translator for table: cif2npa_c_lri_macro
    
    typedef npl_table_translator<npl_cif2npa_c_lri_macro_key_t, npl_cif2npa_c_lri_macro_value_t> npl_cif2npa_c_lri_macro_table_translator_t;
    
    /// table_translator for table: cif2npa_c_mps_macro
    
    typedef npl_table_translator<npl_cif2npa_c_mps_macro_key_t, npl_cif2npa_c_mps_macro_value_t> npl_cif2npa_c_mps_macro_table_translator_t;
    
    /// table_translator for table: counters_block_config_table
    
    typedef npl_table_translator<npl_counters_block_config_table_key_t, npl_counters_block_config_table_value_t> npl_counters_block_config_table_table_translator_t;
    
    /// table_translator for table: counters_voq_block_map_table
    
    typedef npl_table_translator<npl_counters_voq_block_map_table_key_t, npl_counters_voq_block_map_table_value_t> npl_counters_voq_block_map_table_table_translator_t;
    
    /// table_translator for table: cud_is_multicast_bitmap
    
    typedef npl_table_translator<npl_cud_is_multicast_bitmap_key_t, npl_cud_is_multicast_bitmap_value_t> npl_cud_is_multicast_bitmap_table_translator_t;
    
    /// table_translator for table: cud_narrow_hw_table
    
    typedef npl_table_translator<npl_cud_narrow_hw_table_key_t, npl_cud_narrow_hw_table_value_t> npl_cud_narrow_hw_table_table_translator_t;
    
    /// table_translator for table: cud_wide_hw_table
    
    typedef npl_table_translator<npl_cud_wide_hw_table_key_t, npl_cud_wide_hw_table_value_t> npl_cud_wide_hw_table_table_translator_t;
    
    /// table_translator for table: default_egress_ipv4_sec_acl_table
    
    typedef npl_ternary_table_translator<npl_default_egress_ipv4_sec_acl_table_key_t, npl_default_egress_ipv4_sec_acl_table_value_t> npl_default_egress_ipv4_sec_acl_table_table_translator_t;
    
    /// table_translator for table: default_egress_ipv6_acl_sec_table
    
    typedef npl_ternary_table_translator<npl_default_egress_ipv6_acl_sec_table_key_t, npl_default_egress_ipv6_acl_sec_table_value_t> npl_default_egress_ipv6_acl_sec_table_table_translator_t;
    
    /// table_translator for table: dest_slice_voq_map_table
    
    typedef npl_table_translator<npl_dest_slice_voq_map_table_key_t, npl_dest_slice_voq_map_table_value_t> npl_dest_slice_voq_map_table_table_translator_t;
    
    /// table_translator for table: destination_decoding_table
    
    typedef npl_table_translator<npl_destination_decoding_table_key_t, npl_destination_decoding_table_value_t> npl_destination_decoding_table_table_translator_t;
    
    /// table_translator for table: device_mode_table
    
    typedef npl_table_translator<npl_device_mode_table_key_t, npl_device_mode_table_value_t> npl_device_mode_table_table_translator_t;
    
    /// table_translator for table: dsp_l2_attributes_table
    
    typedef npl_table_translator<npl_dsp_l2_attributes_table_key_t, npl_dsp_l2_attributes_table_value_t> npl_dsp_l2_attributes_table_table_translator_t;
    
    /// table_translator for table: dsp_l3_attributes_table
    
    typedef npl_table_translator<npl_dsp_l3_attributes_table_key_t, npl_dsp_l3_attributes_table_value_t> npl_dsp_l3_attributes_table_table_translator_t;
    
    /// table_translator for table: dummy_dip_index_table
    
    typedef npl_table_translator<npl_dummy_dip_index_table_key_t, npl_dummy_dip_index_table_value_t> npl_dummy_dip_index_table_table_translator_t;
    
    /// table_translator for table: ecn_remark_static_table
    
    typedef npl_ternary_table_translator<npl_ecn_remark_static_table_key_t, npl_ecn_remark_static_table_value_t> npl_ecn_remark_static_table_table_translator_t;
    
    /// table_translator for table: egress_mac_ipv4_sec_acl_table
    
    typedef npl_ternary_table_translator<npl_egress_mac_ipv4_sec_acl_table_key_t, npl_egress_mac_ipv4_sec_acl_table_value_t> npl_egress_mac_ipv4_sec_acl_table_table_translator_t;
    
    /// table_translator for table: egress_nh_and_svi_direct0_table
    
    typedef npl_table_translator<npl_egress_nh_and_svi_direct0_table_key_t, npl_egress_nh_and_svi_direct0_table_value_t> npl_egress_nh_and_svi_direct0_table_table_translator_t;
    
    /// table_translator for table: egress_nh_and_svi_direct1_table
    
    typedef npl_table_translator<npl_egress_nh_and_svi_direct1_table_key_t, npl_egress_nh_and_svi_direct1_table_value_t> npl_egress_nh_and_svi_direct1_table_table_translator_t;
    
    /// table_translator for table: em_mp_table
    
    typedef npl_table_translator<npl_em_mp_table_key_t, npl_em_mp_table_value_t> npl_em_mp_table_table_translator_t;
    
    /// table_translator for table: em_pfc_cong_table
    
    typedef npl_table_translator<npl_em_pfc_cong_table_key_t, npl_em_pfc_cong_table_value_t> npl_em_pfc_cong_table_table_translator_t;
    
    /// table_translator for table: ene_byte_addition_static_table
    
    typedef npl_ternary_table_translator<npl_ene_byte_addition_static_table_key_t, npl_ene_byte_addition_static_table_value_t> npl_ene_byte_addition_static_table_table_translator_t;
    
    /// table_translator for table: ene_macro_code_tpid_profile_static_table
    
    typedef npl_table_translator<npl_ene_macro_code_tpid_profile_static_table_key_t, npl_ene_macro_code_tpid_profile_static_table_value_t> npl_ene_macro_code_tpid_profile_static_table_table_translator_t;
    
    /// table_translator for table: erpp_fabric_counters_offset_table
    
    typedef npl_ternary_table_translator<npl_erpp_fabric_counters_offset_table_key_t, npl_erpp_fabric_counters_offset_table_value_t> npl_erpp_fabric_counters_offset_table_table_translator_t;
    
    /// table_translator for table: erpp_fabric_counters_table
    
    typedef npl_ternary_table_translator<npl_erpp_fabric_counters_table_key_t, npl_erpp_fabric_counters_table_value_t> npl_erpp_fabric_counters_table_table_translator_t;
    
    /// table_translator for table: eth_meter_profile_mapping_table
    
    typedef npl_table_translator<npl_eth_meter_profile_mapping_table_key_t, npl_eth_meter_profile_mapping_table_value_t> npl_eth_meter_profile_mapping_table_table_translator_t;
    
    /// table_translator for table: eth_oam_set_da_mc2_static_table
    
    typedef npl_table_translator<npl_eth_oam_set_da_mc2_static_table_key_t, npl_eth_oam_set_da_mc2_static_table_value_t> npl_eth_oam_set_da_mc2_static_table_table_translator_t;
    
    /// table_translator for table: eth_oam_set_da_mc_static_table
    
    typedef npl_table_translator<npl_eth_oam_set_da_mc_static_table_key_t, npl_eth_oam_set_da_mc_static_table_value_t> npl_eth_oam_set_da_mc_static_table_table_translator_t;
    
    /// table_translator for table: eth_rtf_conf_set_mapping_table
    
    typedef npl_table_translator<npl_eth_rtf_conf_set_mapping_table_key_t, npl_eth_rtf_conf_set_mapping_table_value_t> npl_eth_rtf_conf_set_mapping_table_table_translator_t;
    
    /// table_translator for table: eve_byte_addition_static_table
    
    typedef npl_table_translator<npl_eve_byte_addition_static_table_key_t, npl_eve_byte_addition_static_table_value_t> npl_eve_byte_addition_static_table_table_translator_t;
    
    /// table_translator for table: eve_to_ethernet_ene_static_table
    
    typedef npl_table_translator<npl_eve_to_ethernet_ene_static_table_key_t, npl_eve_to_ethernet_ene_static_table_value_t> npl_eve_to_ethernet_ene_static_table_table_translator_t;
    
    /// table_translator for table: event_queue_table
    
    typedef npl_table_translator<npl_event_queue_table_key_t, npl_event_queue_table_value_t> npl_event_queue_table_table_translator_t;
    
    /// table_translator for table: external_aux_table
    
    typedef npl_table_translator<npl_external_aux_table_key_t, npl_external_aux_table_value_t> npl_external_aux_table_table_translator_t;
    
    /// table_translator for table: fabric_and_tm_header_size_static_table
    
    typedef npl_ternary_table_translator<npl_fabric_and_tm_header_size_static_table_key_t, npl_fabric_and_tm_header_size_static_table_value_t> npl_fabric_and_tm_header_size_static_table_table_translator_t;
    
    /// table_translator for table: fabric_header_ene_macro_table
    
    typedef npl_ternary_table_translator<npl_fabric_header_ene_macro_table_key_t, npl_fabric_header_ene_macro_table_value_t> npl_fabric_header_ene_macro_table_table_translator_t;
    
    /// table_translator for table: fabric_header_types_static_table
    
    typedef npl_table_translator<npl_fabric_header_types_static_table_key_t, npl_fabric_header_types_static_table_value_t> npl_fabric_header_types_static_table_table_translator_t;
    
    /// table_translator for table: fabric_headers_type_table
    
    typedef npl_ternary_table_translator<npl_fabric_headers_type_table_key_t, npl_fabric_headers_type_table_value_t> npl_fabric_headers_type_table_table_translator_t;
    
    /// table_translator for table: fabric_init_cfg
    
    typedef npl_ternary_table_translator<npl_fabric_init_cfg_key_t, npl_fabric_init_cfg_value_t> npl_fabric_init_cfg_table_translator_t;
    
    /// table_translator for table: fabric_npuh_size_calculation_static_table
    
    typedef npl_ternary_table_translator<npl_fabric_npuh_size_calculation_static_table_key_t, npl_fabric_npuh_size_calculation_static_table_value_t> npl_fabric_npuh_size_calculation_static_table_table_translator_t;
    
    /// table_translator for table: fabric_out_color_map_table
    
    typedef npl_ternary_table_translator<npl_fabric_out_color_map_table_key_t, npl_fabric_out_color_map_table_value_t> npl_fabric_out_color_map_table_table_translator_t;
    
    /// table_translator for table: fabric_rx_fwd_error_handling_counter_table
    
    typedef npl_table_translator<npl_fabric_rx_fwd_error_handling_counter_table_key_t, npl_fabric_rx_fwd_error_handling_counter_table_value_t> npl_fabric_rx_fwd_error_handling_counter_table_table_translator_t;
    
    /// table_translator for table: fabric_rx_fwd_error_handling_destination_table
    
    typedef npl_table_translator<npl_fabric_rx_fwd_error_handling_destination_table_key_t, npl_fabric_rx_fwd_error_handling_destination_table_value_t> npl_fabric_rx_fwd_error_handling_destination_table_table_translator_t;
    
    /// table_translator for table: fabric_rx_term_error_handling_counter_table
    
    typedef npl_table_translator<npl_fabric_rx_term_error_handling_counter_table_key_t, npl_fabric_rx_term_error_handling_counter_table_value_t> npl_fabric_rx_term_error_handling_counter_table_table_translator_t;
    
    /// table_translator for table: fabric_rx_term_error_handling_destination_table
    
    typedef npl_table_translator<npl_fabric_rx_term_error_handling_destination_table_key_t, npl_fabric_rx_term_error_handling_destination_table_value_t> npl_fabric_rx_term_error_handling_destination_table_table_translator_t;
    
    /// table_translator for table: fabric_scaled_mc_map_to_netork_slice_static_table
    
    typedef npl_table_translator<npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t> npl_fabric_scaled_mc_map_to_netork_slice_static_table_table_translator_t;
    
    /// table_translator for table: fabric_smcid_threshold_table
    
    typedef npl_table_translator<npl_fabric_smcid_threshold_table_key_t, npl_fabric_smcid_threshold_table_value_t> npl_fabric_smcid_threshold_table_table_translator_t;
    
    /// table_translator for table: fabric_term_error_checker_static_table
    
    typedef npl_ternary_table_translator<npl_fabric_term_error_checker_static_table_key_t, npl_fabric_term_error_checker_static_table_value_t> npl_fabric_term_error_checker_static_table_table_translator_t;
    
    /// table_translator for table: fabric_tm_headers_table
    
    typedef npl_table_translator<npl_fabric_tm_headers_table_key_t, npl_fabric_tm_headers_table_value_t> npl_fabric_tm_headers_table_table_translator_t;
    
    /// table_translator for table: fabric_transmit_error_checker_static_table
    
    typedef npl_ternary_table_translator<npl_fabric_transmit_error_checker_static_table_key_t, npl_fabric_transmit_error_checker_static_table_value_t> npl_fabric_transmit_error_checker_static_table_table_translator_t;
    
    /// table_translator for table: fb_link_2_link_bundle_table
    
    typedef npl_table_translator<npl_fb_link_2_link_bundle_table_key_t, npl_fb_link_2_link_bundle_table_value_t> npl_fb_link_2_link_bundle_table_table_translator_t;
    
    /// table_translator for table: fe_broadcast_bmp_table
    
    typedef npl_table_translator<npl_fe_broadcast_bmp_table_key_t, npl_fe_broadcast_bmp_table_value_t> npl_fe_broadcast_bmp_table_table_translator_t;
    
    /// table_translator for table: fe_rlb_uc_tx_fb_link_to_oq_map_table
    
    typedef npl_table_translator<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t> npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_table_translator_t;
    
    /// table_translator for table: fe_smcid_threshold_table
    
    typedef npl_table_translator<npl_fe_smcid_threshold_table_key_t, npl_fe_smcid_threshold_table_value_t> npl_fe_smcid_threshold_table_table_translator_t;
    
    /// table_translator for table: fe_smcid_to_mcid_table
    
    typedef npl_table_translator<npl_fe_smcid_to_mcid_table_key_t, npl_fe_smcid_to_mcid_table_value_t> npl_fe_smcid_to_mcid_table_table_translator_t;
    
    /// table_translator for table: fe_uc_link_bundle_desc_table
    
    typedef npl_table_translator<npl_fe_uc_link_bundle_desc_table_key_t, npl_fe_uc_link_bundle_desc_table_value_t> npl_fe_uc_link_bundle_desc_table_table_translator_t;
    
    /// table_translator for table: fi_core_tcam_table
    
    typedef npl_ternary_table_translator<npl_fi_core_tcam_table_key_t, npl_fi_core_tcam_table_value_t> npl_fi_core_tcam_table_table_translator_t;
    
    /// table_translator for table: fi_macro_config_table
    
    typedef npl_table_translator<npl_fi_macro_config_table_key_t, npl_fi_macro_config_table_value_t> npl_fi_macro_config_table_table_translator_t;
    
    /// table_translator for table: filb_voq_mapping
    
    typedef npl_table_translator<npl_filb_voq_mapping_key_t, npl_filb_voq_mapping_value_t> npl_filb_voq_mapping_table_translator_t;
    
    /// table_translator for table: first_ene_static_table
    
    typedef npl_table_translator<npl_first_ene_static_table_key_t, npl_first_ene_static_table_value_t> npl_first_ene_static_table_table_translator_t;
    
    /// table_translator for table: frm_db_fabric_routing_table
    
    typedef npl_table_translator<npl_frm_db_fabric_routing_table_key_t, npl_frm_db_fabric_routing_table_value_t> npl_frm_db_fabric_routing_table_table_translator_t;
    
    /// table_translator for table: fwd_destination_to_tm_result_data
    
    typedef npl_table_translator<npl_fwd_destination_to_tm_result_data_key_t, npl_fwd_destination_to_tm_result_data_value_t> npl_fwd_destination_to_tm_result_data_table_translator_t;
    
    /// table_translator for table: fwd_type_to_ive_enable_table
    
    typedef npl_table_translator<npl_fwd_type_to_ive_enable_table_key_t, npl_fwd_type_to_ive_enable_table_value_t> npl_fwd_type_to_ive_enable_table_table_translator_t;
    
    /// table_translator for table: get_ecm_meter_ptr_table
    
    typedef npl_table_translator<npl_get_ecm_meter_ptr_table_key_t, npl_get_ecm_meter_ptr_table_value_t> npl_get_ecm_meter_ptr_table_table_translator_t;
    
    /// table_translator for table: get_ingress_ptp_info_and_is_slp_dm_static_table
    
    typedef npl_table_translator<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t> npl_get_ingress_ptp_info_and_is_slp_dm_static_table_table_translator_t;
    
    /// table_translator for table: get_l2_rtf_conf_set_and_init_stages
    
    typedef npl_table_translator<npl_get_l2_rtf_conf_set_and_init_stages_key_t, npl_get_l2_rtf_conf_set_and_init_stages_value_t> npl_get_l2_rtf_conf_set_and_init_stages_table_translator_t;
    
    /// table_translator for table: get_non_comp_mc_value_static_table
    
    typedef npl_table_translator<npl_get_non_comp_mc_value_static_table_key_t, npl_get_non_comp_mc_value_static_table_value_t> npl_get_non_comp_mc_value_static_table_table_translator_t;
    
    /// table_translator for table: gre_proto_static_table
    
    typedef npl_table_translator<npl_gre_proto_static_table_key_t, npl_gre_proto_static_table_value_t> npl_gre_proto_static_table_table_translator_t;
    
    /// table_translator for table: hmc_cgm_cgm_lut_table
    
    typedef npl_table_translator<npl_hmc_cgm_cgm_lut_table_key_t, npl_hmc_cgm_cgm_lut_table_value_t> npl_hmc_cgm_cgm_lut_table_table_translator_t;
    
    /// table_translator for table: hmc_cgm_profile_global_table
    
    typedef npl_table_translator<npl_hmc_cgm_profile_global_table_key_t, npl_hmc_cgm_profile_global_table_value_t> npl_hmc_cgm_profile_global_table_table_translator_t;
    
    /// table_translator for table: ibm_cmd_table
    
    typedef npl_table_translator<npl_ibm_cmd_table_key_t, npl_ibm_cmd_table_value_t> npl_ibm_cmd_table_table_translator_t;
    
    /// table_translator for table: ibm_mc_cmd_to_encap_data_table
    
    typedef npl_table_translator<npl_ibm_mc_cmd_to_encap_data_table_key_t, npl_ibm_mc_cmd_to_encap_data_table_value_t> npl_ibm_mc_cmd_to_encap_data_table_table_translator_t;
    
    /// table_translator for table: ibm_uc_cmd_to_encap_data_table
    
    typedef npl_table_translator<npl_ibm_uc_cmd_to_encap_data_table_key_t, npl_ibm_uc_cmd_to_encap_data_table_value_t> npl_ibm_uc_cmd_to_encap_data_table_table_translator_t;
    
    /// table_translator for table: ifgb_tc_lut_table
    
    typedef npl_table_translator<npl_ifgb_tc_lut_table_key_t, npl_ifgb_tc_lut_table_value_t> npl_ifgb_tc_lut_table_table_translator_t;
    
    /// table_translator for table: ingress_ip_qos_mapping_table
    
    typedef npl_table_translator<npl_ingress_ip_qos_mapping_table_key_t, npl_ingress_ip_qos_mapping_table_value_t> npl_ingress_ip_qos_mapping_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_eth_db1_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_eth_db1_160_f0_table_key_t, npl_ingress_rtf_eth_db1_160_f0_table_value_t> npl_ingress_rtf_eth_db1_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_eth_db2_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_eth_db2_160_f0_table_key_t, npl_ingress_rtf_eth_db2_160_f0_table_value_t> npl_ingress_rtf_eth_db2_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db1_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db1_160_f0_table_key_t, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t> npl_ingress_rtf_ipv4_db1_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db1_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db1_160_f1_table_key_t, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t> npl_ingress_rtf_ipv4_db1_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db1_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db1_320_f0_table_key_t, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t> npl_ingress_rtf_ipv4_db1_320_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db2_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db2_160_f0_table_key_t, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t> npl_ingress_rtf_ipv4_db2_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db2_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db2_160_f1_table_key_t, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t> npl_ingress_rtf_ipv4_db2_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db2_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db2_320_f0_table_key_t, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t> npl_ingress_rtf_ipv4_db2_320_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db3_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db3_160_f0_table_key_t, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t> npl_ingress_rtf_ipv4_db3_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db3_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db3_160_f1_table_key_t, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t> npl_ingress_rtf_ipv4_db3_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db3_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db3_320_f0_table_key_t, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t> npl_ingress_rtf_ipv4_db3_320_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db4_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db4_160_f0_table_key_t, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t> npl_ingress_rtf_ipv4_db4_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db4_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db4_160_f1_table_key_t, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t> npl_ingress_rtf_ipv4_db4_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv4_db4_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv4_db4_320_f0_table_key_t, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t> npl_ingress_rtf_ipv4_db4_320_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db1_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db1_160_f0_table_key_t, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t> npl_ingress_rtf_ipv6_db1_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db1_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db1_160_f1_table_key_t, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t> npl_ingress_rtf_ipv6_db1_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db1_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db1_320_f0_table_key_t, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t> npl_ingress_rtf_ipv6_db1_320_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db2_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db2_160_f0_table_key_t, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t> npl_ingress_rtf_ipv6_db2_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db2_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db2_160_f1_table_key_t, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t> npl_ingress_rtf_ipv6_db2_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db2_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db2_320_f0_table_key_t, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t> npl_ingress_rtf_ipv6_db2_320_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db3_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db3_160_f0_table_key_t, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t> npl_ingress_rtf_ipv6_db3_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db3_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db3_160_f1_table_key_t, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t> npl_ingress_rtf_ipv6_db3_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db3_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db3_320_f0_table_key_t, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t> npl_ingress_rtf_ipv6_db3_320_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db4_160_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db4_160_f0_table_key_t, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t> npl_ingress_rtf_ipv6_db4_160_f0_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db4_160_f1_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db4_160_f1_table_key_t, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t> npl_ingress_rtf_ipv6_db4_160_f1_table_table_translator_t;
    
    /// table_translator for table: ingress_rtf_ipv6_db4_320_f0_table
    
    typedef npl_ternary_table_translator<npl_ingress_rtf_ipv6_db4_320_f0_table_key_t, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t> npl_ingress_rtf_ipv6_db4_320_f0_table_table_translator_t;
    
    /// table_translator for table: inject_down_select_ene_static_table
    
    typedef npl_ternary_table_translator<npl_inject_down_select_ene_static_table_key_t, npl_inject_down_select_ene_static_table_value_t> npl_inject_down_select_ene_static_table_table_translator_t;
    
    /// table_translator for table: inject_down_tx_redirect_counter_table
    
    typedef npl_table_translator<npl_inject_down_tx_redirect_counter_table_key_t, npl_inject_down_tx_redirect_counter_table_value_t> npl_inject_down_tx_redirect_counter_table_table_translator_t;
    
    /// table_translator for table: inject_mact_ldb_to_output_lr
    
    typedef npl_table_translator<npl_inject_mact_ldb_to_output_lr_key_t, npl_inject_mact_ldb_to_output_lr_value_t> npl_inject_mact_ldb_to_output_lr_table_translator_t;
    
    /// table_translator for table: inject_up_pif_ifg_init_data_table
    
    typedef npl_table_translator<npl_inject_up_pif_ifg_init_data_table_key_t, npl_inject_up_pif_ifg_init_data_table_value_t> npl_inject_up_pif_ifg_init_data_table_table_translator_t;
    
    /// table_translator for table: inject_up_ssp_init_data_table
    
    typedef npl_table_translator<npl_inject_up_ssp_init_data_table_key_t, npl_inject_up_ssp_init_data_table_value_t> npl_inject_up_ssp_init_data_table_table_translator_t;
    
    /// table_translator for table: inner_tpid_table
    
    typedef npl_table_translator<npl_inner_tpid_table_key_t, npl_inner_tpid_table_value_t> npl_inner_tpid_table_table_translator_t;
    
    /// table_translator for table: ip_fwd_header_mapping_to_ethtype_static_table
    
    typedef npl_table_translator<npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t> npl_ip_fwd_header_mapping_to_ethtype_static_table_table_translator_t;
    
    /// table_translator for table: ip_ingress_cmp_mcid_static_table
    
    typedef npl_ternary_table_translator<npl_ip_ingress_cmp_mcid_static_table_key_t, npl_ip_ingress_cmp_mcid_static_table_value_t> npl_ip_ingress_cmp_mcid_static_table_table_translator_t;
    
    /// table_translator for table: ip_mc_local_inject_type_static_table
    
    typedef npl_table_translator<npl_ip_mc_local_inject_type_static_table_key_t, npl_ip_mc_local_inject_type_static_table_value_t> npl_ip_mc_local_inject_type_static_table_table_translator_t;
    
    /// table_translator for table: ip_mc_next_macro_static_table
    
    typedef npl_table_translator<npl_ip_mc_next_macro_static_table_key_t, npl_ip_mc_next_macro_static_table_value_t> npl_ip_mc_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: ip_meter_profile_mapping_table
    
    typedef npl_table_translator<npl_ip_meter_profile_mapping_table_key_t, npl_ip_meter_profile_mapping_table_value_t> npl_ip_meter_profile_mapping_table_table_translator_t;
    
    /// table_translator for table: ip_prefix_destination_table
    
    typedef npl_table_translator<npl_ip_prefix_destination_table_key_t, npl_ip_prefix_destination_table_value_t> npl_ip_prefix_destination_table_table_translator_t;
    
    /// table_translator for table: ip_relay_to_vni_table
    
    typedef npl_table_translator<npl_ip_relay_to_vni_table_key_t, npl_ip_relay_to_vni_table_value_t> npl_ip_relay_to_vni_table_table_translator_t;
    
    /// table_translator for table: ip_rx_global_counter_table
    
    typedef npl_table_translator<npl_ip_rx_global_counter_table_key_t, npl_ip_rx_global_counter_table_value_t> npl_ip_rx_global_counter_table_table_translator_t;
    
    /// table_translator for table: ip_ver_mc_static_table
    
    typedef npl_ternary_table_translator<npl_ip_ver_mc_static_table_key_t, npl_ip_ver_mc_static_table_value_t> npl_ip_ver_mc_static_table_table_translator_t;
    
    /// table_translator for table: ipv4_acl_map_protocol_type_to_protocol_number_table
    
    typedef npl_ternary_table_translator<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t> npl_ipv4_acl_map_protocol_type_to_protocol_number_table_table_translator_t;
    
    /// table_translator for table: ipv4_acl_sport_static_table
    
    typedef npl_table_translator<npl_ipv4_acl_sport_static_table_key_t, npl_ipv4_acl_sport_static_table_value_t> npl_ipv4_acl_sport_static_table_table_translator_t;
    
    /// table_translator for table: ipv4_ip_tunnel_termination_dip_index_tt0_table
    
    typedef npl_table_translator<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t> npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_table_translator_t;
    
    /// table_translator for table: ipv4_ip_tunnel_termination_sip_dip_index_tt0_table
    
    typedef npl_table_translator<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t> npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_table_translator_t;
    
    /// table_translator for table: ipv4_ip_tunnel_termination_sip_dip_index_tt1_table
    
    typedef npl_table_translator<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t> npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_table_translator_t;
    
    /// table_translator for table: ipv4_lpm_table
    
    typedef npl_lpm_table_translator<npl_ipv4_lpm_table_key_t, npl_ipv4_lpm_table_value_t> npl_ipv4_lpm_table_table_translator_t;
    
    /// table_translator for table: ipv4_lpts_table
    
    typedef npl_ternary_table_translator<npl_ipv4_lpts_table_key_t, npl_ipv4_lpts_table_value_t> npl_ipv4_lpts_table_table_translator_t;
    
    /// table_translator for table: ipv4_og_pcl_em_table
    
    typedef npl_table_translator<npl_ipv4_og_pcl_em_table_key_t, npl_ipv4_og_pcl_em_table_value_t> npl_ipv4_og_pcl_em_table_table_translator_t;
    
    /// table_translator for table: ipv4_og_pcl_lpm_table
    
    typedef npl_lpm_table_translator<npl_ipv4_og_pcl_lpm_table_key_t, npl_ipv4_og_pcl_lpm_table_value_t> npl_ipv4_og_pcl_lpm_table_table_translator_t;
    
    /// table_translator for table: ipv4_rtf_conf_set_mapping_table
    
    typedef npl_table_translator<npl_ipv4_rtf_conf_set_mapping_table_key_t, npl_ipv4_rtf_conf_set_mapping_table_value_t> npl_ipv4_rtf_conf_set_mapping_table_table_translator_t;
    
    /// table_translator for table: ipv4_vrf_dip_em_table
    
    typedef npl_table_translator<npl_ipv4_vrf_dip_em_table_key_t, npl_ipv4_vrf_dip_em_table_value_t> npl_ipv4_vrf_dip_em_table_table_translator_t;
    
    /// table_translator for table: ipv4_vrf_s_g_table
    
    typedef npl_table_translator<npl_ipv4_vrf_s_g_table_key_t, npl_ipv4_vrf_s_g_table_value_t> npl_ipv4_vrf_s_g_table_table_translator_t;
    
    /// table_translator for table: ipv6_acl_sport_static_table
    
    typedef npl_table_translator<npl_ipv6_acl_sport_static_table_key_t, npl_ipv6_acl_sport_static_table_value_t> npl_ipv6_acl_sport_static_table_table_translator_t;
    
    /// table_translator for table: ipv6_first_fragment_static_table
    
    typedef npl_ternary_table_translator<npl_ipv6_first_fragment_static_table_key_t, npl_ipv6_first_fragment_static_table_value_t> npl_ipv6_first_fragment_static_table_table_translator_t;
    
    /// table_translator for table: ipv6_lpm_table
    
    typedef npl_lpm_table_translator<npl_ipv6_lpm_table_key_t, npl_ipv6_lpm_table_value_t> npl_ipv6_lpm_table_table_translator_t;
    
    /// table_translator for table: ipv6_lpts_table
    
    typedef npl_ternary_table_translator<npl_ipv6_lpts_table_key_t, npl_ipv6_lpts_table_value_t> npl_ipv6_lpts_table_table_translator_t;
    
    /// table_translator for table: ipv6_mc_select_qos_id
    
    typedef npl_table_translator<npl_ipv6_mc_select_qos_id_key_t, npl_ipv6_mc_select_qos_id_value_t> npl_ipv6_mc_select_qos_id_table_translator_t;
    
    /// table_translator for table: ipv6_og_pcl_em_table
    
    typedef npl_table_translator<npl_ipv6_og_pcl_em_table_key_t, npl_ipv6_og_pcl_em_table_value_t> npl_ipv6_og_pcl_em_table_table_translator_t;
    
    /// table_translator for table: ipv6_og_pcl_lpm_table
    
    typedef npl_lpm_table_translator<npl_ipv6_og_pcl_lpm_table_key_t, npl_ipv6_og_pcl_lpm_table_value_t> npl_ipv6_og_pcl_lpm_table_table_translator_t;
    
    /// table_translator for table: ipv6_rtf_conf_set_mapping_table
    
    typedef npl_table_translator<npl_ipv6_rtf_conf_set_mapping_table_key_t, npl_ipv6_rtf_conf_set_mapping_table_value_t> npl_ipv6_rtf_conf_set_mapping_table_table_translator_t;
    
    /// table_translator for table: ipv6_sip_compression_table
    
    typedef npl_ternary_table_translator<npl_ipv6_sip_compression_table_key_t, npl_ipv6_sip_compression_table_value_t> npl_ipv6_sip_compression_table_table_translator_t;
    
    /// table_translator for table: ipv6_vrf_dip_em_table
    
    typedef npl_table_translator<npl_ipv6_vrf_dip_em_table_key_t, npl_ipv6_vrf_dip_em_table_value_t> npl_ipv6_vrf_dip_em_table_table_translator_t;
    
    /// table_translator for table: ipv6_vrf_s_g_table
    
    typedef npl_table_translator<npl_ipv6_vrf_s_g_table_key_t, npl_ipv6_vrf_s_g_table_value_t> npl_ipv6_vrf_s_g_table_table_translator_t;
    
    /// table_translator for table: is_pacific_b1_static_table
    
    typedef npl_table_translator<npl_is_pacific_b1_static_table_key_t, npl_is_pacific_b1_static_table_value_t> npl_is_pacific_b1_static_table_table_translator_t;
    
    /// table_translator for table: l2_dlp_table
    
    typedef npl_table_translator<npl_l2_dlp_table_key_t, npl_l2_dlp_table_value_t> npl_l2_dlp_table_table_translator_t;
    
    /// table_translator for table: l2_lp_profile_filter_table
    
    typedef npl_table_translator<npl_l2_lp_profile_filter_table_key_t, npl_l2_lp_profile_filter_table_value_t> npl_l2_lp_profile_filter_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_ctrl_fields_static_table
    
    typedef npl_ternary_table_translator<npl_l2_lpts_ctrl_fields_static_table_key_t, npl_l2_lpts_ctrl_fields_static_table_value_t> npl_l2_lpts_ctrl_fields_static_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_ip_fragment_static_table
    
    typedef npl_table_translator<npl_l2_lpts_ip_fragment_static_table_key_t, npl_l2_lpts_ip_fragment_static_table_value_t> npl_l2_lpts_ip_fragment_static_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_ipv4_table
    
    typedef npl_ternary_table_translator<npl_l2_lpts_ipv4_table_key_t, npl_l2_lpts_ipv4_table_value_t> npl_l2_lpts_ipv4_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_ipv6_table
    
    typedef npl_ternary_table_translator<npl_l2_lpts_ipv6_table_key_t, npl_l2_lpts_ipv6_table_value_t> npl_l2_lpts_ipv6_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_mac_table
    
    typedef npl_ternary_table_translator<npl_l2_lpts_mac_table_key_t, npl_l2_lpts_mac_table_value_t> npl_l2_lpts_mac_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_l2_lpts_next_macro_static_table_key_t, npl_l2_lpts_next_macro_static_table_value_t> npl_l2_lpts_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_protocol_table
    
    typedef npl_ternary_table_translator<npl_l2_lpts_protocol_table_key_t, npl_l2_lpts_protocol_table_value_t> npl_l2_lpts_protocol_table_table_translator_t;
    
    /// table_translator for table: l2_lpts_skip_p2p_static_table
    
    typedef npl_table_translator<npl_l2_lpts_skip_p2p_static_table_key_t, npl_l2_lpts_skip_p2p_static_table_value_t> npl_l2_lpts_skip_p2p_static_table_table_translator_t;
    
    /// table_translator for table: l2_termination_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_l2_termination_next_macro_static_table_key_t, npl_l2_termination_next_macro_static_table_value_t> npl_l2_termination_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: l2_tunnel_term_next_macro_static_table
    
    typedef npl_table_translator<npl_l2_tunnel_term_next_macro_static_table_key_t, npl_l2_tunnel_term_next_macro_static_table_value_t> npl_l2_tunnel_term_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: l3_dlp_p_counter_offset_table
    
    typedef npl_ternary_table_translator<npl_l3_dlp_p_counter_offset_table_key_t, npl_l3_dlp_p_counter_offset_table_value_t> npl_l3_dlp_p_counter_offset_table_table_translator_t;
    
    /// table_translator for table: l3_dlp_table
    
    typedef npl_table_translator<npl_l3_dlp_table_key_t, npl_l3_dlp_table_value_t> npl_l3_dlp_table_table_translator_t;
    
    /// table_translator for table: l3_termination_classify_ip_tunnels_table
    
    typedef npl_ternary_table_translator<npl_l3_termination_classify_ip_tunnels_table_key_t, npl_l3_termination_classify_ip_tunnels_table_value_t> npl_l3_termination_classify_ip_tunnels_table_table_translator_t;
    
    /// table_translator for table: l3_termination_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_l3_termination_next_macro_static_table_key_t, npl_l3_termination_next_macro_static_table_value_t> npl_l3_termination_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: l3_tunnel_termination_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_l3_tunnel_termination_next_macro_static_table_key_t, npl_l3_tunnel_termination_next_macro_static_table_value_t> npl_l3_tunnel_termination_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: l3_vxlan_overlay_sa_table
    
    typedef npl_table_translator<npl_l3_vxlan_overlay_sa_table_key_t, npl_l3_vxlan_overlay_sa_table_value_t> npl_l3_vxlan_overlay_sa_table_table_translator_t;
    
    /// table_translator for table: large_encap_global_lsp_prefix_table
    
    typedef npl_table_translator<npl_large_encap_global_lsp_prefix_table_key_t, npl_large_encap_global_lsp_prefix_table_value_t> npl_large_encap_global_lsp_prefix_table_table_translator_t;
    
    /// table_translator for table: large_encap_ip_tunnel_table
    
    typedef npl_table_translator<npl_large_encap_ip_tunnel_table_key_t, npl_large_encap_ip_tunnel_table_value_t> npl_large_encap_ip_tunnel_table_table_translator_t;
    
    /// table_translator for table: large_encap_mpls_he_no_ldp_table
    
    typedef npl_table_translator<npl_large_encap_mpls_he_no_ldp_table_key_t, npl_large_encap_mpls_he_no_ldp_table_value_t> npl_large_encap_mpls_he_no_ldp_table_table_translator_t;
    
    /// table_translator for table: large_encap_mpls_ldp_over_te_table
    
    typedef npl_table_translator<npl_large_encap_mpls_ldp_over_te_table_key_t, npl_large_encap_mpls_ldp_over_te_table_value_t> npl_large_encap_mpls_ldp_over_te_table_table_translator_t;
    
    /// table_translator for table: large_encap_te_he_tunnel_id_table
    
    typedef npl_table_translator<npl_large_encap_te_he_tunnel_id_table_key_t, npl_large_encap_te_he_tunnel_id_table_value_t> npl_large_encap_te_he_tunnel_id_table_table_translator_t;
    
    /// table_translator for table: latest_learn_records_table
    
    typedef npl_table_translator<npl_latest_learn_records_table_key_t, npl_latest_learn_records_table_value_t> npl_latest_learn_records_table_table_translator_t;
    
    /// table_translator for table: learn_manager_cfg_max_learn_type_reg
    
    typedef npl_table_translator<npl_learn_manager_cfg_max_learn_type_reg_key_t, npl_learn_manager_cfg_max_learn_type_reg_value_t> npl_learn_manager_cfg_max_learn_type_reg_table_translator_t;
    
    /// table_translator for table: learn_record_fifo_table
    
    typedef npl_table_translator<npl_learn_record_fifo_table_key_t, npl_learn_record_fifo_table_value_t> npl_learn_record_fifo_table_table_translator_t;
    
    /// table_translator for table: light_fi_fabric_table
    
    typedef npl_table_translator<npl_light_fi_fabric_table_key_t, npl_light_fi_fabric_table_value_t> npl_light_fi_fabric_table_table_translator_t;
    
    /// table_translator for table: light_fi_npu_base_table
    
    typedef npl_table_translator<npl_light_fi_npu_base_table_key_t, npl_light_fi_npu_base_table_value_t> npl_light_fi_npu_base_table_table_translator_t;
    
    /// table_translator for table: light_fi_npu_encap_table
    
    typedef npl_table_translator<npl_light_fi_npu_encap_table_key_t, npl_light_fi_npu_encap_table_value_t> npl_light_fi_npu_encap_table_table_translator_t;
    
    /// table_translator for table: light_fi_nw_0_table
    
    typedef npl_ternary_table_translator<npl_light_fi_nw_0_table_key_t, npl_light_fi_nw_0_table_value_t> npl_light_fi_nw_0_table_table_translator_t;
    
    /// table_translator for table: light_fi_nw_1_table
    
    typedef npl_ternary_table_translator<npl_light_fi_nw_1_table_key_t, npl_light_fi_nw_1_table_value_t> npl_light_fi_nw_1_table_table_translator_t;
    
    /// table_translator for table: light_fi_nw_2_table
    
    typedef npl_ternary_table_translator<npl_light_fi_nw_2_table_key_t, npl_light_fi_nw_2_table_value_t> npl_light_fi_nw_2_table_table_translator_t;
    
    /// table_translator for table: light_fi_nw_3_table
    
    typedef npl_ternary_table_translator<npl_light_fi_nw_3_table_key_t, npl_light_fi_nw_3_table_value_t> npl_light_fi_nw_3_table_table_translator_t;
    
    /// table_translator for table: light_fi_stages_cfg_table
    
    typedef npl_table_translator<npl_light_fi_stages_cfg_table_key_t, npl_light_fi_stages_cfg_table_value_t> npl_light_fi_stages_cfg_table_table_translator_t;
    
    /// table_translator for table: light_fi_tm_table
    
    typedef npl_table_translator<npl_light_fi_tm_table_key_t, npl_light_fi_tm_table_value_t> npl_light_fi_tm_table_table_translator_t;
    
    /// table_translator for table: link_relay_attributes_table
    
    typedef npl_table_translator<npl_link_relay_attributes_table_key_t, npl_link_relay_attributes_table_value_t> npl_link_relay_attributes_table_table_translator_t;
    
    /// table_translator for table: link_up_vector
    
    typedef npl_table_translator<npl_link_up_vector_key_t, npl_link_up_vector_value_t> npl_link_up_vector_table_translator_t;
    
    /// table_translator for table: lp_over_lag_table
    
    typedef npl_table_translator<npl_lp_over_lag_table_key_t, npl_lp_over_lag_table_value_t> npl_lp_over_lag_table_table_translator_t;
    
    /// table_translator for table: lpm_destination_prefix_map_table
    
    typedef npl_table_translator<npl_lpm_destination_prefix_map_table_key_t, npl_lpm_destination_prefix_map_table_value_t> npl_lpm_destination_prefix_map_table_table_translator_t;
    
    /// table_translator for table: lpts_2nd_lookup_table
    
    typedef npl_table_translator<npl_lpts_2nd_lookup_table_key_t, npl_lpts_2nd_lookup_table_value_t> npl_lpts_2nd_lookup_table_table_translator_t;
    
    /// table_translator for table: lpts_meter_table
    
    typedef npl_table_translator<npl_lpts_meter_table_key_t, npl_lpts_meter_table_value_t> npl_lpts_meter_table_table_translator_t;
    
    /// table_translator for table: lpts_og_application_table
    
    typedef npl_ternary_table_translator<npl_lpts_og_application_table_key_t, npl_lpts_og_application_table_value_t> npl_lpts_og_application_table_table_translator_t;
    
    /// table_translator for table: lr_filter_write_ptr_reg
    
    typedef npl_table_translator<npl_lr_filter_write_ptr_reg_key_t, npl_lr_filter_write_ptr_reg_value_t> npl_lr_filter_write_ptr_reg_table_translator_t;
    
    /// table_translator for table: lr_write_ptr_reg
    
    typedef npl_table_translator<npl_lr_write_ptr_reg_key_t, npl_lr_write_ptr_reg_value_t> npl_lr_write_ptr_reg_table_translator_t;
    
    /// table_translator for table: mac_af_npp_attributes_table
    
    typedef npl_table_translator<npl_mac_af_npp_attributes_table_key_t, npl_mac_af_npp_attributes_table_value_t> npl_mac_af_npp_attributes_table_table_translator_t;
    
    /// table_translator for table: mac_da_table
    
    typedef npl_ternary_table_translator<npl_mac_da_table_key_t, npl_mac_da_table_value_t> npl_mac_da_table_table_translator_t;
    
    /// table_translator for table: mac_ethernet_rate_limit_type_static_table
    
    typedef npl_ternary_table_translator<npl_mac_ethernet_rate_limit_type_static_table_key_t, npl_mac_ethernet_rate_limit_type_static_table_value_t> npl_mac_ethernet_rate_limit_type_static_table_table_translator_t;
    
    /// table_translator for table: mac_forwarding_table
    
    typedef npl_table_translator<npl_mac_forwarding_table_key_t, npl_mac_forwarding_table_value_t> npl_mac_forwarding_table_table_translator_t;
    
    /// table_translator for table: mac_mc_em_termination_attributes_table
    
    typedef npl_table_translator<npl_mac_mc_em_termination_attributes_table_key_t, npl_mac_mc_em_termination_attributes_table_value_t> npl_mac_mc_em_termination_attributes_table_table_translator_t;
    
    /// table_translator for table: mac_mc_tcam_termination_attributes_table
    
    typedef npl_ternary_table_translator<npl_mac_mc_tcam_termination_attributes_table_key_t, npl_mac_mc_tcam_termination_attributes_table_value_t> npl_mac_mc_tcam_termination_attributes_table_table_translator_t;
    
    /// table_translator for table: mac_qos_mapping_table
    
    typedef npl_table_translator<npl_mac_qos_mapping_table_key_t, npl_mac_qos_mapping_table_value_t> npl_mac_qos_mapping_table_table_translator_t;
    
    /// table_translator for table: mac_relay_g_ipv4_table
    
    typedef npl_table_translator<npl_mac_relay_g_ipv4_table_key_t, npl_mac_relay_g_ipv4_table_value_t> npl_mac_relay_g_ipv4_table_table_translator_t;
    
    /// table_translator for table: mac_relay_g_ipv6_table
    
    typedef npl_table_translator<npl_mac_relay_g_ipv6_table_key_t, npl_mac_relay_g_ipv6_table_value_t> npl_mac_relay_g_ipv6_table_table_translator_t;
    
    /// table_translator for table: mac_relay_to_vni_table
    
    typedef npl_table_translator<npl_mac_relay_to_vni_table_key_t, npl_mac_relay_to_vni_table_value_t> npl_mac_relay_to_vni_table_table_translator_t;
    
    /// table_translator for table: mac_termination_em_table
    
    typedef npl_table_translator<npl_mac_termination_em_table_key_t, npl_mac_termination_em_table_value_t> npl_mac_termination_em_table_table_translator_t;
    
    /// table_translator for table: mac_termination_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_mac_termination_next_macro_static_table_key_t, npl_mac_termination_next_macro_static_table_value_t> npl_mac_termination_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: mac_termination_no_da_em_table
    
    typedef npl_table_translator<npl_mac_termination_no_da_em_table_key_t, npl_mac_termination_no_da_em_table_value_t> npl_mac_termination_no_da_em_table_table_translator_t;
    
    /// table_translator for table: mac_termination_tcam_table
    
    typedef npl_ternary_table_translator<npl_mac_termination_tcam_table_key_t, npl_mac_termination_tcam_table_value_t> npl_mac_termination_tcam_table_table_translator_t;
    
    /// table_translator for table: map_ene_subcode_to8bit_static_table
    
    typedef npl_table_translator<npl_map_ene_subcode_to8bit_static_table_key_t, npl_map_ene_subcode_to8bit_static_table_value_t> npl_map_ene_subcode_to8bit_static_table_table_translator_t;
    
    /// table_translator for table: map_inject_ccm_macro_static_table
    
    typedef npl_ternary_table_translator<npl_map_inject_ccm_macro_static_table_key_t, npl_map_inject_ccm_macro_static_table_value_t> npl_map_inject_ccm_macro_static_table_table_translator_t;
    
    /// table_translator for table: map_more_labels_static_table
    
    typedef npl_table_translator<npl_map_more_labels_static_table_key_t, npl_map_more_labels_static_table_value_t> npl_map_more_labels_static_table_table_translator_t;
    
    /// table_translator for table: map_recyle_tx_to_rx_data_on_pd_static_table
    
    typedef npl_table_translator<npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t> npl_map_recyle_tx_to_rx_data_on_pd_static_table_table_translator_t;
    
    /// table_translator for table: map_tm_dp_ecn_to_wa_ecn_dp_static_table
    
    typedef npl_table_translator<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t> npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_table_translator_t;
    
    /// table_translator for table: map_tx_punt_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_map_tx_punt_next_macro_static_table_key_t, npl_map_tx_punt_next_macro_static_table_value_t> npl_map_tx_punt_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: map_tx_punt_rcy_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_map_tx_punt_rcy_next_macro_static_table_key_t, npl_map_tx_punt_rcy_next_macro_static_table_value_t> npl_map_tx_punt_rcy_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: mc_bitmap_base_voq_lookup_table
    
    typedef npl_table_translator<npl_mc_bitmap_base_voq_lookup_table_key_t, npl_mc_bitmap_base_voq_lookup_table_value_t> npl_mc_bitmap_base_voq_lookup_table_table_translator_t;
    
    /// table_translator for table: mc_bitmap_tc_map_table
    
    typedef npl_table_translator<npl_mc_bitmap_tc_map_table_key_t, npl_mc_bitmap_tc_map_table_value_t> npl_mc_bitmap_tc_map_table_table_translator_t;
    
    /// table_translator for table: mc_copy_id_map
    
    typedef npl_table_translator<npl_mc_copy_id_map_key_t, npl_mc_copy_id_map_value_t> npl_mc_copy_id_map_table_translator_t;
    
    /// table_translator for table: mc_cud_is_wide_table
    
    typedef npl_table_translator<npl_mc_cud_is_wide_table_key_t, npl_mc_cud_is_wide_table_value_t> npl_mc_cud_is_wide_table_table_translator_t;
    
    /// table_translator for table: mc_em_db
    
    typedef npl_table_translator<npl_mc_em_db_key_t, npl_mc_em_db_value_t> npl_mc_em_db_table_translator_t;
    
    /// table_translator for table: mc_emdb_tc_map_table
    
    typedef npl_table_translator<npl_mc_emdb_tc_map_table_key_t, npl_mc_emdb_tc_map_table_value_t> npl_mc_emdb_tc_map_table_table_translator_t;
    
    /// table_translator for table: mc_fe_links_bmp
    
    typedef npl_table_translator<npl_mc_fe_links_bmp_key_t, npl_mc_fe_links_bmp_value_t> npl_mc_fe_links_bmp_table_translator_t;
    
    /// table_translator for table: mc_ibm_cud_mapping_table
    
    typedef npl_table_translator<npl_mc_ibm_cud_mapping_table_key_t, npl_mc_ibm_cud_mapping_table_value_t> npl_mc_ibm_cud_mapping_table_table_translator_t;
    
    /// table_translator for table: mc_slice_bitmap_table
    
    typedef npl_table_translator<npl_mc_slice_bitmap_table_key_t, npl_mc_slice_bitmap_table_value_t> npl_mc_slice_bitmap_table_table_translator_t;
    
    /// table_translator for table: meg_id_format_table
    
    typedef npl_ternary_table_translator<npl_meg_id_format_table_key_t, npl_meg_id_format_table_value_t> npl_meg_id_format_table_table_translator_t;
    
    /// table_translator for table: mep_address_prefix_table
    
    typedef npl_table_translator<npl_mep_address_prefix_table_key_t, npl_mep_address_prefix_table_value_t> npl_mep_address_prefix_table_table_translator_t;
    
    /// table_translator for table: mii_loopback_table
    
    typedef npl_table_translator<npl_mii_loopback_table_key_t, npl_mii_loopback_table_value_t> npl_mii_loopback_table_table_translator_t;
    
    /// table_translator for table: mirror_code_hw_table
    
    typedef npl_table_translator<npl_mirror_code_hw_table_key_t, npl_mirror_code_hw_table_value_t> npl_mirror_code_hw_table_table_translator_t;
    
    /// table_translator for table: mirror_egress_attributes_table
    
    typedef npl_table_translator<npl_mirror_egress_attributes_table_key_t, npl_mirror_egress_attributes_table_value_t> npl_mirror_egress_attributes_table_table_translator_t;
    
    /// table_translator for table: mirror_to_dsp_in_npu_soft_header_table
    
    typedef npl_table_translator<npl_mirror_to_dsp_in_npu_soft_header_table_key_t, npl_mirror_to_dsp_in_npu_soft_header_table_value_t> npl_mirror_to_dsp_in_npu_soft_header_table_table_translator_t;
    
    /// table_translator for table: mldp_protection_enabled_static_table
    
    typedef npl_ternary_table_translator<npl_mldp_protection_enabled_static_table_key_t, npl_mldp_protection_enabled_static_table_value_t> npl_mldp_protection_enabled_static_table_table_translator_t;
    
    /// table_translator for table: mldp_protection_table
    
    typedef npl_table_translator<npl_mldp_protection_table_key_t, npl_mldp_protection_table_value_t> npl_mldp_protection_table_table_translator_t;
    
    /// table_translator for table: mp_aux_data_table
    
    typedef npl_table_translator<npl_mp_aux_data_table_key_t, npl_mp_aux_data_table_value_t> npl_mp_aux_data_table_table_translator_t;
    
    /// table_translator for table: mp_data_table
    
    typedef npl_table_translator<npl_mp_data_table_key_t, npl_mp_data_table_value_t> npl_mp_data_table_table_translator_t;
    
    /// table_translator for table: mpls_encap_control_static_table
    
    typedef npl_table_translator<npl_mpls_encap_control_static_table_key_t, npl_mpls_encap_control_static_table_value_t> npl_mpls_encap_control_static_table_table_translator_t;
    
    /// table_translator for table: mpls_forwarding_table
    
    typedef npl_table_translator<npl_mpls_forwarding_table_key_t, npl_mpls_forwarding_table_value_t> npl_mpls_forwarding_table_table_translator_t;
    
    /// table_translator for table: mpls_header_offset_in_bytes_static_table
    
    typedef npl_table_translator<npl_mpls_header_offset_in_bytes_static_table_key_t, npl_mpls_header_offset_in_bytes_static_table_value_t> npl_mpls_header_offset_in_bytes_static_table_table_translator_t;
    
    /// table_translator for table: mpls_l3_lsp_static_table
    
    typedef npl_table_translator<npl_mpls_l3_lsp_static_table_key_t, npl_mpls_l3_lsp_static_table_value_t> npl_mpls_l3_lsp_static_table_table_translator_t;
    
    /// table_translator for table: mpls_labels_1_to_4_jump_offset_static_table
    
    typedef npl_table_translator<npl_mpls_labels_1_to_4_jump_offset_static_table_key_t, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t> npl_mpls_labels_1_to_4_jump_offset_static_table_table_translator_t;
    
    /// table_translator for table: mpls_lsp_labels_config_static_table
    
    typedef npl_table_translator<npl_mpls_lsp_labels_config_static_table_key_t, npl_mpls_lsp_labels_config_static_table_value_t> npl_mpls_lsp_labels_config_static_table_table_translator_t;
    
    /// table_translator for table: mpls_qos_mapping_table
    
    typedef npl_table_translator<npl_mpls_qos_mapping_table_key_t, npl_mpls_qos_mapping_table_value_t> npl_mpls_qos_mapping_table_table_translator_t;
    
    /// table_translator for table: mpls_resolve_service_labels_static_table
    
    typedef npl_ternary_table_translator<npl_mpls_resolve_service_labels_static_table_key_t, npl_mpls_resolve_service_labels_static_table_value_t> npl_mpls_resolve_service_labels_static_table_table_translator_t;
    
    /// table_translator for table: mpls_termination_em0_table
    
    typedef npl_table_translator<npl_mpls_termination_em0_table_key_t, npl_mpls_termination_em0_table_value_t> npl_mpls_termination_em0_table_table_translator_t;
    
    /// table_translator for table: mpls_termination_em1_table
    
    typedef npl_table_translator<npl_mpls_termination_em1_table_key_t, npl_mpls_termination_em1_table_value_t> npl_mpls_termination_em1_table_table_translator_t;
    
    /// table_translator for table: mpls_vpn_enabled_static_table
    
    typedef npl_ternary_table_translator<npl_mpls_vpn_enabled_static_table_key_t, npl_mpls_vpn_enabled_static_table_value_t> npl_mpls_vpn_enabled_static_table_table_translator_t;
    
    /// table_translator for table: ms_voq_fabric_context_offset_table
    
    typedef npl_table_translator<npl_ms_voq_fabric_context_offset_table_key_t, npl_ms_voq_fabric_context_offset_table_value_t> npl_ms_voq_fabric_context_offset_table_table_translator_t;
    
    /// table_translator for table: my_ipv4_table
    
    typedef npl_ternary_table_translator<npl_my_ipv4_table_key_t, npl_my_ipv4_table_value_t> npl_my_ipv4_table_table_translator_t;
    
    /// table_translator for table: native_ce_ptr_table
    
    typedef npl_table_translator<npl_native_ce_ptr_table_key_t, npl_native_ce_ptr_table_value_t> npl_native_ce_ptr_table_table_translator_t;
    
    /// table_translator for table: native_fec_table
    
    typedef npl_table_translator<npl_native_fec_table_key_t, npl_native_fec_table_value_t> npl_native_fec_table_table_translator_t;
    
    /// table_translator for table: native_fec_type_decoding_table
    
    typedef npl_table_translator<npl_native_fec_type_decoding_table_key_t, npl_native_fec_type_decoding_table_value_t> npl_native_fec_type_decoding_table_table_translator_t;
    
    /// table_translator for table: native_frr_table
    
    typedef npl_table_translator<npl_native_frr_table_key_t, npl_native_frr_table_value_t> npl_native_frr_table_table_translator_t;
    
    /// table_translator for table: native_frr_type_decoding_table
    
    typedef npl_table_translator<npl_native_frr_type_decoding_table_key_t, npl_native_frr_type_decoding_table_value_t> npl_native_frr_type_decoding_table_table_translator_t;
    
    /// table_translator for table: native_l2_lp_table
    
    typedef npl_table_translator<npl_native_l2_lp_table_key_t, npl_native_l2_lp_table_value_t> npl_native_l2_lp_table_table_translator_t;
    
    /// table_translator for table: native_l2_lp_type_decoding_table
    
    typedef npl_table_translator<npl_native_l2_lp_type_decoding_table_key_t, npl_native_l2_lp_type_decoding_table_value_t> npl_native_l2_lp_type_decoding_table_table_translator_t;
    
    /// table_translator for table: native_lb_group_size_table
    
    typedef npl_table_translator<npl_native_lb_group_size_table_key_t, npl_native_lb_group_size_table_value_t> npl_native_lb_group_size_table_table_translator_t;
    
    /// table_translator for table: native_lb_table
    
    typedef npl_table_translator<npl_native_lb_table_key_t, npl_native_lb_table_value_t> npl_native_lb_table_table_translator_t;
    
    /// table_translator for table: native_lb_type_decoding_table
    
    typedef npl_table_translator<npl_native_lb_type_decoding_table_key_t, npl_native_lb_type_decoding_table_value_t> npl_native_lb_type_decoding_table_table_translator_t;
    
    /// table_translator for table: native_lp_is_pbts_prefix_table
    
    typedef npl_table_translator<npl_native_lp_is_pbts_prefix_table_key_t, npl_native_lp_is_pbts_prefix_table_value_t> npl_native_lp_is_pbts_prefix_table_table_translator_t;
    
    /// table_translator for table: native_lp_pbts_map_table
    
    typedef npl_table_translator<npl_native_lp_pbts_map_table_key_t, npl_native_lp_pbts_map_table_value_t> npl_native_lp_pbts_map_table_table_translator_t;
    
    /// table_translator for table: native_protection_table
    
    typedef npl_table_translator<npl_native_protection_table_key_t, npl_native_protection_table_value_t> npl_native_protection_table_table_translator_t;
    
    /// table_translator for table: next_header_1_is_l4_over_ipv4_static_table
    
    typedef npl_table_translator<npl_next_header_1_is_l4_over_ipv4_static_table_key_t, npl_next_header_1_is_l4_over_ipv4_static_table_value_t> npl_next_header_1_is_l4_over_ipv4_static_table_table_translator_t;
    
    /// table_translator for table: nh_macro_code_to_id_l6_static_table
    
    typedef npl_table_translator<npl_nh_macro_code_to_id_l6_static_table_key_t, npl_nh_macro_code_to_id_l6_static_table_value_t> npl_nh_macro_code_to_id_l6_static_table_table_translator_t;
    
    /// table_translator for table: nhlfe_type_mapping_static_table
    
    typedef npl_table_translator<npl_nhlfe_type_mapping_static_table_key_t, npl_nhlfe_type_mapping_static_table_value_t> npl_nhlfe_type_mapping_static_table_table_translator_t;
    
    /// table_translator for table: null_rtf_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_null_rtf_next_macro_static_table_key_t, npl_null_rtf_next_macro_static_table_value_t> npl_null_rtf_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: nw_smcid_threshold_table
    
    typedef npl_table_translator<npl_nw_smcid_threshold_table_key_t, npl_nw_smcid_threshold_table_value_t> npl_nw_smcid_threshold_table_table_translator_t;
    
    /// table_translator for table: oamp_drop_destination_static_table
    
    typedef npl_table_translator<npl_oamp_drop_destination_static_table_key_t, npl_oamp_drop_destination_static_table_value_t> npl_oamp_drop_destination_static_table_table_translator_t;
    
    /// table_translator for table: oamp_event_queue_table
    
    typedef npl_table_translator<npl_oamp_event_queue_table_key_t, npl_oamp_event_queue_table_value_t> npl_oamp_event_queue_table_table_translator_t;
    
    /// table_translator for table: oamp_redirect_get_counter_table
    
    typedef npl_table_translator<npl_oamp_redirect_get_counter_table_key_t, npl_oamp_redirect_get_counter_table_value_t> npl_oamp_redirect_get_counter_table_table_translator_t;
    
    /// table_translator for table: oamp_redirect_punt_eth_hdr_1_table
    
    typedef npl_table_translator<npl_oamp_redirect_punt_eth_hdr_1_table_key_t, npl_oamp_redirect_punt_eth_hdr_1_table_value_t> npl_oamp_redirect_punt_eth_hdr_1_table_table_translator_t;
    
    /// table_translator for table: oamp_redirect_punt_eth_hdr_2_table
    
    typedef npl_table_translator<npl_oamp_redirect_punt_eth_hdr_2_table_key_t, npl_oamp_redirect_punt_eth_hdr_2_table_value_t> npl_oamp_redirect_punt_eth_hdr_2_table_table_translator_t;
    
    /// table_translator for table: oamp_redirect_punt_eth_hdr_3_table
    
    typedef npl_table_translator<npl_oamp_redirect_punt_eth_hdr_3_table_key_t, npl_oamp_redirect_punt_eth_hdr_3_table_value_t> npl_oamp_redirect_punt_eth_hdr_3_table_table_translator_t;
    
    /// table_translator for table: oamp_redirect_punt_eth_hdr_4_table
    
    typedef npl_table_translator<npl_oamp_redirect_punt_eth_hdr_4_table_key_t, npl_oamp_redirect_punt_eth_hdr_4_table_value_t> npl_oamp_redirect_punt_eth_hdr_4_table_table_translator_t;
    
    /// table_translator for table: oamp_redirect_table
    
    typedef npl_table_translator<npl_oamp_redirect_table_key_t, npl_oamp_redirect_table_value_t> npl_oamp_redirect_table_table_translator_t;
    
    /// table_translator for table: obm_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_obm_next_macro_static_table_key_t, npl_obm_next_macro_static_table_value_t> npl_obm_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: og_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_og_next_macro_static_table_key_t, npl_og_next_macro_static_table_value_t> npl_og_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: outer_tpid_table
    
    typedef npl_table_translator<npl_outer_tpid_table_key_t, npl_outer_tpid_table_value_t> npl_outer_tpid_table_table_translator_t;
    
    /// table_translator for table: overlay_ipv4_sip_table
    
    typedef npl_table_translator<npl_overlay_ipv4_sip_table_key_t, npl_overlay_ipv4_sip_table_value_t> npl_overlay_ipv4_sip_table_table_translator_t;
    
    /// table_translator for table: pad_mtu_inj_check_static_table
    
    typedef npl_ternary_table_translator<npl_pad_mtu_inj_check_static_table_key_t, npl_pad_mtu_inj_check_static_table_value_t> npl_pad_mtu_inj_check_static_table_table_translator_t;
    
    /// table_translator for table: path_lb_type_decoding_table
    
    typedef npl_table_translator<npl_path_lb_type_decoding_table_key_t, npl_path_lb_type_decoding_table_value_t> npl_path_lb_type_decoding_table_table_translator_t;
    
    /// table_translator for table: path_lp_is_pbts_prefix_table
    
    typedef npl_table_translator<npl_path_lp_is_pbts_prefix_table_key_t, npl_path_lp_is_pbts_prefix_table_value_t> npl_path_lp_is_pbts_prefix_table_table_translator_t;
    
    /// table_translator for table: path_lp_pbts_map_table
    
    typedef npl_table_translator<npl_path_lp_pbts_map_table_key_t, npl_path_lp_pbts_map_table_value_t> npl_path_lp_pbts_map_table_table_translator_t;
    
    /// table_translator for table: path_lp_table
    
    typedef npl_table_translator<npl_path_lp_table_key_t, npl_path_lp_table_value_t> npl_path_lp_table_table_translator_t;
    
    /// table_translator for table: path_lp_type_decoding_table
    
    typedef npl_table_translator<npl_path_lp_type_decoding_table_key_t, npl_path_lp_type_decoding_table_value_t> npl_path_lp_type_decoding_table_table_translator_t;
    
    /// table_translator for table: path_protection_table
    
    typedef npl_table_translator<npl_path_protection_table_key_t, npl_path_protection_table_value_t> npl_path_protection_table_table_translator_t;
    
    /// table_translator for table: pdoq_oq_ifc_mapping
    
    typedef npl_table_translator<npl_pdoq_oq_ifc_mapping_key_t, npl_pdoq_oq_ifc_mapping_value_t> npl_pdoq_oq_ifc_mapping_table_translator_t;
    
    /// table_translator for table: pdvoq_bank_pair_offset_table
    
    typedef npl_table_translator<npl_pdvoq_bank_pair_offset_table_key_t, npl_pdvoq_bank_pair_offset_table_value_t> npl_pdvoq_bank_pair_offset_table_table_translator_t;
    
    /// table_translator for table: pdvoq_slice_voq_properties_table
    
    typedef npl_table_translator<npl_pdvoq_slice_voq_properties_table_key_t, npl_pdvoq_slice_voq_properties_table_value_t> npl_pdvoq_slice_voq_properties_table_table_translator_t;
    
    /// table_translator for table: per_asbr_and_dpe_table
    
    typedef npl_table_translator<npl_per_asbr_and_dpe_table_key_t, npl_per_asbr_and_dpe_table_value_t> npl_per_asbr_and_dpe_table_table_translator_t;
    
    /// table_translator for table: per_pe_and_prefix_vpn_key_large_table
    
    typedef npl_table_translator<npl_per_pe_and_prefix_vpn_key_large_table_key_t, npl_per_pe_and_prefix_vpn_key_large_table_value_t> npl_per_pe_and_prefix_vpn_key_large_table_table_translator_t;
    
    /// table_translator for table: per_pe_and_vrf_vpn_key_large_table
    
    typedef npl_table_translator<npl_per_pe_and_vrf_vpn_key_large_table_key_t, npl_per_pe_and_vrf_vpn_key_large_table_value_t> npl_per_pe_and_vrf_vpn_key_large_table_table_translator_t;
    
    /// table_translator for table: per_port_destination_table
    
    typedef npl_table_translator<npl_per_port_destination_table_key_t, npl_per_port_destination_table_value_t> npl_per_port_destination_table_table_translator_t;
    
    /// table_translator for table: per_vrf_mpls_forwarding_table
    
    typedef npl_table_translator<npl_per_vrf_mpls_forwarding_table_key_t, npl_per_vrf_mpls_forwarding_table_value_t> npl_per_vrf_mpls_forwarding_table_table_translator_t;
    
    /// table_translator for table: pfc_destination_table
    
    typedef npl_table_translator<npl_pfc_destination_table_key_t, npl_pfc_destination_table_value_t> npl_pfc_destination_table_table_translator_t;
    
    /// table_translator for table: pfc_event_queue_table
    
    typedef npl_table_translator<npl_pfc_event_queue_table_key_t, npl_pfc_event_queue_table_value_t> npl_pfc_event_queue_table_table_translator_t;
    
    /// table_translator for table: pfc_filter_wd_table
    
    typedef npl_ternary_table_translator<npl_pfc_filter_wd_table_key_t, npl_pfc_filter_wd_table_value_t> npl_pfc_filter_wd_table_table_translator_t;
    
    /// table_translator for table: pfc_offset_from_vector_static_table
    
    typedef npl_ternary_table_translator<npl_pfc_offset_from_vector_static_table_key_t, npl_pfc_offset_from_vector_static_table_value_t> npl_pfc_offset_from_vector_static_table_table_translator_t;
    
    /// table_translator for table: pfc_ssp_slice_map_table
    
    typedef npl_ternary_table_translator<npl_pfc_ssp_slice_map_table_key_t, npl_pfc_ssp_slice_map_table_value_t> npl_pfc_ssp_slice_map_table_table_translator_t;
    
    /// table_translator for table: pfc_tc_latency_table
    
    typedef npl_ternary_table_translator<npl_pfc_tc_latency_table_key_t, npl_pfc_tc_latency_table_value_t> npl_pfc_tc_latency_table_table_translator_t;
    
    /// table_translator for table: pfc_tc_table
    
    typedef npl_table_translator<npl_pfc_tc_table_key_t, npl_pfc_tc_table_value_t> npl_pfc_tc_table_table_translator_t;
    
    /// table_translator for table: pfc_tc_wrap_latency_table
    
    typedef npl_ternary_table_translator<npl_pfc_tc_wrap_latency_table_key_t, npl_pfc_tc_wrap_latency_table_value_t> npl_pfc_tc_wrap_latency_table_table_translator_t;
    
    /// table_translator for table: pfc_vector_static_table
    
    typedef npl_table_translator<npl_pfc_vector_static_table_key_t, npl_pfc_vector_static_table_value_t> npl_pfc_vector_static_table_table_translator_t;
    
    /// table_translator for table: pin_start_offset_macros
    
    typedef npl_table_translator<npl_pin_start_offset_macros_key_t, npl_pin_start_offset_macros_value_t> npl_pin_start_offset_macros_table_translator_t;
    
    /// table_translator for table: pma_loopback_table
    
    typedef npl_table_translator<npl_pma_loopback_table_key_t, npl_pma_loopback_table_value_t> npl_pma_loopback_table_table_translator_t;
    
    /// table_translator for table: port_dspa_group_size_table
    
    typedef npl_table_translator<npl_port_dspa_group_size_table_key_t, npl_port_dspa_group_size_table_value_t> npl_port_dspa_group_size_table_table_translator_t;
    
    /// table_translator for table: port_dspa_table
    
    typedef npl_table_translator<npl_port_dspa_table_key_t, npl_port_dspa_table_value_t> npl_port_dspa_table_table_translator_t;
    
    /// table_translator for table: port_dspa_type_decoding_table
    
    typedef npl_table_translator<npl_port_dspa_type_decoding_table_key_t, npl_port_dspa_type_decoding_table_value_t> npl_port_dspa_type_decoding_table_table_translator_t;
    
    /// table_translator for table: port_npp_protection_table
    
    typedef npl_table_translator<npl_port_npp_protection_table_key_t, npl_port_npp_protection_table_value_t> npl_port_npp_protection_table_table_translator_t;
    
    /// table_translator for table: port_npp_protection_type_decoding_table
    
    typedef npl_table_translator<npl_port_npp_protection_type_decoding_table_key_t, npl_port_npp_protection_type_decoding_table_value_t> npl_port_npp_protection_type_decoding_table_table_translator_t;
    
    /// table_translator for table: port_protection_table
    
    typedef npl_table_translator<npl_port_protection_table_key_t, npl_port_protection_table_value_t> npl_port_protection_table_table_translator_t;
    
    /// table_translator for table: punt_ethertype_static_table
    
    typedef npl_ternary_table_translator<npl_punt_ethertype_static_table_key_t, npl_punt_ethertype_static_table_value_t> npl_punt_ethertype_static_table_table_translator_t;
    
    /// table_translator for table: punt_rcy_inject_header_ene_encap_table
    
    typedef npl_table_translator<npl_punt_rcy_inject_header_ene_encap_table_key_t, npl_punt_rcy_inject_header_ene_encap_table_value_t> npl_punt_rcy_inject_header_ene_encap_table_table_translator_t;
    
    /// table_translator for table: punt_select_nw_ene_static_table
    
    typedef npl_table_translator<npl_punt_select_nw_ene_static_table_key_t, npl_punt_select_nw_ene_static_table_value_t> npl_punt_select_nw_ene_static_table_table_translator_t;
    
    /// table_translator for table: punt_tunnel_transport_encap_table
    
    typedef npl_table_translator<npl_punt_tunnel_transport_encap_table_key_t, npl_punt_tunnel_transport_encap_table_value_t> npl_punt_tunnel_transport_encap_table_table_translator_t;
    
    /// table_translator for table: punt_tunnel_transport_extended_encap_table
    
    typedef npl_table_translator<npl_punt_tunnel_transport_extended_encap_table_key_t, npl_punt_tunnel_transport_extended_encap_table_value_t> npl_punt_tunnel_transport_extended_encap_table_table_translator_t;
    
    /// table_translator for table: punt_tunnel_transport_extended_encap_table2
    
    typedef npl_table_translator<npl_punt_tunnel_transport_extended_encap_table2_key_t, npl_punt_tunnel_transport_extended_encap_table2_value_t> npl_punt_tunnel_transport_extended_encap_table2_table_translator_t;
    
    /// table_translator for table: pwe_label_table
    
    typedef npl_table_translator<npl_pwe_label_table_key_t, npl_pwe_label_table_value_t> npl_pwe_label_table_table_translator_t;
    
    /// table_translator for table: pwe_to_l3_dest_table
    
    typedef npl_table_translator<npl_pwe_to_l3_dest_table_key_t, npl_pwe_to_l3_dest_table_value_t> npl_pwe_to_l3_dest_table_table_translator_t;
    
    /// table_translator for table: pwe_vpls_label_table
    
    typedef npl_table_translator<npl_pwe_vpls_label_table_key_t, npl_pwe_vpls_label_table_value_t> npl_pwe_vpls_label_table_table_translator_t;
    
    /// table_translator for table: pwe_vpls_tunnel_label_table
    
    typedef npl_table_translator<npl_pwe_vpls_tunnel_label_table_key_t, npl_pwe_vpls_tunnel_label_table_value_t> npl_pwe_vpls_tunnel_label_table_table_translator_t;
    
    /// table_translator for table: reassembly_source_port_map_table
    
    typedef npl_table_translator<npl_reassembly_source_port_map_table_key_t, npl_reassembly_source_port_map_table_value_t> npl_reassembly_source_port_map_table_table_translator_t;
    
    /// table_translator for table: recycle_override_table
    
    typedef npl_table_translator<npl_recycle_override_table_key_t, npl_recycle_override_table_value_t> npl_recycle_override_table_table_translator_t;
    
    /// table_translator for table: recycled_inject_up_info_table
    
    typedef npl_table_translator<npl_recycled_inject_up_info_table_key_t, npl_recycled_inject_up_info_table_value_t> npl_recycled_inject_up_info_table_table_translator_t;
    
    /// table_translator for table: redirect_destination_table
    
    typedef npl_table_translator<npl_redirect_destination_table_key_t, npl_redirect_destination_table_value_t> npl_redirect_destination_table_table_translator_t;
    
    /// table_translator for table: redirect_table
    
    template<> inline
    bool npl_ternary_table_translator<npl_redirect_table_key_t, npl_redirect_table_value_t>::is_multi_line_entries()
    {
        return true;
    }
    typedef npl_ternary_table_translator<npl_redirect_table_key_t, npl_redirect_table_value_t> npl_redirect_table_table_translator_t;
    
    /// table_translator for table: resolution_pfc_select_table
    
    typedef npl_ternary_table_translator<npl_resolution_pfc_select_table_key_t, npl_resolution_pfc_select_table_value_t> npl_resolution_pfc_select_table_table_translator_t;
    
    /// table_translator for table: resolution_set_next_macro_table
    
    typedef npl_table_translator<npl_resolution_set_next_macro_table_key_t, npl_resolution_set_next_macro_table_value_t> npl_resolution_set_next_macro_table_table_translator_t;
    
    /// table_translator for table: rewrite_sa_prefix_index_table
    
    typedef npl_table_translator<npl_rewrite_sa_prefix_index_table_key_t, npl_rewrite_sa_prefix_index_table_value_t> npl_rewrite_sa_prefix_index_table_table_translator_t;
    
    /// table_translator for table: rmep_last_time_table
    
    typedef npl_table_translator<npl_rmep_last_time_table_key_t, npl_rmep_last_time_table_value_t> npl_rmep_last_time_table_table_translator_t;
    
    /// table_translator for table: rmep_state_table
    
    typedef npl_table_translator<npl_rmep_state_table_key_t, npl_rmep_state_table_value_t> npl_rmep_state_table_table_translator_t;
    
    /// table_translator for table: rpf_fec_access_map_table
    
    typedef npl_table_translator<npl_rpf_fec_access_map_table_key_t, npl_rpf_fec_access_map_table_value_t> npl_rpf_fec_access_map_table_table_translator_t;
    
    /// table_translator for table: rpf_fec_table
    
    typedef npl_table_translator<npl_rpf_fec_table_key_t, npl_rpf_fec_table_value_t> npl_rpf_fec_table_table_translator_t;
    
    /// table_translator for table: rtf_conf_set_to_og_pcl_compress_bits_mapping_table
    
    typedef npl_table_translator<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t> npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_table_translator_t;
    
    /// table_translator for table: rtf_conf_set_to_og_pcl_ids_mapping_table
    
    typedef npl_table_translator<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t> npl_rtf_conf_set_to_og_pcl_ids_mapping_table_table_translator_t;
    
    /// table_translator for table: rtf_conf_set_to_post_fwd_stage_mapping_table
    
    typedef npl_table_translator<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t> npl_rtf_conf_set_to_post_fwd_stage_mapping_table_table_translator_t;
    
    /// table_translator for table: rtf_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_rtf_next_macro_static_table_key_t, npl_rtf_next_macro_static_table_value_t> npl_rtf_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: rx_counters_block_config_table
    
    typedef npl_table_translator<npl_rx_counters_block_config_table_key_t, npl_rx_counters_block_config_table_value_t> npl_rx_counters_block_config_table_table_translator_t;
    
    /// table_translator for table: rx_fwd_error_handling_counter_table
    
    typedef npl_table_translator<npl_rx_fwd_error_handling_counter_table_key_t, npl_rx_fwd_error_handling_counter_table_value_t> npl_rx_fwd_error_handling_counter_table_table_translator_t;
    
    /// table_translator for table: rx_fwd_error_handling_destination_table
    
    typedef npl_table_translator<npl_rx_fwd_error_handling_destination_table_key_t, npl_rx_fwd_error_handling_destination_table_value_t> npl_rx_fwd_error_handling_destination_table_table_translator_t;
    
    /// table_translator for table: rx_ip_p_counter_offset_static_table
    
    typedef npl_table_translator<npl_rx_ip_p_counter_offset_static_table_key_t, npl_rx_ip_p_counter_offset_static_table_value_t> npl_rx_ip_p_counter_offset_static_table_table_translator_t;
    
    /// table_translator for table: rx_map_npp_to_ssp_table
    
    typedef npl_table_translator<npl_rx_map_npp_to_ssp_table_key_t, npl_rx_map_npp_to_ssp_table_value_t> npl_rx_map_npp_to_ssp_table_table_translator_t;
    
    /// table_translator for table: rx_meter_block_meter_attribute_table
    
    typedef npl_table_translator<npl_rx_meter_block_meter_attribute_table_key_t, npl_rx_meter_block_meter_attribute_table_value_t> npl_rx_meter_block_meter_attribute_table_table_translator_t;
    
    /// table_translator for table: rx_meter_block_meter_profile_table
    
    typedef npl_table_translator<npl_rx_meter_block_meter_profile_table_key_t, npl_rx_meter_block_meter_profile_table_value_t> npl_rx_meter_block_meter_profile_table_table_translator_t;
    
    /// table_translator for table: rx_meter_block_meter_shaper_configuration_table
    
    typedef npl_table_translator<npl_rx_meter_block_meter_shaper_configuration_table_key_t, npl_rx_meter_block_meter_shaper_configuration_table_value_t> npl_rx_meter_block_meter_shaper_configuration_table_table_translator_t;
    
    /// table_translator for table: rx_meter_distributed_meter_profile_table
    
    typedef npl_table_translator<npl_rx_meter_distributed_meter_profile_table_key_t, npl_rx_meter_distributed_meter_profile_table_value_t> npl_rx_meter_distributed_meter_profile_table_table_translator_t;
    
    /// table_translator for table: rx_meter_exact_meter_decision_mapping_table
    
    typedef npl_table_translator<npl_rx_meter_exact_meter_decision_mapping_table_key_t, npl_rx_meter_exact_meter_decision_mapping_table_value_t> npl_rx_meter_exact_meter_decision_mapping_table_table_translator_t;
    
    /// table_translator for table: rx_meter_meter_profile_table
    
    typedef npl_table_translator<npl_rx_meter_meter_profile_table_key_t, npl_rx_meter_meter_profile_table_value_t> npl_rx_meter_meter_profile_table_table_translator_t;
    
    /// table_translator for table: rx_meter_meter_shaper_configuration_table
    
    typedef npl_table_translator<npl_rx_meter_meter_shaper_configuration_table_key_t, npl_rx_meter_meter_shaper_configuration_table_value_t> npl_rx_meter_meter_shaper_configuration_table_table_translator_t;
    
    /// table_translator for table: rx_meter_meters_attribute_table
    
    typedef npl_table_translator<npl_rx_meter_meters_attribute_table_key_t, npl_rx_meter_meters_attribute_table_value_t> npl_rx_meter_meters_attribute_table_table_translator_t;
    
    /// table_translator for table: rx_meter_rate_limiter_shaper_configuration_table
    
    typedef npl_table_translator<npl_rx_meter_rate_limiter_shaper_configuration_table_key_t, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t> npl_rx_meter_rate_limiter_shaper_configuration_table_table_translator_t;
    
    /// table_translator for table: rx_meter_stat_meter_decision_mapping_table
    
    typedef npl_table_translator<npl_rx_meter_stat_meter_decision_mapping_table_key_t, npl_rx_meter_stat_meter_decision_mapping_table_value_t> npl_rx_meter_stat_meter_decision_mapping_table_table_translator_t;
    
    /// table_translator for table: rx_npu_to_tm_dest_table
    
    typedef npl_table_translator<npl_rx_npu_to_tm_dest_table_key_t, npl_rx_npu_to_tm_dest_table_value_t> npl_rx_npu_to_tm_dest_table_table_translator_t;
    
    /// table_translator for table: rx_obm_code_table
    
    typedef npl_table_translator<npl_rx_obm_code_table_key_t, npl_rx_obm_code_table_value_t> npl_rx_obm_code_table_table_translator_t;
    
    /// table_translator for table: rx_obm_punt_src_and_code_table
    
    typedef npl_table_translator<npl_rx_obm_punt_src_and_code_table_key_t, npl_rx_obm_punt_src_and_code_table_value_t> npl_rx_obm_punt_src_and_code_table_table_translator_t;
    
    /// table_translator for table: rx_redirect_code_ext_table
    
    typedef npl_table_translator<npl_rx_redirect_code_ext_table_key_t, npl_rx_redirect_code_ext_table_value_t> npl_rx_redirect_code_ext_table_table_translator_t;
    
    /// table_translator for table: rx_redirect_code_table
    
    typedef npl_table_translator<npl_rx_redirect_code_table_key_t, npl_rx_redirect_code_table_value_t> npl_rx_redirect_code_table_table_translator_t;
    
    /// table_translator for table: rx_redirect_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_rx_redirect_next_macro_static_table_key_t, npl_rx_redirect_next_macro_static_table_value_t> npl_rx_redirect_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: rx_term_error_handling_counter_table
    
    typedef npl_table_translator<npl_rx_term_error_handling_counter_table_key_t, npl_rx_term_error_handling_counter_table_value_t> npl_rx_term_error_handling_counter_table_table_translator_t;
    
    /// table_translator for table: rx_term_error_handling_destination_table
    
    typedef npl_table_translator<npl_rx_term_error_handling_destination_table_key_t, npl_rx_term_error_handling_destination_table_value_t> npl_rx_term_error_handling_destination_table_table_translator_t;
    
    /// table_translator for table: rxpdr_dsp_lookup_table
    
    typedef npl_table_translator<npl_rxpdr_dsp_lookup_table_key_t, npl_rxpdr_dsp_lookup_table_value_t> npl_rxpdr_dsp_lookup_table_table_translator_t;
    
    /// table_translator for table: rxpdr_dsp_tc_map
    
    typedef npl_table_translator<npl_rxpdr_dsp_tc_map_key_t, npl_rxpdr_dsp_tc_map_value_t> npl_rxpdr_dsp_tc_map_table_translator_t;
    
    /// table_translator for table: sch_oqse_cfg
    
    typedef npl_table_translator<npl_sch_oqse_cfg_key_t, npl_sch_oqse_cfg_value_t> npl_sch_oqse_cfg_table_translator_t;
    
    /// table_translator for table: second_ene_static_table
    
    typedef npl_ternary_table_translator<npl_second_ene_static_table_key_t, npl_second_ene_static_table_value_t> npl_second_ene_static_table_table_translator_t;
    
    /// table_translator for table: select_inject_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_select_inject_next_macro_static_table_key_t, npl_select_inject_next_macro_static_table_value_t> npl_select_inject_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: service_lp_attributes_table
    
    typedef npl_table_translator<npl_service_lp_attributes_table_key_t, npl_service_lp_attributes_table_value_t> npl_service_lp_attributes_table_table_translator_t;
    
    /// table_translator for table: service_mapping_em0_ac_port_table
    
    typedef npl_table_translator<npl_service_mapping_em0_ac_port_table_key_t, npl_service_mapping_em0_ac_port_table_value_t> npl_service_mapping_em0_ac_port_table_table_translator_t;
    
    /// table_translator for table: service_mapping_em0_ac_port_tag_table
    
    typedef npl_table_translator<npl_service_mapping_em0_ac_port_tag_table_key_t, npl_service_mapping_em0_ac_port_tag_table_value_t> npl_service_mapping_em0_ac_port_tag_table_table_translator_t;
    
    /// table_translator for table: service_mapping_em0_ac_port_tag_tag_table
    
    typedef npl_table_translator<npl_service_mapping_em0_ac_port_tag_tag_table_key_t, npl_service_mapping_em0_ac_port_tag_tag_table_value_t> npl_service_mapping_em0_ac_port_tag_tag_table_table_translator_t;
    
    /// table_translator for table: service_mapping_em0_pwe_tag_table
    
    typedef npl_table_translator<npl_service_mapping_em0_pwe_tag_table_key_t, npl_service_mapping_em0_pwe_tag_table_value_t> npl_service_mapping_em0_pwe_tag_table_table_translator_t;
    
    /// table_translator for table: service_mapping_em1_ac_port_tag_table
    
    typedef npl_table_translator<npl_service_mapping_em1_ac_port_tag_table_key_t, npl_service_mapping_em1_ac_port_tag_table_value_t> npl_service_mapping_em1_ac_port_tag_table_table_translator_t;
    
    /// table_translator for table: service_mapping_tcam_ac_port_table
    
    typedef npl_ternary_table_translator<npl_service_mapping_tcam_ac_port_table_key_t, npl_service_mapping_tcam_ac_port_table_value_t> npl_service_mapping_tcam_ac_port_table_table_translator_t;
    
    /// table_translator for table: service_mapping_tcam_ac_port_tag_table
    
    typedef npl_ternary_table_translator<npl_service_mapping_tcam_ac_port_tag_table_key_t, npl_service_mapping_tcam_ac_port_tag_table_value_t> npl_service_mapping_tcam_ac_port_tag_table_table_translator_t;
    
    /// table_translator for table: service_mapping_tcam_ac_port_tag_tag_table
    
    typedef npl_ternary_table_translator<npl_service_mapping_tcam_ac_port_tag_tag_table_key_t, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t> npl_service_mapping_tcam_ac_port_tag_tag_table_table_translator_t;
    
    /// table_translator for table: service_mapping_tcam_pwe_tag_table
    
    typedef npl_ternary_table_translator<npl_service_mapping_tcam_pwe_tag_table_key_t, npl_service_mapping_tcam_pwe_tag_table_value_t> npl_service_mapping_tcam_pwe_tag_table_table_translator_t;
    
    /// table_translator for table: service_relay_attributes_table
    
    typedef npl_table_translator<npl_service_relay_attributes_table_key_t, npl_service_relay_attributes_table_value_t> npl_service_relay_attributes_table_table_translator_t;
    
    /// table_translator for table: set_ene_macro_and_bytes_to_remove_table
    
    typedef npl_table_translator<npl_set_ene_macro_and_bytes_to_remove_table_key_t, npl_set_ene_macro_and_bytes_to_remove_table_value_t> npl_set_ene_macro_and_bytes_to_remove_table_table_translator_t;
    
    /// table_translator for table: sgacl_table
    
    typedef npl_ternary_table_translator<npl_sgacl_table_key_t, npl_sgacl_table_value_t> npl_sgacl_table_table_translator_t;
    
    /// table_translator for table: sip_index_table
    
    typedef npl_table_translator<npl_sip_index_table_key_t, npl_sip_index_table_value_t> npl_sip_index_table_table_translator_t;
    
    /// table_translator for table: slice_modes_table
    
    typedef npl_table_translator<npl_slice_modes_table_key_t, npl_slice_modes_table_value_t> npl_slice_modes_table_table_translator_t;
    
    /// table_translator for table: slp_based_forwarding_table
    
    typedef npl_table_translator<npl_slp_based_forwarding_table_key_t, npl_slp_based_forwarding_table_value_t> npl_slp_based_forwarding_table_table_translator_t;
    
    /// table_translator for table: small_encap_mpls_he_asbr_table
    
    typedef npl_table_translator<npl_small_encap_mpls_he_asbr_table_key_t, npl_small_encap_mpls_he_asbr_table_value_t> npl_small_encap_mpls_he_asbr_table_table_translator_t;
    
    /// table_translator for table: small_encap_mpls_he_te_table
    
    typedef npl_table_translator<npl_small_encap_mpls_he_te_table_key_t, npl_small_encap_mpls_he_te_table_value_t> npl_small_encap_mpls_he_te_table_table_translator_t;
    
    /// table_translator for table: snoop_code_hw_table
    
    typedef npl_table_translator<npl_snoop_code_hw_table_key_t, npl_snoop_code_hw_table_value_t> npl_snoop_code_hw_table_table_translator_t;
    
    /// table_translator for table: snoop_table
    
    template<> inline
    bool npl_ternary_table_translator<npl_snoop_table_key_t, npl_snoop_table_value_t>::is_multi_line_entries()
    {
        return true;
    }
    typedef npl_ternary_table_translator<npl_snoop_table_key_t, npl_snoop_table_value_t> npl_snoop_table_table_translator_t;
    
    /// table_translator for table: snoop_to_dsp_in_npu_soft_header_table
    
    typedef npl_table_translator<npl_snoop_to_dsp_in_npu_soft_header_table_key_t, npl_snoop_to_dsp_in_npu_soft_header_table_value_t> npl_snoop_to_dsp_in_npu_soft_header_table_table_translator_t;
    
    /// table_translator for table: source_pif_hw_table
    
    typedef npl_table_translator<npl_source_pif_hw_table_key_t, npl_source_pif_hw_table_value_t> npl_source_pif_hw_table_table_translator_t;
    
    /// table_translator for table: stage2_lb_group_size_table
    
    typedef npl_table_translator<npl_stage2_lb_group_size_table_key_t, npl_stage2_lb_group_size_table_value_t> npl_stage2_lb_group_size_table_table_translator_t;
    
    /// table_translator for table: stage2_lb_table
    
    typedef npl_table_translator<npl_stage2_lb_table_key_t, npl_stage2_lb_table_value_t> npl_stage2_lb_table_table_translator_t;
    
    /// table_translator for table: stage3_lb_group_size_table
    
    typedef npl_table_translator<npl_stage3_lb_group_size_table_key_t, npl_stage3_lb_group_size_table_value_t> npl_stage3_lb_group_size_table_table_translator_t;
    
    /// table_translator for table: stage3_lb_table
    
    typedef npl_table_translator<npl_stage3_lb_table_key_t, npl_stage3_lb_table_value_t> npl_stage3_lb_table_table_translator_t;
    
    /// table_translator for table: stage3_lb_type_decoding_table
    
    typedef npl_table_translator<npl_stage3_lb_type_decoding_table_key_t, npl_stage3_lb_type_decoding_table_value_t> npl_stage3_lb_type_decoding_table_table_translator_t;
    
    /// table_translator for table: svl_next_macro_static_table
    
    typedef npl_ternary_table_translator<npl_svl_next_macro_static_table_key_t, npl_svl_next_macro_static_table_value_t> npl_svl_next_macro_static_table_table_translator_t;
    
    /// table_translator for table: te_headend_lsp_counter_offset_table
    
    typedef npl_ternary_table_translator<npl_te_headend_lsp_counter_offset_table_key_t, npl_te_headend_lsp_counter_offset_table_value_t> npl_te_headend_lsp_counter_offset_table_table_translator_t;
    
    /// table_translator for table: termination_to_forwarding_fi_hardwired_table
    
    typedef npl_table_translator<npl_termination_to_forwarding_fi_hardwired_table_key_t, npl_termination_to_forwarding_fi_hardwired_table_value_t> npl_termination_to_forwarding_fi_hardwired_table_table_translator_t;
    
    /// table_translator for table: tm_ibm_cmd_to_destination
    
    typedef npl_table_translator<npl_tm_ibm_cmd_to_destination_key_t, npl_tm_ibm_cmd_to_destination_value_t> npl_tm_ibm_cmd_to_destination_table_translator_t;
    
    /// table_translator for table: ts_cmd_hw_static_table
    
    typedef npl_table_translator<npl_ts_cmd_hw_static_table_key_t, npl_ts_cmd_hw_static_table_value_t> npl_ts_cmd_hw_static_table_table_translator_t;
    
    /// table_translator for table: tunnel_dlp_p_counter_offset_table
    
    typedef npl_ternary_table_translator<npl_tunnel_dlp_p_counter_offset_table_key_t, npl_tunnel_dlp_p_counter_offset_table_value_t> npl_tunnel_dlp_p_counter_offset_table_table_translator_t;
    
    /// table_translator for table: tunnel_qos_static_table
    
    typedef npl_table_translator<npl_tunnel_qos_static_table_key_t, npl_tunnel_qos_static_table_value_t> npl_tunnel_qos_static_table_table_translator_t;
    
    /// table_translator for table: tx_counters_block_config_table
    
    typedef npl_table_translator<npl_tx_counters_block_config_table_key_t, npl_tx_counters_block_config_table_value_t> npl_tx_counters_block_config_table_table_translator_t;
    
    /// table_translator for table: tx_error_handling_counter_table
    
    typedef npl_table_translator<npl_tx_error_handling_counter_table_key_t, npl_tx_error_handling_counter_table_value_t> npl_tx_error_handling_counter_table_table_translator_t;
    
    /// table_translator for table: tx_punt_eth_encap_table
    
    typedef npl_table_translator<npl_tx_punt_eth_encap_table_key_t, npl_tx_punt_eth_encap_table_value_t> npl_tx_punt_eth_encap_table_table_translator_t;
    
    /// table_translator for table: tx_redirect_code_table
    
    typedef npl_table_translator<npl_tx_redirect_code_table_key_t, npl_tx_redirect_code_table_value_t> npl_tx_redirect_code_table_table_translator_t;
    
    /// table_translator for table: txpdr_mc_list_size_table
    
    typedef npl_table_translator<npl_txpdr_mc_list_size_table_key_t, npl_txpdr_mc_list_size_table_value_t> npl_txpdr_mc_list_size_table_table_translator_t;
    
    /// table_translator for table: txpdr_tc_map_table
    
    typedef npl_table_translator<npl_txpdr_tc_map_table_key_t, npl_txpdr_tc_map_table_value_t> npl_txpdr_tc_map_table_table_translator_t;
    
    /// table_translator for table: txpp_dlp_profile_table
    
    typedef npl_table_translator<npl_txpp_dlp_profile_table_key_t, npl_txpp_dlp_profile_table_value_t> npl_txpp_dlp_profile_table_table_translator_t;
    
    /// table_translator for table: txpp_encap_qos_mapping_table
    
    typedef npl_table_translator<npl_txpp_encap_qos_mapping_table_key_t, npl_txpp_encap_qos_mapping_table_value_t> npl_txpp_encap_qos_mapping_table_table_translator_t;
    
    /// table_translator for table: txpp_first_enc_type_to_second_enc_type_offset
    
    typedef npl_table_translator<npl_txpp_first_enc_type_to_second_enc_type_offset_key_t, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t> npl_txpp_first_enc_type_to_second_enc_type_offset_table_translator_t;
    
    /// table_translator for table: txpp_fwd_header_type_is_l2_table
    
    typedef npl_table_translator<npl_txpp_fwd_header_type_is_l2_table_key_t, npl_txpp_fwd_header_type_is_l2_table_value_t> npl_txpp_fwd_header_type_is_l2_table_table_translator_t;
    
    /// table_translator for table: txpp_fwd_qos_mapping_table
    
    typedef npl_table_translator<npl_txpp_fwd_qos_mapping_table_key_t, npl_txpp_fwd_qos_mapping_table_value_t> npl_txpp_fwd_qos_mapping_table_table_translator_t;
    
    /// table_translator for table: txpp_ibm_enables_table
    
    typedef npl_table_translator<npl_txpp_ibm_enables_table_key_t, npl_txpp_ibm_enables_table_value_t> npl_txpp_ibm_enables_table_table_translator_t;
    
    /// table_translator for table: txpp_initial_npe_macro_table
    
    typedef npl_ternary_table_translator<npl_txpp_initial_npe_macro_table_key_t, npl_txpp_initial_npe_macro_table_value_t> npl_txpp_initial_npe_macro_table_table_translator_t;
    
    /// table_translator for table: txpp_mapping_qos_tag_table
    
    typedef npl_table_translator<npl_txpp_mapping_qos_tag_table_key_t, npl_txpp_mapping_qos_tag_table_value_t> npl_txpp_mapping_qos_tag_table_table_translator_t;
    
    /// table_translator for table: uc_ibm_tc_map_table
    
    typedef npl_table_translator<npl_uc_ibm_tc_map_table_key_t, npl_uc_ibm_tc_map_table_value_t> npl_uc_ibm_tc_map_table_table_translator_t;
    
    /// table_translator for table: urpf_ipsa_dest_is_lpts_static_table
    
    typedef npl_ternary_table_translator<npl_urpf_ipsa_dest_is_lpts_static_table_key_t, npl_urpf_ipsa_dest_is_lpts_static_table_value_t> npl_urpf_ipsa_dest_is_lpts_static_table_table_translator_t;
    
    /// table_translator for table: vlan_edit_tpid1_profile_hw_table
    
    typedef npl_table_translator<npl_vlan_edit_tpid1_profile_hw_table_key_t, npl_vlan_edit_tpid1_profile_hw_table_value_t> npl_vlan_edit_tpid1_profile_hw_table_table_translator_t;
    
    /// table_translator for table: vlan_edit_tpid2_profile_hw_table
    
    typedef npl_table_translator<npl_vlan_edit_tpid2_profile_hw_table_key_t, npl_vlan_edit_tpid2_profile_hw_table_value_t> npl_vlan_edit_tpid2_profile_hw_table_table_translator_t;
    
    /// table_translator for table: vlan_format_table
    
    typedef npl_ternary_table_translator<npl_vlan_format_table_key_t, npl_vlan_format_table_value_t> npl_vlan_format_table_table_translator_t;
    
    /// table_translator for table: vni_table
    
    typedef npl_table_translator<npl_vni_table_key_t, npl_vni_table_value_t> npl_vni_table_table_translator_t;
    
    /// table_translator for table: voq_cgm_slice_buffers_consumption_lut_for_enq_table
    
    typedef npl_table_translator<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t> npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_table_translator_t;
    
    /// table_translator for table: voq_cgm_slice_dram_cgm_profile_table
    
    typedef npl_table_translator<npl_voq_cgm_slice_dram_cgm_profile_table_key_t, npl_voq_cgm_slice_dram_cgm_profile_table_value_t> npl_voq_cgm_slice_dram_cgm_profile_table_table_translator_t;
    
    /// table_translator for table: voq_cgm_slice_pd_consumption_lut_for_enq_table
    
    typedef npl_table_translator<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t> npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_table_translator_t;
    
    /// table_translator for table: voq_cgm_slice_profile_buff_region_thresholds_table
    
    typedef npl_table_translator<npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t> npl_voq_cgm_slice_profile_buff_region_thresholds_table_table_translator_t;
    
    /// table_translator for table: voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table
    
    typedef npl_table_translator<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t> npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_table_translator_t;
    
    /// table_translator for table: voq_cgm_slice_profile_pkt_region_thresholds_table
    
    typedef npl_table_translator<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t> npl_voq_cgm_slice_profile_pkt_region_thresholds_table_table_translator_t;
    
    /// table_translator for table: voq_cgm_slice_slice_cgm_profile_table
    
    typedef npl_table_translator<npl_voq_cgm_slice_slice_cgm_profile_table_key_t, npl_voq_cgm_slice_slice_cgm_profile_table_value_t> npl_voq_cgm_slice_slice_cgm_profile_table_table_translator_t;
    
    /// table_translator for table: vsid_table
    
    typedef npl_table_translator<npl_vsid_table_key_t, npl_vsid_table_value_t> npl_vsid_table_table_translator_t;
    
    /// table_translator for table: vxlan_l2_dlp_table
    
    typedef npl_table_translator<npl_vxlan_l2_dlp_table_key_t, npl_vxlan_l2_dlp_table_value_t> npl_vxlan_l2_dlp_table_table_translator_t;
    
}

#endif
