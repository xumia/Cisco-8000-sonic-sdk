namespace cereal {

template <class Archive> void save(Archive&, const silicon_one::la_acl_field_def&);
template <class Archive> void load(Archive&, silicon_one::la_acl_field_def&);

template <class Archive> void save(Archive&, const npl_aux_table_key_t&);
template <class Archive> void load(Archive&, npl_aux_table_key_t&);

template <class Archive> void save(Archive&, const npl_egress_direct0_key_t&);
template <class Archive> void load(Archive&, npl_egress_direct0_key_t&);

template <class Archive> void save(Archive&, const npl_egress_direct1_key_t&);
template <class Archive> void load(Archive&, npl_egress_direct1_key_t&);

template <class Archive> void save(Archive&, const npl_lb_key_t&);
template <class Archive> void load(Archive&, npl_lb_key_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db__key_t&);
template <class Archive> void load(Archive&, npl_mc_em_db__key_t&);

template <class Archive> void save(Archive&, const npl_packed_ud_160_key_t&);
template <class Archive> void load(Archive&, npl_packed_ud_160_key_t&);

template <class Archive> void save(Archive&, const npl_packed_ud_320_key_t&);
template <class Archive> void load(Archive&, npl_packed_ud_320_key_t&);

template <class Archive> void save(Archive&, const npl_pbts_map_table_key_t&);
template <class Archive> void load(Archive&, npl_pbts_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_reassembly_source_port_map_key_t&);
template <class Archive> void load(Archive&, npl_reassembly_source_port_map_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_first_macro_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_first_macro_table_key_t&);

template <class Archive> void save(Archive&, const npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t&);
template <class Archive> void load(Archive&, npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t&);

template <class Archive> void save(Archive&, const npl_mac_forwarding_key_t&);
template <class Archive> void load(Archive&, npl_mac_forwarding_key_t&);

template <class Archive> void save(Archive&, const npl_redirect_stage_og_key_t&);
template <class Archive> void load(Archive&, npl_redirect_stage_og_key_t&);

template <class Archive> void save(Archive&, const npl_ud_key_t&);
template <class Archive> void load(Archive&, npl_ud_key_t&);

template <class Archive> void save(Archive&, const npl_qos_mapping_key_t&);
template <class Archive> void load(Archive&, npl_qos_mapping_key_t&);

template <class Archive> void save(Archive&, const npl_acl_map_fi_header_type_to_protocol_number_table_key_t&);
template <class Archive> void load(Archive&, npl_acl_map_fi_header_type_to_protocol_number_table_key_t&);

template <class Archive> void save(Archive&, const npl_acl_map_fi_header_type_to_protocol_number_table_value_t&);
template <class Archive> void load(Archive&, npl_acl_map_fi_header_type_to_protocol_number_table_value_t&);

template <class Archive> void save(Archive&, const npl_additional_labels_table_key_t&);
template <class Archive> void load(Archive&, npl_additional_labels_table_key_t&);

template <class Archive> void save(Archive&, const npl_additional_labels_table_value_t&);
template <class Archive> void load(Archive&, npl_additional_labels_table_value_t&);

template <class Archive> void save(Archive&, const npl_all_reachable_vector_key_t&);
template <class Archive> void load(Archive&, npl_all_reachable_vector_key_t&);

template <class Archive> void save(Archive&, const npl_all_reachable_vector_value_t&);
template <class Archive> void load(Archive&, npl_all_reachable_vector_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_desired_tx_interval_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_desired_tx_interval_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_desired_tx_interval_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_desired_tx_interval_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_detection_multiple_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_detection_multiple_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_detection_multiple_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_detection_multiple_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_event_queue_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_event_queue_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_event_queue_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_event_queue_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_inner_da_high_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_inner_da_high_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_inner_da_high_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_inner_da_high_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_inner_da_low_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_inner_da_low_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_inner_da_low_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_inner_da_low_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_inner_ethernet_header_static_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_inner_ethernet_header_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_inner_ethernet_header_static_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_inner_ethernet_header_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_ttl_static_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_ttl_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_ttl_static_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_ttl_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_A_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_A_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_A_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_A_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_B_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_B_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_B_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_B_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_C_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_C_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_C_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_C_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_D_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_D_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_sip_D_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_sip_D_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_punt_encap_static_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_punt_encap_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_punt_encap_static_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_punt_encap_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_required_tx_interval_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_required_tx_interval_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_required_tx_interval_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_required_tx_interval_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_rx_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_rx_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_rx_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_rx_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_set_inject_type_static_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_set_inject_type_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_set_inject_type_static_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_set_inject_type_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_udp_port_map_static_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_udp_port_map_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_udp_port_map_static_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_udp_port_map_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_bfd_udp_port_static_table_key_t&);
template <class Archive> void load(Archive&, npl_bfd_udp_port_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_bfd_udp_port_static_table_value_t&);
template <class Archive> void load(Archive&, npl_bfd_udp_port_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_bitmap_oqg_map_table_key_t&);
template <class Archive> void load(Archive&, npl_bitmap_oqg_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_bitmap_oqg_map_table_value_t&);
template <class Archive> void load(Archive&, npl_bitmap_oqg_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_bvn_tc_map_table_key_t&);
template <class Archive> void load(Archive&, npl_bvn_tc_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_bvn_tc_map_table_value_t&);
template <class Archive> void load(Archive&, npl_bvn_tc_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_calc_checksum_enable_table_key_t&);
template <class Archive> void load(Archive&, npl_calc_checksum_enable_table_key_t&);

template <class Archive> void save(Archive&, const npl_calc_checksum_enable_table_value_t&);
template <class Archive> void load(Archive&, npl_calc_checksum_enable_table_value_t&);

template <class Archive> void save(Archive&, const npl_ccm_flags_table_key_t&);
template <class Archive> void load(Archive&, npl_ccm_flags_table_key_t&);

template <class Archive> void save(Archive&, const npl_ccm_flags_table_value_t&);
template <class Archive> void load(Archive&, npl_ccm_flags_table_value_t&);

template <class Archive> void save(Archive&, const npl_cif2npa_c_lri_macro_key_t&);
template <class Archive> void load(Archive&, npl_cif2npa_c_lri_macro_key_t&);

template <class Archive> void save(Archive&, const npl_cif2npa_c_lri_macro_value_t&);
template <class Archive> void load(Archive&, npl_cif2npa_c_lri_macro_value_t&);

template <class Archive> void save(Archive&, const npl_cif2npa_c_mps_macro_key_t&);
template <class Archive> void load(Archive&, npl_cif2npa_c_mps_macro_key_t&);

template <class Archive> void save(Archive&, const npl_cif2npa_c_mps_macro_value_t&);
template <class Archive> void load(Archive&, npl_cif2npa_c_mps_macro_value_t&);

template <class Archive> void save(Archive&, const npl_counters_block_config_table_key_t&);
template <class Archive> void load(Archive&, npl_counters_block_config_table_key_t&);

template <class Archive> void save(Archive&, const npl_counters_block_config_table_value_t&);
template <class Archive> void load(Archive&, npl_counters_block_config_table_value_t&);

template <class Archive> void save(Archive&, const npl_counters_voq_block_map_table_key_t&);
template <class Archive> void load(Archive&, npl_counters_voq_block_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_counters_voq_block_map_table_value_t&);
template <class Archive> void load(Archive&, npl_counters_voq_block_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_cud_is_multicast_bitmap_key_t&);
template <class Archive> void load(Archive&, npl_cud_is_multicast_bitmap_key_t&);

template <class Archive> void save(Archive&, const npl_cud_is_multicast_bitmap_value_t&);
template <class Archive> void load(Archive&, npl_cud_is_multicast_bitmap_value_t&);

template <class Archive> void save(Archive&, const npl_cud_narrow_hw_table_key_t&);
template <class Archive> void load(Archive&, npl_cud_narrow_hw_table_key_t&);

template <class Archive> void save(Archive&, const npl_cud_narrow_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_cud_narrow_hw_table_value_t&);

template <class Archive> void save(Archive&, const npl_cud_wide_hw_table_key_t&);
template <class Archive> void load(Archive&, npl_cud_wide_hw_table_key_t&);

template <class Archive> void save(Archive&, const npl_cud_wide_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_cud_wide_hw_table_value_t&);

template <class Archive> void save(Archive&, const npl_default_egress_ipv4_sec_acl_table_key_t&);
template <class Archive> void load(Archive&, npl_default_egress_ipv4_sec_acl_table_key_t&);

template <class Archive> void save(Archive&, const npl_default_egress_ipv4_sec_acl_table_value_t&);
template <class Archive> void load(Archive&, npl_default_egress_ipv4_sec_acl_table_value_t&);

template <class Archive> void save(Archive&, const npl_default_egress_ipv6_acl_sec_table_key_t&);
template <class Archive> void load(Archive&, npl_default_egress_ipv6_acl_sec_table_key_t&);

template <class Archive> void save(Archive&, const npl_default_egress_ipv6_acl_sec_table_value_t&);
template <class Archive> void load(Archive&, npl_default_egress_ipv6_acl_sec_table_value_t&);

template <class Archive> void save(Archive&, const npl_dest_slice_voq_map_table_key_t&);
template <class Archive> void load(Archive&, npl_dest_slice_voq_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_dest_slice_voq_map_table_value_t&);
template <class Archive> void load(Archive&, npl_dest_slice_voq_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_destination_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_destination_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_destination_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_destination_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_device_mode_table_key_t&);
template <class Archive> void load(Archive&, npl_device_mode_table_key_t&);

template <class Archive> void save(Archive&, const npl_device_mode_table_value_t&);
template <class Archive> void load(Archive&, npl_device_mode_table_value_t&);

template <class Archive> void save(Archive&, const npl_dsp_l2_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_dsp_l2_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_dsp_l2_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_dsp_l2_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_dsp_l3_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_dsp_l3_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_dsp_l3_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_dsp_l3_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_dummy_dip_index_table_key_t&);
template <class Archive> void load(Archive&, npl_dummy_dip_index_table_key_t&);

template <class Archive> void save(Archive&, const npl_dummy_dip_index_table_value_t&);
template <class Archive> void load(Archive&, npl_dummy_dip_index_table_value_t&);

template <class Archive> void save(Archive&, const npl_ecn_remark_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ecn_remark_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ecn_remark_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ecn_remark_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_egress_mac_ipv4_sec_acl_table_key_t&);
template <class Archive> void load(Archive&, npl_egress_mac_ipv4_sec_acl_table_key_t&);

template <class Archive> void save(Archive&, const npl_egress_mac_ipv4_sec_acl_table_value_t&);
template <class Archive> void load(Archive&, npl_egress_mac_ipv4_sec_acl_table_value_t&);

template <class Archive> void save(Archive&, const npl_egress_nh_and_svi_direct0_table_key_t&);
template <class Archive> void load(Archive&, npl_egress_nh_and_svi_direct0_table_key_t&);

template <class Archive> void save(Archive&, const npl_egress_nh_and_svi_direct0_table_value_t&);
template <class Archive> void load(Archive&, npl_egress_nh_and_svi_direct0_table_value_t&);

template <class Archive> void save(Archive&, const npl_egress_nh_and_svi_direct1_table_key_t&);
template <class Archive> void load(Archive&, npl_egress_nh_and_svi_direct1_table_key_t&);

template <class Archive> void save(Archive&, const npl_egress_nh_and_svi_direct1_table_value_t&);
template <class Archive> void load(Archive&, npl_egress_nh_and_svi_direct1_table_value_t&);

template <class Archive> void save(Archive&, const npl_em_mp_table_key_t&);
template <class Archive> void load(Archive&, npl_em_mp_table_key_t&);

template <class Archive> void save(Archive&, const npl_em_mp_table_value_t&);
template <class Archive> void load(Archive&, npl_em_mp_table_value_t&);

template <class Archive> void save(Archive&, const npl_em_pfc_cong_table_key_t&);
template <class Archive> void load(Archive&, npl_em_pfc_cong_table_key_t&);

template <class Archive> void save(Archive&, const npl_em_pfc_cong_table_value_t&);
template <class Archive> void load(Archive&, npl_em_pfc_cong_table_value_t&);

template <class Archive> void save(Archive&, const npl_ene_byte_addition_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ene_byte_addition_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ene_byte_addition_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ene_byte_addition_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_code_tpid_profile_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ene_macro_code_tpid_profile_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_code_tpid_profile_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ene_macro_code_tpid_profile_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_erpp_fabric_counters_offset_table_key_t&);
template <class Archive> void load(Archive&, npl_erpp_fabric_counters_offset_table_key_t&);

template <class Archive> void save(Archive&, const npl_erpp_fabric_counters_offset_table_value_t&);
template <class Archive> void load(Archive&, npl_erpp_fabric_counters_offset_table_value_t&);

template <class Archive> void save(Archive&, const npl_erpp_fabric_counters_table_key_t&);
template <class Archive> void load(Archive&, npl_erpp_fabric_counters_table_key_t&);

template <class Archive> void save(Archive&, const npl_erpp_fabric_counters_table_value_t&);
template <class Archive> void load(Archive&, npl_erpp_fabric_counters_table_value_t&);

template <class Archive> void save(Archive&, const npl_eth_meter_profile_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_eth_meter_profile_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_eth_meter_profile_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_eth_meter_profile_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_eth_oam_set_da_mc2_static_table_key_t&);
template <class Archive> void load(Archive&, npl_eth_oam_set_da_mc2_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_eth_oam_set_da_mc2_static_table_value_t&);
template <class Archive> void load(Archive&, npl_eth_oam_set_da_mc2_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_eth_oam_set_da_mc_static_table_key_t&);
template <class Archive> void load(Archive&, npl_eth_oam_set_da_mc_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_eth_oam_set_da_mc_static_table_value_t&);
template <class Archive> void load(Archive&, npl_eth_oam_set_da_mc_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_eth_rtf_conf_set_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_eth_rtf_conf_set_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_eth_rtf_conf_set_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_eth_rtf_conf_set_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_eve_byte_addition_static_table_key_t&);
template <class Archive> void load(Archive&, npl_eve_byte_addition_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_eve_byte_addition_static_table_value_t&);
template <class Archive> void load(Archive&, npl_eve_byte_addition_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_eve_to_ethernet_ene_static_table_key_t&);
template <class Archive> void load(Archive&, npl_eve_to_ethernet_ene_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_eve_to_ethernet_ene_static_table_value_t&);
template <class Archive> void load(Archive&, npl_eve_to_ethernet_ene_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_event_queue_table_key_t&);
template <class Archive> void load(Archive&, npl_event_queue_table_key_t&);

template <class Archive> void save(Archive&, const npl_event_queue_table_value_t&);
template <class Archive> void load(Archive&, npl_event_queue_table_value_t&);

template <class Archive> void save(Archive&, const npl_external_aux_table_key_t&);
template <class Archive> void load(Archive&, npl_external_aux_table_key_t&);

template <class Archive> void save(Archive&, const npl_external_aux_table_value_t&);
template <class Archive> void load(Archive&, npl_external_aux_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_and_tm_header_size_static_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_and_tm_header_size_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_and_tm_header_size_static_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_and_tm_header_size_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_header_ene_macro_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_header_ene_macro_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_header_ene_macro_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_header_ene_macro_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_header_types_static_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_header_types_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_header_types_static_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_header_types_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_headers_type_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_headers_type_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_headers_type_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_headers_type_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_init_cfg_key_t&);
template <class Archive> void load(Archive&, npl_fabric_init_cfg_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_init_cfg_value_t&);
template <class Archive> void load(Archive&, npl_fabric_init_cfg_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_npuh_size_calculation_static_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_npuh_size_calculation_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_npuh_size_calculation_static_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_npuh_size_calculation_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_out_color_map_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_out_color_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_out_color_map_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_out_color_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_fwd_error_handling_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_fwd_error_handling_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_fwd_error_handling_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_fwd_error_handling_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_fwd_error_handling_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_fwd_error_handling_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_fwd_error_handling_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_fwd_error_handling_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_term_error_handling_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_term_error_handling_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_term_error_handling_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_term_error_handling_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_term_error_handling_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_term_error_handling_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_rx_term_error_handling_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_rx_term_error_handling_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_smcid_threshold_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_smcid_threshold_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_smcid_threshold_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_smcid_threshold_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_term_error_checker_static_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_term_error_checker_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_term_error_checker_static_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_term_error_checker_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_tm_headers_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_tm_headers_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_tm_headers_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_tm_headers_table_value_t&);

template <class Archive> void save(Archive&, const npl_fabric_transmit_error_checker_static_table_key_t&);
template <class Archive> void load(Archive&, npl_fabric_transmit_error_checker_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_fabric_transmit_error_checker_static_table_value_t&);
template <class Archive> void load(Archive&, npl_fabric_transmit_error_checker_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_fb_link_2_link_bundle_table_key_t&);
template <class Archive> void load(Archive&, npl_fb_link_2_link_bundle_table_key_t&);

template <class Archive> void save(Archive&, const npl_fb_link_2_link_bundle_table_value_t&);
template <class Archive> void load(Archive&, npl_fb_link_2_link_bundle_table_value_t&);

template <class Archive> void save(Archive&, const npl_fe_broadcast_bmp_table_key_t&);
template <class Archive> void load(Archive&, npl_fe_broadcast_bmp_table_key_t&);

template <class Archive> void save(Archive&, const npl_fe_broadcast_bmp_table_value_t&);
template <class Archive> void load(Archive&, npl_fe_broadcast_bmp_table_value_t&);

template <class Archive> void save(Archive&, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t&);
template <class Archive> void load(Archive&, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t&);
template <class Archive> void load(Archive&, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_fe_smcid_threshold_table_key_t&);
template <class Archive> void load(Archive&, npl_fe_smcid_threshold_table_key_t&);

template <class Archive> void save(Archive&, const npl_fe_smcid_threshold_table_value_t&);
template <class Archive> void load(Archive&, npl_fe_smcid_threshold_table_value_t&);

template <class Archive> void save(Archive&, const npl_fe_smcid_to_mcid_table_key_t&);
template <class Archive> void load(Archive&, npl_fe_smcid_to_mcid_table_key_t&);

template <class Archive> void save(Archive&, const npl_fe_smcid_to_mcid_table_value_t&);
template <class Archive> void load(Archive&, npl_fe_smcid_to_mcid_table_value_t&);

template <class Archive> void save(Archive&, const npl_fe_uc_link_bundle_desc_table_key_t&);
template <class Archive> void load(Archive&, npl_fe_uc_link_bundle_desc_table_key_t&);

template <class Archive> void save(Archive&, const npl_fe_uc_link_bundle_desc_table_value_t&);
template <class Archive> void load(Archive&, npl_fe_uc_link_bundle_desc_table_value_t&);

template <class Archive> void save(Archive&, const npl_fi_core_tcam_table_key_t&);
template <class Archive> void load(Archive&, npl_fi_core_tcam_table_key_t&);

template <class Archive> void save(Archive&, const npl_fi_core_tcam_table_value_t&);
template <class Archive> void load(Archive&, npl_fi_core_tcam_table_value_t&);

template <class Archive> void save(Archive&, const npl_fi_macro_config_table_key_t&);
template <class Archive> void load(Archive&, npl_fi_macro_config_table_key_t&);

template <class Archive> void save(Archive&, const npl_fi_macro_config_table_value_t&);
template <class Archive> void load(Archive&, npl_fi_macro_config_table_value_t&);

template <class Archive> void save(Archive&, const npl_filb_voq_mapping_key_t&);
template <class Archive> void load(Archive&, npl_filb_voq_mapping_key_t&);

template <class Archive> void save(Archive&, const npl_filb_voq_mapping_value_t&);
template <class Archive> void load(Archive&, npl_filb_voq_mapping_value_t&);

template <class Archive> void save(Archive&, const npl_first_ene_static_table_key_t&);
template <class Archive> void load(Archive&, npl_first_ene_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_first_ene_static_table_value_t&);
template <class Archive> void load(Archive&, npl_first_ene_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_frm_db_fabric_routing_table_key_t&);
template <class Archive> void load(Archive&, npl_frm_db_fabric_routing_table_key_t&);

template <class Archive> void save(Archive&, const npl_frm_db_fabric_routing_table_value_t&);
template <class Archive> void load(Archive&, npl_frm_db_fabric_routing_table_value_t&);

template <class Archive> void save(Archive&, const npl_fwd_destination_to_tm_result_data_key_t&);
template <class Archive> void load(Archive&, npl_fwd_destination_to_tm_result_data_key_t&);

template <class Archive> void save(Archive&, const npl_fwd_destination_to_tm_result_data_value_t&);
template <class Archive> void load(Archive&, npl_fwd_destination_to_tm_result_data_value_t&);

template <class Archive> void save(Archive&, const npl_fwd_type_to_ive_enable_table_key_t&);
template <class Archive> void load(Archive&, npl_fwd_type_to_ive_enable_table_key_t&);

template <class Archive> void save(Archive&, const npl_fwd_type_to_ive_enable_table_value_t&);
template <class Archive> void load(Archive&, npl_fwd_type_to_ive_enable_table_value_t&);

template <class Archive> void save(Archive&, const npl_get_ecm_meter_ptr_table_key_t&);
template <class Archive> void load(Archive&, npl_get_ecm_meter_ptr_table_key_t&);

template <class Archive> void save(Archive&, const npl_get_ecm_meter_ptr_table_value_t&);
template <class Archive> void load(Archive&, npl_get_ecm_meter_ptr_table_value_t&);

template <class Archive> void save(Archive&, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t&);
template <class Archive> void load(Archive&, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t&);
template <class Archive> void load(Archive&, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_get_l2_rtf_conf_set_and_init_stages_key_t&);
template <class Archive> void load(Archive&, npl_get_l2_rtf_conf_set_and_init_stages_key_t&);

template <class Archive> void save(Archive&, const npl_get_l2_rtf_conf_set_and_init_stages_value_t&);
template <class Archive> void load(Archive&, npl_get_l2_rtf_conf_set_and_init_stages_value_t&);

template <class Archive> void save(Archive&, const npl_get_non_comp_mc_value_static_table_key_t&);
template <class Archive> void load(Archive&, npl_get_non_comp_mc_value_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_get_non_comp_mc_value_static_table_value_t&);
template <class Archive> void load(Archive&, npl_get_non_comp_mc_value_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_gre_proto_static_table_key_t&);
template <class Archive> void load(Archive&, npl_gre_proto_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_gre_proto_static_table_value_t&);
template <class Archive> void load(Archive&, npl_gre_proto_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_hmc_cgm_cgm_lut_table_key_t&);
template <class Archive> void load(Archive&, npl_hmc_cgm_cgm_lut_table_key_t&);

template <class Archive> void save(Archive&, const npl_hmc_cgm_cgm_lut_table_value_t&);
template <class Archive> void load(Archive&, npl_hmc_cgm_cgm_lut_table_value_t&);

template <class Archive> void save(Archive&, const npl_hmc_cgm_profile_global_table_key_t&);
template <class Archive> void load(Archive&, npl_hmc_cgm_profile_global_table_key_t&);

template <class Archive> void save(Archive&, const npl_hmc_cgm_profile_global_table_value_t&);
template <class Archive> void load(Archive&, npl_hmc_cgm_profile_global_table_value_t&);

template <class Archive> void save(Archive&, const npl_ibm_cmd_table_key_t&);
template <class Archive> void load(Archive&, npl_ibm_cmd_table_key_t&);

template <class Archive> void save(Archive&, const npl_ibm_cmd_table_value_t&);
template <class Archive> void load(Archive&, npl_ibm_cmd_table_value_t&);

template <class Archive> void save(Archive&, const npl_ibm_mc_cmd_to_encap_data_table_key_t&);
template <class Archive> void load(Archive&, npl_ibm_mc_cmd_to_encap_data_table_key_t&);

template <class Archive> void save(Archive&, const npl_ibm_mc_cmd_to_encap_data_table_value_t&);
template <class Archive> void load(Archive&, npl_ibm_mc_cmd_to_encap_data_table_value_t&);

template <class Archive> void save(Archive&, const npl_ibm_uc_cmd_to_encap_data_table_key_t&);
template <class Archive> void load(Archive&, npl_ibm_uc_cmd_to_encap_data_table_key_t&);

template <class Archive> void save(Archive&, const npl_ibm_uc_cmd_to_encap_data_table_value_t&);
template <class Archive> void load(Archive&, npl_ibm_uc_cmd_to_encap_data_table_value_t&);

template <class Archive> void save(Archive&, const npl_ifgb_tc_lut_table_key_t&);
template <class Archive> void load(Archive&, npl_ifgb_tc_lut_table_key_t&);

template <class Archive> void save(Archive&, const npl_ifgb_tc_lut_table_value_t&);
template <class Archive> void load(Archive&, npl_ifgb_tc_lut_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_ip_qos_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_ip_qos_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_ip_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_ip_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_eth_db1_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_eth_db1_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_eth_db1_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_eth_db1_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_eth_db2_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_eth_db2_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_eth_db2_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_eth_db2_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db1_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db1_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db1_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db1_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db1_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db1_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db2_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db2_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db2_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db2_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db2_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db2_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db3_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db3_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db3_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db3_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db3_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db3_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db4_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db4_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db4_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db4_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db4_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv4_db4_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db1_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db1_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db1_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db1_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db1_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db2_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db2_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db2_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db2_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db2_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db2_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db3_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db3_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db3_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db3_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db3_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db3_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db4_160_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db4_160_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db4_160_f1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db4_160_f1_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db4_320_f0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ingress_rtf_ipv6_db4_320_f0_table_value_t&);
template <class Archive> void load(Archive&, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t&);

template <class Archive> void save(Archive&, const npl_inject_down_select_ene_static_table_key_t&);
template <class Archive> void load(Archive&, npl_inject_down_select_ene_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_inject_down_select_ene_static_table_value_t&);
template <class Archive> void load(Archive&, npl_inject_down_select_ene_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_inject_down_tx_redirect_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_inject_down_tx_redirect_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_inject_down_tx_redirect_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_inject_down_tx_redirect_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_inject_mact_ldb_to_output_lr_key_t&);
template <class Archive> void load(Archive&, npl_inject_mact_ldb_to_output_lr_key_t&);

template <class Archive> void save(Archive&, const npl_inject_mact_ldb_to_output_lr_value_t&);
template <class Archive> void load(Archive&, npl_inject_mact_ldb_to_output_lr_value_t&);

template <class Archive> void save(Archive&, const npl_inject_up_pif_ifg_init_data_table_key_t&);
template <class Archive> void load(Archive&, npl_inject_up_pif_ifg_init_data_table_key_t&);

template <class Archive> void save(Archive&, const npl_inject_up_pif_ifg_init_data_table_value_t&);
template <class Archive> void load(Archive&, npl_inject_up_pif_ifg_init_data_table_value_t&);

template <class Archive> void save(Archive&, const npl_inject_up_ssp_init_data_table_key_t&);
template <class Archive> void load(Archive&, npl_inject_up_ssp_init_data_table_key_t&);

template <class Archive> void save(Archive&, const npl_inject_up_ssp_init_data_table_value_t&);
template <class Archive> void load(Archive&, npl_inject_up_ssp_init_data_table_value_t&);

template <class Archive> void save(Archive&, const npl_inner_tpid_table_key_t&);
template <class Archive> void load(Archive&, npl_inner_tpid_table_key_t&);

template <class Archive> void save(Archive&, const npl_inner_tpid_table_value_t&);
template <class Archive> void load(Archive&, npl_inner_tpid_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_ingress_cmp_mcid_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_ingress_cmp_mcid_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_ingress_cmp_mcid_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_ingress_cmp_mcid_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_mc_local_inject_type_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_mc_local_inject_type_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_mc_local_inject_type_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_mc_local_inject_type_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_mc_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_mc_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_mc_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_mc_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_meter_profile_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_meter_profile_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_meter_profile_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_meter_profile_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_prefix_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_prefix_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_prefix_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_prefix_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_relay_to_vni_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_relay_to_vni_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_relay_to_vni_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_relay_to_vni_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_rx_global_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_rx_global_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_rx_global_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_rx_global_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_mc_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ip_ver_mc_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_mc_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ip_ver_mc_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_acl_sport_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_acl_sport_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_acl_sport_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_acl_sport_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_lpm_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_lpm_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_lpm_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_lpm_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_lpts_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_lpts_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_lpts_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_lpts_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_og_pcl_em_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_og_pcl_em_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_og_pcl_em_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_og_pcl_em_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_og_pcl_lpm_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_og_pcl_lpm_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_og_pcl_lpm_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_og_pcl_lpm_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_rtf_conf_set_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_rtf_conf_set_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_rtf_conf_set_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_rtf_conf_set_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_vrf_dip_em_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_vrf_dip_em_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_vrf_dip_em_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_vrf_dip_em_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv4_vrf_s_g_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv4_vrf_s_g_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv4_vrf_s_g_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv4_vrf_s_g_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_acl_sport_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_acl_sport_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_acl_sport_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_acl_sport_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_first_fragment_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_first_fragment_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_first_fragment_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_first_fragment_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_lpm_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_lpm_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_lpm_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_lpm_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_lpts_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_lpts_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_lpts_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_lpts_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_mc_select_qos_id_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_mc_select_qos_id_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_mc_select_qos_id_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_mc_select_qos_id_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_og_pcl_em_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_og_pcl_em_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_og_pcl_em_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_og_pcl_em_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_og_pcl_lpm_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_og_pcl_lpm_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_og_pcl_lpm_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_og_pcl_lpm_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_rtf_conf_set_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_rtf_conf_set_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_rtf_conf_set_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_rtf_conf_set_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_sip_compression_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_sip_compression_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_sip_compression_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_sip_compression_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_vrf_dip_em_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_vrf_dip_em_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_vrf_dip_em_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_vrf_dip_em_table_value_t&);

template <class Archive> void save(Archive&, const npl_ipv6_vrf_s_g_table_key_t&);
template <class Archive> void load(Archive&, npl_ipv6_vrf_s_g_table_key_t&);

template <class Archive> void save(Archive&, const npl_ipv6_vrf_s_g_table_value_t&);
template <class Archive> void load(Archive&, npl_ipv6_vrf_s_g_table_value_t&);

template <class Archive> void save(Archive&, const npl_is_pacific_b1_static_table_key_t&);
template <class Archive> void load(Archive&, npl_is_pacific_b1_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_is_pacific_b1_static_table_value_t&);
template <class Archive> void load(Archive&, npl_is_pacific_b1_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_dlp_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_dlp_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_dlp_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_dlp_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lp_profile_filter_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lp_profile_filter_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lp_profile_filter_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lp_profile_filter_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ctrl_fields_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ctrl_fields_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ctrl_fields_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ctrl_fields_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ip_fragment_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ip_fragment_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ip_fragment_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ip_fragment_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ipv4_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ipv4_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ipv4_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ipv4_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ipv6_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ipv6_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ipv6_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ipv6_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_mac_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_mac_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_mac_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_mac_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_protocol_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_protocol_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_protocol_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_protocol_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_skip_p2p_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_skip_p2p_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_skip_p2p_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_skip_p2p_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_termination_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_termination_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_termination_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_termination_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l2_tunnel_term_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l2_tunnel_term_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l2_tunnel_term_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l2_tunnel_term_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_p_counter_offset_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_p_counter_offset_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_p_counter_offset_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_p_counter_offset_table_value_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_table_value_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_classify_ip_tunnels_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_termination_classify_ip_tunnels_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_classify_ip_tunnels_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_termination_classify_ip_tunnels_table_value_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_termination_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_termination_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_termination_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l3_tunnel_termination_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_tunnel_termination_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_tunnel_termination_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_tunnel_termination_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_l3_vxlan_overlay_sa_table_key_t&);
template <class Archive> void load(Archive&, npl_l3_vxlan_overlay_sa_table_key_t&);

template <class Archive> void save(Archive&, const npl_l3_vxlan_overlay_sa_table_value_t&);
template <class Archive> void load(Archive&, npl_l3_vxlan_overlay_sa_table_value_t&);

template <class Archive> void save(Archive&, const npl_large_encap_global_lsp_prefix_table_key_t&);
template <class Archive> void load(Archive&, npl_large_encap_global_lsp_prefix_table_key_t&);

template <class Archive> void save(Archive&, const npl_large_encap_global_lsp_prefix_table_value_t&);
template <class Archive> void load(Archive&, npl_large_encap_global_lsp_prefix_table_value_t&);

template <class Archive> void save(Archive&, const npl_large_encap_ip_tunnel_table_key_t&);
template <class Archive> void load(Archive&, npl_large_encap_ip_tunnel_table_key_t&);

template <class Archive> void save(Archive&, const npl_large_encap_ip_tunnel_table_value_t&);
template <class Archive> void load(Archive&, npl_large_encap_ip_tunnel_table_value_t&);

template <class Archive> void save(Archive&, const npl_large_encap_mpls_he_no_ldp_table_key_t&);
template <class Archive> void load(Archive&, npl_large_encap_mpls_he_no_ldp_table_key_t&);

template <class Archive> void save(Archive&, const npl_large_encap_mpls_he_no_ldp_table_value_t&);
template <class Archive> void load(Archive&, npl_large_encap_mpls_he_no_ldp_table_value_t&);

template <class Archive> void save(Archive&, const npl_large_encap_mpls_ldp_over_te_table_key_t&);
template <class Archive> void load(Archive&, npl_large_encap_mpls_ldp_over_te_table_key_t&);

template <class Archive> void save(Archive&, const npl_large_encap_mpls_ldp_over_te_table_value_t&);
template <class Archive> void load(Archive&, npl_large_encap_mpls_ldp_over_te_table_value_t&);

template <class Archive> void save(Archive&, const npl_large_encap_te_he_tunnel_id_table_key_t&);
template <class Archive> void load(Archive&, npl_large_encap_te_he_tunnel_id_table_key_t&);

template <class Archive> void save(Archive&, const npl_large_encap_te_he_tunnel_id_table_value_t&);
template <class Archive> void load(Archive&, npl_large_encap_te_he_tunnel_id_table_value_t&);

template <class Archive> void save(Archive&, const npl_latest_learn_records_table_key_t&);
template <class Archive> void load(Archive&, npl_latest_learn_records_table_key_t&);

template <class Archive> void save(Archive&, const npl_latest_learn_records_table_value_t&);
template <class Archive> void load(Archive&, npl_latest_learn_records_table_value_t&);

template <class Archive> void save(Archive&, const npl_learn_manager_cfg_max_learn_type_reg_key_t&);
template <class Archive> void load(Archive&, npl_learn_manager_cfg_max_learn_type_reg_key_t&);

template <class Archive> void save(Archive&, const npl_learn_manager_cfg_max_learn_type_reg_value_t&);
template <class Archive> void load(Archive&, npl_learn_manager_cfg_max_learn_type_reg_value_t&);

template <class Archive> void save(Archive&, const npl_learn_record_fifo_table_key_t&);
template <class Archive> void load(Archive&, npl_learn_record_fifo_table_key_t&);

template <class Archive> void save(Archive&, const npl_learn_record_fifo_table_value_t&);
template <class Archive> void load(Archive&, npl_learn_record_fifo_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_fabric_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_fabric_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_fabric_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_fabric_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_npu_base_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_npu_base_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_npu_base_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_npu_base_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_npu_encap_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_npu_encap_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_npu_encap_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_npu_encap_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_0_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_0_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_0_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_0_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_1_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_1_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_1_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_1_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_2_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_2_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_2_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_2_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_3_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_3_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_nw_3_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_nw_3_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_stages_cfg_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_stages_cfg_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_stages_cfg_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_stages_cfg_table_value_t&);

template <class Archive> void save(Archive&, const npl_light_fi_tm_table_key_t&);
template <class Archive> void load(Archive&, npl_light_fi_tm_table_key_t&);

template <class Archive> void save(Archive&, const npl_light_fi_tm_table_value_t&);
template <class Archive> void load(Archive&, npl_light_fi_tm_table_value_t&);

template <class Archive> void save(Archive&, const npl_link_relay_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_link_relay_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_link_relay_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_link_relay_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_link_up_vector_key_t&);
template <class Archive> void load(Archive&, npl_link_up_vector_key_t&);

template <class Archive> void save(Archive&, const npl_link_up_vector_value_t&);
template <class Archive> void load(Archive&, npl_link_up_vector_value_t&);

template <class Archive> void save(Archive&, const npl_lp_over_lag_table_key_t&);
template <class Archive> void load(Archive&, npl_lp_over_lag_table_key_t&);

template <class Archive> void save(Archive&, const npl_lp_over_lag_table_value_t&);
template <class Archive> void load(Archive&, npl_lp_over_lag_table_value_t&);

template <class Archive> void save(Archive&, const npl_lpm_destination_prefix_map_table_key_t&);
template <class Archive> void load(Archive&, npl_lpm_destination_prefix_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_lpm_destination_prefix_map_table_value_t&);
template <class Archive> void load(Archive&, npl_lpm_destination_prefix_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_lpts_2nd_lookup_table_key_t&);
template <class Archive> void load(Archive&, npl_lpts_2nd_lookup_table_key_t&);

template <class Archive> void save(Archive&, const npl_lpts_2nd_lookup_table_value_t&);
template <class Archive> void load(Archive&, npl_lpts_2nd_lookup_table_value_t&);

template <class Archive> void save(Archive&, const npl_lpts_meter_table_key_t&);
template <class Archive> void load(Archive&, npl_lpts_meter_table_key_t&);

template <class Archive> void save(Archive&, const npl_lpts_meter_table_value_t&);
template <class Archive> void load(Archive&, npl_lpts_meter_table_value_t&);

template <class Archive> void save(Archive&, const npl_lpts_og_application_table_key_t&);
template <class Archive> void load(Archive&, npl_lpts_og_application_table_key_t&);

template <class Archive> void save(Archive&, const npl_lpts_og_application_table_value_t&);
template <class Archive> void load(Archive&, npl_lpts_og_application_table_value_t&);

template <class Archive> void save(Archive&, const npl_lr_filter_write_ptr_reg_key_t&);
template <class Archive> void load(Archive&, npl_lr_filter_write_ptr_reg_key_t&);

template <class Archive> void save(Archive&, const npl_lr_filter_write_ptr_reg_value_t&);
template <class Archive> void load(Archive&, npl_lr_filter_write_ptr_reg_value_t&);

template <class Archive> void save(Archive&, const npl_lr_write_ptr_reg_key_t&);
template <class Archive> void load(Archive&, npl_lr_write_ptr_reg_key_t&);

template <class Archive> void save(Archive&, const npl_lr_write_ptr_reg_value_t&);
template <class Archive> void load(Archive&, npl_lr_write_ptr_reg_value_t&);

template <class Archive> void save(Archive&, const npl_mac_af_npp_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_af_npp_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_af_npp_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_af_npp_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_da_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_da_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_da_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_da_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_ethernet_rate_limit_type_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_ethernet_rate_limit_type_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_ethernet_rate_limit_type_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_ethernet_rate_limit_type_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_forwarding_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_forwarding_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_forwarding_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_forwarding_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_mc_em_termination_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_mc_em_termination_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_mc_em_termination_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_mc_em_termination_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_mc_tcam_termination_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_mc_tcam_termination_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_mc_tcam_termination_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_mc_tcam_termination_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_qos_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_qos_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_g_ipv4_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_relay_g_ipv4_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_g_ipv4_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_relay_g_ipv4_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_g_ipv6_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_relay_g_ipv6_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_g_ipv6_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_relay_g_ipv6_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_to_vni_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_relay_to_vni_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_to_vni_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_relay_to_vni_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_em_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_termination_em_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_em_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_termination_em_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_termination_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_termination_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_no_da_em_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_termination_no_da_em_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_no_da_em_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_termination_no_da_em_table_value_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_tcam_table_key_t&);
template <class Archive> void load(Archive&, npl_mac_termination_tcam_table_key_t&);

template <class Archive> void save(Archive&, const npl_mac_termination_tcam_table_value_t&);
template <class Archive> void load(Archive&, npl_mac_termination_tcam_table_value_t&);

template <class Archive> void save(Archive&, const npl_map_ene_subcode_to8bit_static_table_key_t&);
template <class Archive> void load(Archive&, npl_map_ene_subcode_to8bit_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_map_ene_subcode_to8bit_static_table_value_t&);
template <class Archive> void load(Archive&, npl_map_ene_subcode_to8bit_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_map_inject_ccm_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_map_inject_ccm_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_map_inject_ccm_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_map_inject_ccm_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_map_more_labels_static_table_key_t&);
template <class Archive> void load(Archive&, npl_map_more_labels_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_map_more_labels_static_table_value_t&);
template <class Archive> void load(Archive&, npl_map_more_labels_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t&);
template <class Archive> void load(Archive&, npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t&);
template <class Archive> void load(Archive&, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t&);
template <class Archive> void load(Archive&, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t&);
template <class Archive> void load(Archive&, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_map_tx_punt_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_map_tx_punt_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_map_tx_punt_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_map_tx_punt_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_map_tx_punt_rcy_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_map_tx_punt_rcy_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_map_tx_punt_rcy_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_map_tx_punt_rcy_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mc_bitmap_base_voq_lookup_table_key_t&);
template <class Archive> void load(Archive&, npl_mc_bitmap_base_voq_lookup_table_key_t&);

template <class Archive> void save(Archive&, const npl_mc_bitmap_base_voq_lookup_table_value_t&);
template <class Archive> void load(Archive&, npl_mc_bitmap_base_voq_lookup_table_value_t&);

template <class Archive> void save(Archive&, const npl_mc_bitmap_tc_map_table_key_t&);
template <class Archive> void load(Archive&, npl_mc_bitmap_tc_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_mc_bitmap_tc_map_table_value_t&);
template <class Archive> void load(Archive&, npl_mc_bitmap_tc_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_mc_copy_id_map_key_t&);
template <class Archive> void load(Archive&, npl_mc_copy_id_map_key_t&);

template <class Archive> void save(Archive&, const npl_mc_copy_id_map_value_t&);
template <class Archive> void load(Archive&, npl_mc_copy_id_map_value_t&);

template <class Archive> void save(Archive&, const npl_mc_cud_is_wide_table_key_t&);
template <class Archive> void load(Archive&, npl_mc_cud_is_wide_table_key_t&);

template <class Archive> void save(Archive&, const npl_mc_cud_is_wide_table_value_t&);
template <class Archive> void load(Archive&, npl_mc_cud_is_wide_table_value_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db_key_t&);
template <class Archive> void load(Archive&, npl_mc_em_db_key_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db_value_t&);
template <class Archive> void load(Archive&, npl_mc_em_db_value_t&);

template <class Archive> void save(Archive&, const npl_mc_emdb_tc_map_table_key_t&);
template <class Archive> void load(Archive&, npl_mc_emdb_tc_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_mc_emdb_tc_map_table_value_t&);
template <class Archive> void load(Archive&, npl_mc_emdb_tc_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_mc_fe_links_bmp_key_t&);
template <class Archive> void load(Archive&, npl_mc_fe_links_bmp_key_t&);

template <class Archive> void save(Archive&, const npl_mc_fe_links_bmp_value_t&);
template <class Archive> void load(Archive&, npl_mc_fe_links_bmp_value_t&);

template <class Archive> void save(Archive&, const npl_mc_ibm_cud_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_mc_ibm_cud_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_mc_ibm_cud_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_mc_ibm_cud_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_mc_slice_bitmap_table_key_t&);
template <class Archive> void load(Archive&, npl_mc_slice_bitmap_table_key_t&);

template <class Archive> void save(Archive&, const npl_mc_slice_bitmap_table_value_t&);
template <class Archive> void load(Archive&, npl_mc_slice_bitmap_table_value_t&);

template <class Archive> void save(Archive&, const npl_meg_id_format_table_key_t&);
template <class Archive> void load(Archive&, npl_meg_id_format_table_key_t&);

template <class Archive> void save(Archive&, const npl_meg_id_format_table_value_t&);
template <class Archive> void load(Archive&, npl_meg_id_format_table_value_t&);

template <class Archive> void save(Archive&, const npl_mep_address_prefix_table_key_t&);
template <class Archive> void load(Archive&, npl_mep_address_prefix_table_key_t&);

template <class Archive> void save(Archive&, const npl_mep_address_prefix_table_value_t&);
template <class Archive> void load(Archive&, npl_mep_address_prefix_table_value_t&);

template <class Archive> void save(Archive&, const npl_mii_loopback_table_key_t&);
template <class Archive> void load(Archive&, npl_mii_loopback_table_key_t&);

template <class Archive> void save(Archive&, const npl_mii_loopback_table_value_t&);
template <class Archive> void load(Archive&, npl_mii_loopback_table_value_t&);

template <class Archive> void save(Archive&, const npl_mirror_code_hw_table_key_t&);
template <class Archive> void load(Archive&, npl_mirror_code_hw_table_key_t&);

template <class Archive> void save(Archive&, const npl_mirror_code_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_mirror_code_hw_table_value_t&);

template <class Archive> void save(Archive&, const npl_mirror_egress_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_mirror_egress_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_mirror_egress_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_mirror_egress_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_mirror_to_dsp_in_npu_soft_header_table_key_t&);
template <class Archive> void load(Archive&, npl_mirror_to_dsp_in_npu_soft_header_table_key_t&);

template <class Archive> void save(Archive&, const npl_mirror_to_dsp_in_npu_soft_header_table_value_t&);
template <class Archive> void load(Archive&, npl_mirror_to_dsp_in_npu_soft_header_table_value_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_enabled_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_enabled_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_enabled_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_enabled_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_table_key_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_table_key_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_table_value_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_table_value_t&);

template <class Archive> void save(Archive&, const npl_mp_aux_data_table_key_t&);
template <class Archive> void load(Archive&, npl_mp_aux_data_table_key_t&);

template <class Archive> void save(Archive&, const npl_mp_aux_data_table_value_t&);
template <class Archive> void load(Archive&, npl_mp_aux_data_table_value_t&);

template <class Archive> void save(Archive&, const npl_mp_data_table_key_t&);
template <class Archive> void load(Archive&, npl_mp_data_table_key_t&);

template <class Archive> void save(Archive&, const npl_mp_data_table_value_t&);
template <class Archive> void load(Archive&, npl_mp_data_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_encap_control_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_encap_control_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_encap_control_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_encap_control_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_forwarding_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_forwarding_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_forwarding_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_forwarding_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_header_offset_in_bytes_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_header_offset_in_bytes_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_header_offset_in_bytes_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_header_offset_in_bytes_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_l3_lsp_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_l3_lsp_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_l3_lsp_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_l3_lsp_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_labels_1_to_4_jump_offset_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_labels_1_to_4_jump_offset_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_labels_1_to_4_jump_offset_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_lsp_labels_config_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_lsp_labels_config_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_lsp_labels_config_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_lsp_labels_config_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_qos_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_qos_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_resolve_service_labels_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_resolve_service_labels_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_resolve_service_labels_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_resolve_service_labels_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_em0_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_em0_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_em0_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_em0_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_em1_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_em1_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_em1_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_em1_table_value_t&);

template <class Archive> void save(Archive&, const npl_mpls_vpn_enabled_static_table_key_t&);
template <class Archive> void load(Archive&, npl_mpls_vpn_enabled_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_mpls_vpn_enabled_static_table_value_t&);
template <class Archive> void load(Archive&, npl_mpls_vpn_enabled_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_ms_voq_fabric_context_offset_table_key_t&);
template <class Archive> void load(Archive&, npl_ms_voq_fabric_context_offset_table_key_t&);

template <class Archive> void save(Archive&, const npl_ms_voq_fabric_context_offset_table_value_t&);
template <class Archive> void load(Archive&, npl_ms_voq_fabric_context_offset_table_value_t&);

template <class Archive> void save(Archive&, const npl_my_ipv4_table_key_t&);
template <class Archive> void load(Archive&, npl_my_ipv4_table_key_t&);

template <class Archive> void save(Archive&, const npl_my_ipv4_table_value_t&);
template <class Archive> void load(Archive&, npl_my_ipv4_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_ce_ptr_table_key_t&);
template <class Archive> void load(Archive&, npl_native_ce_ptr_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_ce_ptr_table_value_t&);
template <class Archive> void load(Archive&, npl_native_ce_ptr_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_fec_table_key_t&);
template <class Archive> void load(Archive&, npl_native_fec_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_fec_table_value_t&);
template <class Archive> void load(Archive&, npl_native_fec_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_fec_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_native_fec_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_fec_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_native_fec_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_frr_table_key_t&);
template <class Archive> void load(Archive&, npl_native_frr_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_frr_table_value_t&);
template <class Archive> void load(Archive&, npl_native_frr_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_frr_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_native_frr_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_frr_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_native_frr_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_table_key_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_table_value_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_lb_group_size_table_key_t&);
template <class Archive> void load(Archive&, npl_native_lb_group_size_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_lb_group_size_table_value_t&);
template <class Archive> void load(Archive&, npl_native_lb_group_size_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_lb_table_key_t&);
template <class Archive> void load(Archive&, npl_native_lb_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_lb_table_value_t&);
template <class Archive> void load(Archive&, npl_native_lb_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_lb_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_native_lb_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_lb_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_native_lb_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_lp_is_pbts_prefix_table_key_t&);
template <class Archive> void load(Archive&, npl_native_lp_is_pbts_prefix_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_lp_is_pbts_prefix_table_value_t&);
template <class Archive> void load(Archive&, npl_native_lp_is_pbts_prefix_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_lp_pbts_map_table_key_t&);
template <class Archive> void load(Archive&, npl_native_lp_pbts_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_lp_pbts_map_table_value_t&);
template <class Archive> void load(Archive&, npl_native_lp_pbts_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_native_protection_table_key_t&);
template <class Archive> void load(Archive&, npl_native_protection_table_key_t&);

template <class Archive> void save(Archive&, const npl_native_protection_table_value_t&);
template <class Archive> void load(Archive&, npl_native_protection_table_value_t&);

template <class Archive> void save(Archive&, const npl_next_header_1_is_l4_over_ipv4_static_table_key_t&);
template <class Archive> void load(Archive&, npl_next_header_1_is_l4_over_ipv4_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_next_header_1_is_l4_over_ipv4_static_table_value_t&);
template <class Archive> void load(Archive&, npl_next_header_1_is_l4_over_ipv4_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_nh_macro_code_to_id_l6_static_table_key_t&);
template <class Archive> void load(Archive&, npl_nh_macro_code_to_id_l6_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_nh_macro_code_to_id_l6_static_table_value_t&);
template <class Archive> void load(Archive&, npl_nh_macro_code_to_id_l6_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_nhlfe_type_mapping_static_table_key_t&);
template <class Archive> void load(Archive&, npl_nhlfe_type_mapping_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_nhlfe_type_mapping_static_table_value_t&);
template <class Archive> void load(Archive&, npl_nhlfe_type_mapping_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_null_rtf_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_null_rtf_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_null_rtf_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_null_rtf_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_nw_smcid_threshold_table_key_t&);
template <class Archive> void load(Archive&, npl_nw_smcid_threshold_table_key_t&);

template <class Archive> void save(Archive&, const npl_nw_smcid_threshold_table_value_t&);
template <class Archive> void load(Archive&, npl_nw_smcid_threshold_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_drop_destination_static_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_drop_destination_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_drop_destination_static_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_drop_destination_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_event_queue_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_event_queue_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_event_queue_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_event_queue_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_get_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_get_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_get_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_get_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_1_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_1_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_1_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_1_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_2_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_2_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_2_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_2_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_3_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_3_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_3_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_3_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_4_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_4_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_punt_eth_hdr_4_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_punt_eth_hdr_4_table_value_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_table_key_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_table_key_t&);

template <class Archive> void save(Archive&, const npl_oamp_redirect_table_value_t&);
template <class Archive> void load(Archive&, npl_oamp_redirect_table_value_t&);

template <class Archive> void save(Archive&, const npl_obm_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_obm_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_obm_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_obm_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_og_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_og_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_og_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_og_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_outer_tpid_table_key_t&);
template <class Archive> void load(Archive&, npl_outer_tpid_table_key_t&);

template <class Archive> void save(Archive&, const npl_outer_tpid_table_value_t&);
template <class Archive> void load(Archive&, npl_outer_tpid_table_value_t&);

template <class Archive> void save(Archive&, const npl_overlay_ipv4_sip_table_key_t&);
template <class Archive> void load(Archive&, npl_overlay_ipv4_sip_table_key_t&);

template <class Archive> void save(Archive&, const npl_overlay_ipv4_sip_table_value_t&);
template <class Archive> void load(Archive&, npl_overlay_ipv4_sip_table_value_t&);

template <class Archive> void save(Archive&, const npl_pad_mtu_inj_check_static_table_key_t&);
template <class Archive> void load(Archive&, npl_pad_mtu_inj_check_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_pad_mtu_inj_check_static_table_value_t&);
template <class Archive> void load(Archive&, npl_pad_mtu_inj_check_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_path_lb_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_path_lb_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_path_lb_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_path_lb_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_path_lp_is_pbts_prefix_table_key_t&);
template <class Archive> void load(Archive&, npl_path_lp_is_pbts_prefix_table_key_t&);

template <class Archive> void save(Archive&, const npl_path_lp_is_pbts_prefix_table_value_t&);
template <class Archive> void load(Archive&, npl_path_lp_is_pbts_prefix_table_value_t&);

template <class Archive> void save(Archive&, const npl_path_lp_pbts_map_table_key_t&);
template <class Archive> void load(Archive&, npl_path_lp_pbts_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_path_lp_pbts_map_table_value_t&);
template <class Archive> void load(Archive&, npl_path_lp_pbts_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_path_lp_table_key_t&);
template <class Archive> void load(Archive&, npl_path_lp_table_key_t&);

template <class Archive> void save(Archive&, const npl_path_lp_table_value_t&);
template <class Archive> void load(Archive&, npl_path_lp_table_value_t&);

template <class Archive> void save(Archive&, const npl_path_lp_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_path_lp_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_path_lp_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_path_lp_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_path_protection_table_key_t&);
template <class Archive> void load(Archive&, npl_path_protection_table_key_t&);

template <class Archive> void save(Archive&, const npl_path_protection_table_value_t&);
template <class Archive> void load(Archive&, npl_path_protection_table_value_t&);

template <class Archive> void save(Archive&, const npl_pdoq_oq_ifc_mapping_key_t&);
template <class Archive> void load(Archive&, npl_pdoq_oq_ifc_mapping_key_t&);

template <class Archive> void save(Archive&, const npl_pdoq_oq_ifc_mapping_value_t&);
template <class Archive> void load(Archive&, npl_pdoq_oq_ifc_mapping_value_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_bank_pair_offset_table_key_t&);
template <class Archive> void load(Archive&, npl_pdvoq_bank_pair_offset_table_key_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_bank_pair_offset_table_value_t&);
template <class Archive> void load(Archive&, npl_pdvoq_bank_pair_offset_table_value_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_slice_voq_properties_table_key_t&);
template <class Archive> void load(Archive&, npl_pdvoq_slice_voq_properties_table_key_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_slice_voq_properties_table_value_t&);
template <class Archive> void load(Archive&, npl_pdvoq_slice_voq_properties_table_value_t&);

template <class Archive> void save(Archive&, const npl_per_asbr_and_dpe_table_key_t&);
template <class Archive> void load(Archive&, npl_per_asbr_and_dpe_table_key_t&);

template <class Archive> void save(Archive&, const npl_per_asbr_and_dpe_table_value_t&);
template <class Archive> void load(Archive&, npl_per_asbr_and_dpe_table_value_t&);

template <class Archive> void save(Archive&, const npl_per_pe_and_prefix_vpn_key_large_table_key_t&);
template <class Archive> void load(Archive&, npl_per_pe_and_prefix_vpn_key_large_table_key_t&);

template <class Archive> void save(Archive&, const npl_per_pe_and_prefix_vpn_key_large_table_value_t&);
template <class Archive> void load(Archive&, npl_per_pe_and_prefix_vpn_key_large_table_value_t&);

template <class Archive> void save(Archive&, const npl_per_pe_and_vrf_vpn_key_large_table_key_t&);
template <class Archive> void load(Archive&, npl_per_pe_and_vrf_vpn_key_large_table_key_t&);

template <class Archive> void save(Archive&, const npl_per_pe_and_vrf_vpn_key_large_table_value_t&);
template <class Archive> void load(Archive&, npl_per_pe_and_vrf_vpn_key_large_table_value_t&);

template <class Archive> void save(Archive&, const npl_per_port_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_per_port_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_per_port_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_per_port_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_per_vrf_mpls_forwarding_table_key_t&);
template <class Archive> void load(Archive&, npl_per_vrf_mpls_forwarding_table_key_t&);

template <class Archive> void save(Archive&, const npl_per_vrf_mpls_forwarding_table_value_t&);
template <class Archive> void load(Archive&, npl_per_vrf_mpls_forwarding_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_event_queue_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_event_queue_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_event_queue_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_event_queue_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_filter_wd_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_filter_wd_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_filter_wd_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_filter_wd_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_offset_from_vector_static_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_offset_from_vector_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_offset_from_vector_static_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_offset_from_vector_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_ssp_slice_map_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_ssp_slice_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_ssp_slice_map_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_ssp_slice_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_tc_latency_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_tc_latency_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_tc_latency_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_tc_latency_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_tc_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_tc_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_tc_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_tc_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_tc_wrap_latency_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_tc_wrap_latency_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_tc_wrap_latency_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_tc_wrap_latency_table_value_t&);

template <class Archive> void save(Archive&, const npl_pfc_vector_static_table_key_t&);
template <class Archive> void load(Archive&, npl_pfc_vector_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_pfc_vector_static_table_value_t&);
template <class Archive> void load(Archive&, npl_pfc_vector_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_pin_start_offset_macros_key_t&);
template <class Archive> void load(Archive&, npl_pin_start_offset_macros_key_t&);

template <class Archive> void save(Archive&, const npl_pin_start_offset_macros_value_t&);
template <class Archive> void load(Archive&, npl_pin_start_offset_macros_value_t&);

template <class Archive> void save(Archive&, const npl_pma_loopback_table_key_t&);
template <class Archive> void load(Archive&, npl_pma_loopback_table_key_t&);

template <class Archive> void save(Archive&, const npl_pma_loopback_table_value_t&);
template <class Archive> void load(Archive&, npl_pma_loopback_table_value_t&);

template <class Archive> void save(Archive&, const npl_port_dspa_group_size_table_key_t&);
template <class Archive> void load(Archive&, npl_port_dspa_group_size_table_key_t&);

template <class Archive> void save(Archive&, const npl_port_dspa_group_size_table_value_t&);
template <class Archive> void load(Archive&, npl_port_dspa_group_size_table_value_t&);

template <class Archive> void save(Archive&, const npl_port_dspa_table_key_t&);
template <class Archive> void load(Archive&, npl_port_dspa_table_key_t&);

template <class Archive> void save(Archive&, const npl_port_dspa_table_value_t&);
template <class Archive> void load(Archive&, npl_port_dspa_table_value_t&);

template <class Archive> void save(Archive&, const npl_port_dspa_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_port_dspa_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_port_dspa_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_port_dspa_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_port_npp_protection_table_key_t&);
template <class Archive> void load(Archive&, npl_port_npp_protection_table_key_t&);

template <class Archive> void save(Archive&, const npl_port_npp_protection_table_value_t&);
template <class Archive> void load(Archive&, npl_port_npp_protection_table_value_t&);

template <class Archive> void save(Archive&, const npl_port_npp_protection_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_port_npp_protection_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_port_npp_protection_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_port_npp_protection_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_port_protection_table_key_t&);
template <class Archive> void load(Archive&, npl_port_protection_table_key_t&);

template <class Archive> void save(Archive&, const npl_port_protection_table_value_t&);
template <class Archive> void load(Archive&, npl_port_protection_table_value_t&);

template <class Archive> void save(Archive&, const npl_punt_ethertype_static_table_key_t&);
template <class Archive> void load(Archive&, npl_punt_ethertype_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_punt_ethertype_static_table_value_t&);
template <class Archive> void load(Archive&, npl_punt_ethertype_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_punt_rcy_inject_header_ene_encap_table_key_t&);
template <class Archive> void load(Archive&, npl_punt_rcy_inject_header_ene_encap_table_key_t&);

template <class Archive> void save(Archive&, const npl_punt_rcy_inject_header_ene_encap_table_value_t&);
template <class Archive> void load(Archive&, npl_punt_rcy_inject_header_ene_encap_table_value_t&);

template <class Archive> void save(Archive&, const npl_punt_select_nw_ene_static_table_key_t&);
template <class Archive> void load(Archive&, npl_punt_select_nw_ene_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_punt_select_nw_ene_static_table_value_t&);
template <class Archive> void load(Archive&, npl_punt_select_nw_ene_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_punt_tunnel_transport_encap_table_key_t&);
template <class Archive> void load(Archive&, npl_punt_tunnel_transport_encap_table_key_t&);

template <class Archive> void save(Archive&, const npl_punt_tunnel_transport_encap_table_value_t&);
template <class Archive> void load(Archive&, npl_punt_tunnel_transport_encap_table_value_t&);

template <class Archive> void save(Archive&, const npl_punt_tunnel_transport_extended_encap_table_key_t&);
template <class Archive> void load(Archive&, npl_punt_tunnel_transport_extended_encap_table_key_t&);

template <class Archive> void save(Archive&, const npl_punt_tunnel_transport_extended_encap_table_value_t&);
template <class Archive> void load(Archive&, npl_punt_tunnel_transport_extended_encap_table_value_t&);

template <class Archive> void save(Archive&, const npl_punt_tunnel_transport_extended_encap_table2_key_t&);
template <class Archive> void load(Archive&, npl_punt_tunnel_transport_extended_encap_table2_key_t&);

template <class Archive> void save(Archive&, const npl_punt_tunnel_transport_extended_encap_table2_value_t&);
template <class Archive> void load(Archive&, npl_punt_tunnel_transport_extended_encap_table2_value_t&);

template <class Archive> void save(Archive&, const npl_pwe_label_table_key_t&);
template <class Archive> void load(Archive&, npl_pwe_label_table_key_t&);

template <class Archive> void save(Archive&, const npl_pwe_label_table_value_t&);
template <class Archive> void load(Archive&, npl_pwe_label_table_value_t&);

template <class Archive> void save(Archive&, const npl_pwe_to_l3_dest_table_key_t&);
template <class Archive> void load(Archive&, npl_pwe_to_l3_dest_table_key_t&);

template <class Archive> void save(Archive&, const npl_pwe_to_l3_dest_table_value_t&);
template <class Archive> void load(Archive&, npl_pwe_to_l3_dest_table_value_t&);

template <class Archive> void save(Archive&, const npl_pwe_vpls_label_table_key_t&);
template <class Archive> void load(Archive&, npl_pwe_vpls_label_table_key_t&);

template <class Archive> void save(Archive&, const npl_pwe_vpls_label_table_value_t&);
template <class Archive> void load(Archive&, npl_pwe_vpls_label_table_value_t&);

template <class Archive> void save(Archive&, const npl_pwe_vpls_tunnel_label_table_key_t&);
template <class Archive> void load(Archive&, npl_pwe_vpls_tunnel_label_table_key_t&);

template <class Archive> void save(Archive&, const npl_pwe_vpls_tunnel_label_table_value_t&);
template <class Archive> void load(Archive&, npl_pwe_vpls_tunnel_label_table_value_t&);

template <class Archive> void save(Archive&, const npl_reassembly_source_port_map_table_key_t&);
template <class Archive> void load(Archive&, npl_reassembly_source_port_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_reassembly_source_port_map_table_value_t&);
template <class Archive> void load(Archive&, npl_reassembly_source_port_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_recycle_override_table_key_t&);
template <class Archive> void load(Archive&, npl_recycle_override_table_key_t&);

template <class Archive> void save(Archive&, const npl_recycle_override_table_value_t&);
template <class Archive> void load(Archive&, npl_recycle_override_table_value_t&);

template <class Archive> void save(Archive&, const npl_recycled_inject_up_info_table_key_t&);
template <class Archive> void load(Archive&, npl_recycled_inject_up_info_table_key_t&);

template <class Archive> void save(Archive&, const npl_recycled_inject_up_info_table_value_t&);
template <class Archive> void load(Archive&, npl_recycled_inject_up_info_table_value_t&);

template <class Archive> void save(Archive&, const npl_redirect_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_redirect_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_redirect_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_redirect_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_redirect_table_key_t&);
template <class Archive> void load(Archive&, npl_redirect_table_key_t&);

template <class Archive> void save(Archive&, const npl_redirect_table_value_t&);
template <class Archive> void load(Archive&, npl_redirect_table_value_t&);

template <class Archive> void save(Archive&, const npl_resolution_pfc_select_table_key_t&);
template <class Archive> void load(Archive&, npl_resolution_pfc_select_table_key_t&);

template <class Archive> void save(Archive&, const npl_resolution_pfc_select_table_value_t&);
template <class Archive> void load(Archive&, npl_resolution_pfc_select_table_value_t&);

template <class Archive> void save(Archive&, const npl_resolution_set_next_macro_table_key_t&);
template <class Archive> void load(Archive&, npl_resolution_set_next_macro_table_key_t&);

template <class Archive> void save(Archive&, const npl_resolution_set_next_macro_table_value_t&);
template <class Archive> void load(Archive&, npl_resolution_set_next_macro_table_value_t&);

template <class Archive> void save(Archive&, const npl_rewrite_sa_prefix_index_table_key_t&);
template <class Archive> void load(Archive&, npl_rewrite_sa_prefix_index_table_key_t&);

template <class Archive> void save(Archive&, const npl_rewrite_sa_prefix_index_table_value_t&);
template <class Archive> void load(Archive&, npl_rewrite_sa_prefix_index_table_value_t&);

template <class Archive> void save(Archive&, const npl_rmep_last_time_table_key_t&);
template <class Archive> void load(Archive&, npl_rmep_last_time_table_key_t&);

template <class Archive> void save(Archive&, const npl_rmep_last_time_table_value_t&);
template <class Archive> void load(Archive&, npl_rmep_last_time_table_value_t&);

template <class Archive> void save(Archive&, const npl_rmep_state_table_key_t&);
template <class Archive> void load(Archive&, npl_rmep_state_table_key_t&);

template <class Archive> void save(Archive&, const npl_rmep_state_table_value_t&);
template <class Archive> void load(Archive&, npl_rmep_state_table_value_t&);

template <class Archive> void save(Archive&, const npl_rpf_fec_access_map_table_key_t&);
template <class Archive> void load(Archive&, npl_rpf_fec_access_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_rpf_fec_access_map_table_value_t&);
template <class Archive> void load(Archive&, npl_rpf_fec_access_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_rpf_fec_table_key_t&);
template <class Archive> void load(Archive&, npl_rpf_fec_table_key_t&);

template <class Archive> void save(Archive&, const npl_rpf_fec_table_value_t&);
template <class Archive> void load(Archive&, npl_rpf_fec_table_value_t&);

template <class Archive> void save(Archive&, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_rtf_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_rtf_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_rtf_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_rtf_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_counters_block_config_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_counters_block_config_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_counters_block_config_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_counters_block_config_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_fwd_error_handling_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_fwd_error_handling_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_fwd_error_handling_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_fwd_error_handling_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_fwd_error_handling_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_fwd_error_handling_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_fwd_error_handling_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_fwd_error_handling_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_ip_p_counter_offset_static_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_ip_p_counter_offset_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_ip_p_counter_offset_static_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_ip_p_counter_offset_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_map_npp_to_ssp_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_map_npp_to_ssp_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_map_npp_to_ssp_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_map_npp_to_ssp_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_attribute_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_attribute_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_attribute_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_attribute_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_profile_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_profile_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_profile_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_profile_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_shaper_configuration_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_shaper_configuration_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_shaper_configuration_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_shaper_configuration_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_distributed_meter_profile_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_distributed_meter_profile_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_distributed_meter_profile_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_distributed_meter_profile_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_exact_meter_decision_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_exact_meter_decision_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_exact_meter_decision_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_exact_meter_decision_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meter_profile_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meter_profile_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meter_profile_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meter_profile_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meter_shaper_configuration_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meter_shaper_configuration_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meter_shaper_configuration_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meter_shaper_configuration_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meters_attribute_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meters_attribute_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meters_attribute_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meters_attribute_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_rate_limiter_shaper_configuration_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_rate_limiter_shaper_configuration_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_rate_limiter_shaper_configuration_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_stat_meter_decision_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_meter_stat_meter_decision_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_stat_meter_decision_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_meter_stat_meter_decision_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_npu_to_tm_dest_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_npu_to_tm_dest_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_npu_to_tm_dest_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_npu_to_tm_dest_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_obm_code_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_obm_code_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_obm_code_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_obm_code_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_obm_punt_src_and_code_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_obm_punt_src_and_code_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_obm_punt_src_and_code_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_obm_punt_src_and_code_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_redirect_code_ext_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_redirect_code_ext_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_redirect_code_ext_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_redirect_code_ext_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_redirect_code_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_redirect_code_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_redirect_code_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_redirect_code_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_redirect_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_redirect_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_redirect_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_redirect_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_term_error_handling_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_term_error_handling_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_term_error_handling_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_term_error_handling_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_rx_term_error_handling_destination_table_key_t&);
template <class Archive> void load(Archive&, npl_rx_term_error_handling_destination_table_key_t&);

template <class Archive> void save(Archive&, const npl_rx_term_error_handling_destination_table_value_t&);
template <class Archive> void load(Archive&, npl_rx_term_error_handling_destination_table_value_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_lookup_table_key_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_lookup_table_key_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_lookup_table_value_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_lookup_table_value_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_tc_map_key_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_tc_map_key_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_tc_map_value_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_tc_map_value_t&);

template <class Archive> void save(Archive&, const npl_sch_oqse_cfg_key_t&);
template <class Archive> void load(Archive&, npl_sch_oqse_cfg_key_t&);

template <class Archive> void save(Archive&, const npl_sch_oqse_cfg_value_t&);
template <class Archive> void load(Archive&, npl_sch_oqse_cfg_value_t&);

template <class Archive> void save(Archive&, const npl_second_ene_static_table_key_t&);
template <class Archive> void load(Archive&, npl_second_ene_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_second_ene_static_table_value_t&);
template <class Archive> void load(Archive&, npl_second_ene_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_select_inject_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_select_inject_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_select_inject_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_select_inject_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_lp_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_service_lp_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_lp_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_service_lp_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_ac_port_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_ac_port_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_ac_port_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_ac_port_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_ac_port_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_ac_port_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_ac_port_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_ac_port_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_ac_port_tag_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_ac_port_tag_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_ac_port_tag_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_ac_port_tag_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_pwe_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_pwe_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em0_pwe_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em0_pwe_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em1_ac_port_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em1_ac_port_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_em1_ac_port_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_em1_ac_port_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_ac_port_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_ac_port_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_ac_port_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_ac_port_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_ac_port_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_ac_port_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_ac_port_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_ac_port_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_ac_port_tag_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_ac_port_tag_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_pwe_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_pwe_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_mapping_tcam_pwe_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_service_mapping_tcam_pwe_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_service_relay_attributes_table_key_t&);
template <class Archive> void load(Archive&, npl_service_relay_attributes_table_key_t&);

template <class Archive> void save(Archive&, const npl_service_relay_attributes_table_value_t&);
template <class Archive> void load(Archive&, npl_service_relay_attributes_table_value_t&);

template <class Archive> void save(Archive&, const npl_set_ene_macro_and_bytes_to_remove_table_key_t&);
template <class Archive> void load(Archive&, npl_set_ene_macro_and_bytes_to_remove_table_key_t&);

template <class Archive> void save(Archive&, const npl_set_ene_macro_and_bytes_to_remove_table_value_t&);
template <class Archive> void load(Archive&, npl_set_ene_macro_and_bytes_to_remove_table_value_t&);

template <class Archive> void save(Archive&, const npl_sgacl_table_key_t&);
template <class Archive> void load(Archive&, npl_sgacl_table_key_t&);

template <class Archive> void save(Archive&, const npl_sgacl_table_value_t&);
template <class Archive> void load(Archive&, npl_sgacl_table_value_t&);

template <class Archive> void save(Archive&, const npl_sip_index_table_key_t&);
template <class Archive> void load(Archive&, npl_sip_index_table_key_t&);

template <class Archive> void save(Archive&, const npl_sip_index_table_value_t&);
template <class Archive> void load(Archive&, npl_sip_index_table_value_t&);

template <class Archive> void save(Archive&, const npl_slice_modes_table_key_t&);
template <class Archive> void load(Archive&, npl_slice_modes_table_key_t&);

template <class Archive> void save(Archive&, const npl_slice_modes_table_value_t&);
template <class Archive> void load(Archive&, npl_slice_modes_table_value_t&);

template <class Archive> void save(Archive&, const npl_slp_based_forwarding_table_key_t&);
template <class Archive> void load(Archive&, npl_slp_based_forwarding_table_key_t&);

template <class Archive> void save(Archive&, const npl_slp_based_forwarding_table_value_t&);
template <class Archive> void load(Archive&, npl_slp_based_forwarding_table_value_t&);

template <class Archive> void save(Archive&, const npl_small_encap_mpls_he_asbr_table_key_t&);
template <class Archive> void load(Archive&, npl_small_encap_mpls_he_asbr_table_key_t&);

template <class Archive> void save(Archive&, const npl_small_encap_mpls_he_asbr_table_value_t&);
template <class Archive> void load(Archive&, npl_small_encap_mpls_he_asbr_table_value_t&);

template <class Archive> void save(Archive&, const npl_small_encap_mpls_he_te_table_key_t&);
template <class Archive> void load(Archive&, npl_small_encap_mpls_he_te_table_key_t&);

template <class Archive> void save(Archive&, const npl_small_encap_mpls_he_te_table_value_t&);
template <class Archive> void load(Archive&, npl_small_encap_mpls_he_te_table_value_t&);

template <class Archive> void save(Archive&, const npl_snoop_code_hw_table_key_t&);
template <class Archive> void load(Archive&, npl_snoop_code_hw_table_key_t&);

template <class Archive> void save(Archive&, const npl_snoop_code_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_snoop_code_hw_table_value_t&);

template <class Archive> void save(Archive&, const npl_snoop_table_key_t&);
template <class Archive> void load(Archive&, npl_snoop_table_key_t&);

template <class Archive> void save(Archive&, const npl_snoop_table_value_t&);
template <class Archive> void load(Archive&, npl_snoop_table_value_t&);

template <class Archive> void save(Archive&, const npl_snoop_to_dsp_in_npu_soft_header_table_key_t&);
template <class Archive> void load(Archive&, npl_snoop_to_dsp_in_npu_soft_header_table_key_t&);

template <class Archive> void save(Archive&, const npl_snoop_to_dsp_in_npu_soft_header_table_value_t&);
template <class Archive> void load(Archive&, npl_snoop_to_dsp_in_npu_soft_header_table_value_t&);

template <class Archive> void save(Archive&, const npl_source_pif_hw_table_key_t&);
template <class Archive> void load(Archive&, npl_source_pif_hw_table_key_t&);

template <class Archive> void save(Archive&, const npl_source_pif_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_source_pif_hw_table_value_t&);

template <class Archive> void save(Archive&, const npl_stage2_lb_group_size_table_key_t&);
template <class Archive> void load(Archive&, npl_stage2_lb_group_size_table_key_t&);

template <class Archive> void save(Archive&, const npl_stage2_lb_group_size_table_value_t&);
template <class Archive> void load(Archive&, npl_stage2_lb_group_size_table_value_t&);

template <class Archive> void save(Archive&, const npl_stage2_lb_table_key_t&);
template <class Archive> void load(Archive&, npl_stage2_lb_table_key_t&);

template <class Archive> void save(Archive&, const npl_stage2_lb_table_value_t&);
template <class Archive> void load(Archive&, npl_stage2_lb_table_value_t&);

template <class Archive> void save(Archive&, const npl_stage3_lb_group_size_table_key_t&);
template <class Archive> void load(Archive&, npl_stage3_lb_group_size_table_key_t&);

template <class Archive> void save(Archive&, const npl_stage3_lb_group_size_table_value_t&);
template <class Archive> void load(Archive&, npl_stage3_lb_group_size_table_value_t&);

template <class Archive> void save(Archive&, const npl_stage3_lb_table_key_t&);
template <class Archive> void load(Archive&, npl_stage3_lb_table_key_t&);

template <class Archive> void save(Archive&, const npl_stage3_lb_table_value_t&);
template <class Archive> void load(Archive&, npl_stage3_lb_table_value_t&);

template <class Archive> void save(Archive&, const npl_stage3_lb_type_decoding_table_key_t&);
template <class Archive> void load(Archive&, npl_stage3_lb_type_decoding_table_key_t&);

template <class Archive> void save(Archive&, const npl_stage3_lb_type_decoding_table_value_t&);
template <class Archive> void load(Archive&, npl_stage3_lb_type_decoding_table_value_t&);

template <class Archive> void save(Archive&, const npl_svl_next_macro_static_table_key_t&);
template <class Archive> void load(Archive&, npl_svl_next_macro_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_svl_next_macro_static_table_value_t&);
template <class Archive> void load(Archive&, npl_svl_next_macro_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_te_headend_lsp_counter_offset_table_key_t&);
template <class Archive> void load(Archive&, npl_te_headend_lsp_counter_offset_table_key_t&);

template <class Archive> void save(Archive&, const npl_te_headend_lsp_counter_offset_table_value_t&);
template <class Archive> void load(Archive&, npl_te_headend_lsp_counter_offset_table_value_t&);

template <class Archive> void save(Archive&, const npl_termination_to_forwarding_fi_hardwired_table_key_t&);
template <class Archive> void load(Archive&, npl_termination_to_forwarding_fi_hardwired_table_key_t&);

template <class Archive> void save(Archive&, const npl_termination_to_forwarding_fi_hardwired_table_value_t&);
template <class Archive> void load(Archive&, npl_termination_to_forwarding_fi_hardwired_table_value_t&);

template <class Archive> void save(Archive&, const npl_tm_ibm_cmd_to_destination_key_t&);
template <class Archive> void load(Archive&, npl_tm_ibm_cmd_to_destination_key_t&);

template <class Archive> void save(Archive&, const npl_tm_ibm_cmd_to_destination_value_t&);
template <class Archive> void load(Archive&, npl_tm_ibm_cmd_to_destination_value_t&);

template <class Archive> void save(Archive&, const npl_ts_cmd_hw_static_table_key_t&);
template <class Archive> void load(Archive&, npl_ts_cmd_hw_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_ts_cmd_hw_static_table_value_t&);
template <class Archive> void load(Archive&, npl_ts_cmd_hw_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_tunnel_dlp_p_counter_offset_table_key_t&);
template <class Archive> void load(Archive&, npl_tunnel_dlp_p_counter_offset_table_key_t&);

template <class Archive> void save(Archive&, const npl_tunnel_dlp_p_counter_offset_table_value_t&);
template <class Archive> void load(Archive&, npl_tunnel_dlp_p_counter_offset_table_value_t&);

template <class Archive> void save(Archive&, const npl_tunnel_qos_static_table_key_t&);
template <class Archive> void load(Archive&, npl_tunnel_qos_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_tunnel_qos_static_table_value_t&);
template <class Archive> void load(Archive&, npl_tunnel_qos_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_tx_counters_block_config_table_key_t&);
template <class Archive> void load(Archive&, npl_tx_counters_block_config_table_key_t&);

template <class Archive> void save(Archive&, const npl_tx_counters_block_config_table_value_t&);
template <class Archive> void load(Archive&, npl_tx_counters_block_config_table_value_t&);

template <class Archive> void save(Archive&, const npl_tx_error_handling_counter_table_key_t&);
template <class Archive> void load(Archive&, npl_tx_error_handling_counter_table_key_t&);

template <class Archive> void save(Archive&, const npl_tx_error_handling_counter_table_value_t&);
template <class Archive> void load(Archive&, npl_tx_error_handling_counter_table_value_t&);

template <class Archive> void save(Archive&, const npl_tx_punt_eth_encap_table_key_t&);
template <class Archive> void load(Archive&, npl_tx_punt_eth_encap_table_key_t&);

template <class Archive> void save(Archive&, const npl_tx_punt_eth_encap_table_value_t&);
template <class Archive> void load(Archive&, npl_tx_punt_eth_encap_table_value_t&);

template <class Archive> void save(Archive&, const npl_tx_redirect_code_table_key_t&);
template <class Archive> void load(Archive&, npl_tx_redirect_code_table_key_t&);

template <class Archive> void save(Archive&, const npl_tx_redirect_code_table_value_t&);
template <class Archive> void load(Archive&, npl_tx_redirect_code_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpdr_mc_list_size_table_key_t&);
template <class Archive> void load(Archive&, npl_txpdr_mc_list_size_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpdr_mc_list_size_table_value_t&);
template <class Archive> void load(Archive&, npl_txpdr_mc_list_size_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpdr_tc_map_table_key_t&);
template <class Archive> void load(Archive&, npl_txpdr_tc_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpdr_tc_map_table_value_t&);
template <class Archive> void load(Archive&, npl_txpdr_tc_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_dlp_profile_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_dlp_profile_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_dlp_profile_table_value_t&);
template <class Archive> void load(Archive&, npl_txpp_dlp_profile_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_encap_qos_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_encap_qos_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_encap_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_txpp_encap_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_first_enc_type_to_second_enc_type_offset_key_t&);
template <class Archive> void load(Archive&, npl_txpp_first_enc_type_to_second_enc_type_offset_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_first_enc_type_to_second_enc_type_offset_value_t&);
template <class Archive> void load(Archive&, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_fwd_header_type_is_l2_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_fwd_header_type_is_l2_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_fwd_header_type_is_l2_table_value_t&);
template <class Archive> void load(Archive&, npl_txpp_fwd_header_type_is_l2_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_fwd_qos_mapping_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_fwd_qos_mapping_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_fwd_qos_mapping_table_value_t&);
template <class Archive> void load(Archive&, npl_txpp_fwd_qos_mapping_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_ibm_enables_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_ibm_enables_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_ibm_enables_table_value_t&);
template <class Archive> void load(Archive&, npl_txpp_ibm_enables_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_initial_npe_macro_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_initial_npe_macro_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_initial_npe_macro_table_value_t&);
template <class Archive> void load(Archive&, npl_txpp_initial_npe_macro_table_value_t&);

template <class Archive> void save(Archive&, const npl_txpp_mapping_qos_tag_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_mapping_qos_tag_table_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_mapping_qos_tag_table_value_t&);
template <class Archive> void load(Archive&, npl_txpp_mapping_qos_tag_table_value_t&);

template <class Archive> void save(Archive&, const npl_uc_ibm_tc_map_table_key_t&);
template <class Archive> void load(Archive&, npl_uc_ibm_tc_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_uc_ibm_tc_map_table_value_t&);
template <class Archive> void load(Archive&, npl_uc_ibm_tc_map_table_value_t&);

template <class Archive> void save(Archive&, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t&);
template <class Archive> void load(Archive&, npl_urpf_ipsa_dest_is_lpts_static_table_key_t&);

template <class Archive> void save(Archive&, const npl_urpf_ipsa_dest_is_lpts_static_table_value_t&);
template <class Archive> void load(Archive&, npl_urpf_ipsa_dest_is_lpts_static_table_value_t&);

template <class Archive> void save(Archive&, const npl_vlan_edit_tpid1_profile_hw_table_key_t&);
template <class Archive> void load(Archive&, npl_vlan_edit_tpid1_profile_hw_table_key_t&);

template <class Archive> void save(Archive&, const npl_vlan_edit_tpid1_profile_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_vlan_edit_tpid1_profile_hw_table_value_t&);

template <class Archive> void save(Archive&, const npl_vlan_edit_tpid2_profile_hw_table_key_t&);
template <class Archive> void load(Archive&, npl_vlan_edit_tpid2_profile_hw_table_key_t&);

template <class Archive> void save(Archive&, const npl_vlan_edit_tpid2_profile_hw_table_value_t&);
template <class Archive> void load(Archive&, npl_vlan_edit_tpid2_profile_hw_table_value_t&);

template <class Archive> void save(Archive&, const npl_vlan_format_table_key_t&);
template <class Archive> void load(Archive&, npl_vlan_format_table_key_t&);

template <class Archive> void save(Archive&, const npl_vlan_format_table_value_t&);
template <class Archive> void load(Archive&, npl_vlan_format_table_value_t&);

template <class Archive> void save(Archive&, const npl_vni_table_key_t&);
template <class Archive> void load(Archive&, npl_vni_table_key_t&);

template <class Archive> void save(Archive&, const npl_vni_table_value_t&);
template <class Archive> void load(Archive&, npl_vni_table_value_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_dram_cgm_profile_table_key_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_dram_cgm_profile_table_key_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_dram_cgm_profile_table_value_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_dram_cgm_profile_table_value_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_slice_cgm_profile_table_key_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_slice_cgm_profile_table_key_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_slice_cgm_profile_table_value_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_slice_cgm_profile_table_value_t&);

template <class Archive> void save(Archive&, const npl_vsid_table_key_t&);
template <class Archive> void load(Archive&, npl_vsid_table_key_t&);

template <class Archive> void save(Archive&, const npl_vsid_table_value_t&);
template <class Archive> void load(Archive&, npl_vsid_table_value_t&);

template <class Archive> void save(Archive&, const npl_vxlan_l2_dlp_table_key_t&);
template <class Archive> void load(Archive&, npl_vxlan_l2_dlp_table_key_t&);

template <class Archive> void save(Archive&, const npl_vxlan_l2_dlp_table_value_t&);
template <class Archive> void load(Archive&, npl_vxlan_l2_dlp_table_value_t&);

template <class Archive> void save(Archive&, const silicon_one::resource_monitor&);
template <class Archive> void load(Archive&, silicon_one::resource_monitor&);

template <class Archive> void save(Archive&, const silicon_one::resource_monitor&);
template <class Archive> void load(Archive&, silicon_one::resource_monitor&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_port_common_base::subnet_count_map_key_t&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_port_common_base::subnet_count_map_key_t&);

template <class Archive> void save(Archive&, const silicon_one::la_vrf_port_common_base::ip_host_data&);
template <class Archive> void load(Archive&, silicon_one::la_vrf_port_common_base::ip_host_data&);

}

