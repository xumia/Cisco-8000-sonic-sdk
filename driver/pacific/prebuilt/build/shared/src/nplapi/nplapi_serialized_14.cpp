#define AUTO_SERIALIZE_CODE
#include "common/cereal_utils.h"

#ifdef CEREAL_DISABLE_OPTIMIZATION
// Disable optimizations as clang, GCC choke on this file in -O3 mode.
#ifdef __GNUC__
    #ifdef __clang__
        #pragma clang optimize off
    #else
        #pragma GCC optimize ("O0")
    #endif
#endif
#endif
#if CEREAL_MODE == CEREAL_MODE_BINARY
#include <cereal/archives/binary.hpp>
#elif CEREAL_MODE == CEREAL_MODE_JSON
#include <cereal/archives/json.hpp>
#elif CEREAL_MODE == CEREAL_MODE_XML
#include <cereal/archives/xml.hpp>
#endif
#include <cereal/types/array.hpp>
#include <cereal/types/atomic.hpp>
#include <cereal/types/base_class.hpp>
#include <cereal/types/bitset.hpp>
#include <cereal/types/chrono.hpp>
#include <cereal/types/forward_list.hpp>
#include <cereal/types/functional.hpp>
#include <cereal/types/list.hpp>
#include <cereal/types/map.hpp>
#include <cereal/types/memory.hpp>
#include <cereal/types/polymorphic.hpp>
#include <cereal/types/queue.hpp>
#include <cereal/types/set.hpp>
#include <cereal/types/stack.hpp>
#include <cereal/types/string.hpp>
#include <cereal/types/tuple.hpp>
#include <cereal/types/unordered_map.hpp>
#include <cereal/types/unordered_set.hpp>
#include <cereal/types/utility.hpp>
#include <cereal/types/vector.hpp>

#include "nplapi/compiled/api/include/nplapi/npl_table_types.h"
#include "nplapi/compiled/api/include/nplapi/npl_tables_static_init.h"
#include "nplapi/compiled/api/include/nplapi/npl_types.h"
#include "nplapi/compiled/api/include/nplapi_translator/npl_generic_data_structs.h"
#include "nplapi/compiled/api/include/nplapi_translator/npl_table_entry_translation.h"
#include "nplapi/device_tables.h"

template <class T>
static T&
cereal_gen_remove_const(const T& t)
{
    return const_cast<T&>(t);
}

#define CEREAL_GEN_COPY_ARRAY(from, to, size) \
for (size_t i = 0; i < size; ++i) {\
    to[i] = from[i];\
}

#define CEREAL_GEN_COMMA() ,
#include "nplapi/nplapi_serialized_fwd_declarations.h"

namespace cereal {

extern unsigned g_nplapi_serialization_version;

template <class Archive> void save(Archive&, const npl_base_voq_nr_t&);
template <class Archive> void load(Archive&, npl_base_voq_nr_t&);

template <class Archive> void save(Archive&, const npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t&);
template <class Archive> void load(Archive&, npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t&);

template <class Archive> void save(Archive&, const npl_bfd_em_t&);
template <class Archive> void load(Archive&, npl_bfd_em_t&);

template <class Archive> void save(Archive&, const npl_bfd_flags_t&);
template <class Archive> void load(Archive&, npl_bfd_flags_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv4_prot_shared_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv4_prot_shared_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_prot_shared_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_prot_shared_t&);

template <class Archive> void save(Archive&, const npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t&);
template <class Archive> void load(Archive&, npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t&);

template <class Archive> void save(Archive&, const npl_bfd_mp_table_transmit_b_payload_t&);
template <class Archive> void load(Archive&, npl_bfd_mp_table_transmit_b_payload_t&);

template <class Archive> void save(Archive&, const npl_bfd_transport_and_label_t&);
template <class Archive> void load(Archive&, npl_bfd_transport_and_label_t&);

template <class Archive> void save(Archive&, const npl_common_cntr_offset_t&);
template <class Archive> void load(Archive&, npl_common_cntr_offset_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_curr_and_next_prot_type_t&);
template <class Archive> void load(Archive&, npl_curr_and_next_prot_type_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_drop_punt_or_permit_t&);
template <class Archive> void load(Archive&, npl_drop_punt_or_permit_t&);

template <class Archive> void save(Archive&, const npl_dsp_map_info_t&);
template <class Archive> void load(Archive&, npl_dsp_map_info_t&);

template <class Archive> void save(Archive&, const npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t&);
template <class Archive> void load(Archive&, npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t&);

template <class Archive> void save(Archive&, const npl_eth_rtf_prop_over_fwd0_t&);
template <class Archive> void load(Archive&, npl_eth_rtf_prop_over_fwd0_t&);

template <class Archive> void save(Archive&, const npl_ethernet_header_flags_t&);
template <class Archive> void load(Archive&, npl_ethernet_header_flags_t&);

template <class Archive> void save(Archive&, const npl_ethernet_oam_em_t&);
template <class Archive> void load(Archive&, npl_ethernet_oam_em_t&);

template <class Archive> void save(Archive&, const npl_gre_encap_data_t&);
template <class Archive> void load(Archive&, npl_gre_encap_data_t&);

template <class Archive> void save(Archive&, const npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t&);
template <class Archive> void load(Archive&, npl_ibm_cmd_table_result_t_anonymous_union_voq_or_bitmap_t&);

template <class Archive> void save(Archive&, const npl_ingress_ptp_info_t&);
template <class Archive> void load(Archive&, npl_ingress_ptp_info_t&);

template <class Archive> void save(Archive&, const npl_ingress_qos_mapping_remark_t&);
template <class Archive> void load(Archive&, npl_ingress_qos_mapping_remark_t&);

template <class Archive> void save(Archive&, const npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t&);
template <class Archive> void load(Archive&, npl_initial_recycle_pd_nw_rx_data_t_anonymous_union_init_data_t&);

template <class Archive> void save(Archive&, const npl_ip_lpm_result_t_anonymous_union_destination_or_default_t&);
template <class Archive> void load(Archive&, npl_ip_lpm_result_t_anonymous_union_destination_or_default_t&);

template <class Archive> void save(Archive&, const npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t&);
template <class Archive> void load(Archive&, npl_ip_lpm_result_t_anonymous_union_rtype_or_is_fec_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_and_post_fwd_stage_t&);
template <class Archive> void load(Archive&, npl_ip_ver_and_post_fwd_stage_t&);

template <class Archive> void save(Archive&, const npl_ipv4_header_flags_t&);
template <class Archive> void load(Archive&, npl_ipv4_header_flags_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_init_rtf_stage_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive> void save(Archive&, const npl_ipv4_sip_dip_t&);
template <class Archive> void load(Archive&, npl_ipv4_sip_dip_t&);

template <class Archive> void save(Archive&, const npl_ipv6_header_flags_t&);
template <class Archive> void load(Archive&, npl_ipv6_header_flags_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_traps_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_traps_t&);

template <class Archive> void save(Archive&, const npl_l2_relay_id_t&);
template <class Archive> void load(Archive&, npl_l2_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_lm_command_t&);
template <class Archive> void load(Archive&, npl_lm_command_t&);

template <class Archive> void save(Archive&, const npl_lp_id_t&);
template <class Archive> void load(Archive&, npl_lp_id_t&);

template <class Archive> void save(Archive&, const npl_lpts_packet_flags_t&);
template <class Archive> void load(Archive&, npl_lpts_packet_flags_t&);

template <class Archive> void save(Archive&, const npl_lsp_labels_t&);
template <class Archive> void load(Archive&, npl_lsp_labels_t&);

template <class Archive> void save(Archive&, const npl_lsp_type_t&);
template <class Archive> void load(Archive&, npl_lsp_type_t&);

template <class Archive> void save(Archive&, const npl_lsr_encap_t_anonymous_union_lsp_t&);
template <class Archive> void load(Archive&, npl_lsr_encap_t_anonymous_union_lsp_t&);

template <class Archive> void save(Archive&, const npl_mac_addr_t&);
template <class Archive> void load(Archive&, npl_mac_addr_t&);

template <class Archive> void save(Archive&, const npl_mac_l2_relay_attributes_t&);
template <class Archive> void load(Archive&, npl_mac_l2_relay_attributes_t&);

template <class Archive> void save(Archive&, const npl_mc_copy_id_t&);
template <class Archive> void load(Archive&, npl_mc_copy_id_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db_result_tx_format_1_t&);
template <class Archive> void load(Archive&, npl_mc_em_db_result_tx_format_1_t&);

template <class Archive> void save(Archive&, const npl_mc_rx_tc_map_profile_t&);
template <class Archive> void load(Archive&, npl_mc_rx_tc_map_profile_t&);

template <class Archive> void save(Archive&, const npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t&);
template <class Archive> void load(Archive&, npl_mc_slice_bitmap_table_entry_t_anonymous_union_group_size_or_bitmap_t&);

template <class Archive> void save(Archive&, const npl_mc_tx_tc_map_profile_t&);
template <class Archive> void load(Archive&, npl_mc_tx_tc_map_profile_t&);

template <class Archive> void save(Archive&, const npl_mcid_t&);
template <class Archive> void load(Archive&, npl_mcid_t&);

template <class Archive> void save(Archive&, const npl_meg_id_t&);
template <class Archive> void load(Archive&, npl_meg_id_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_t&);

template <class Archive> void save(Archive&, const npl_more_labels_index_t&);
template <class Archive> void load(Archive&, npl_more_labels_index_t&);

template <class Archive> void save(Archive&, const npl_mpls_header_flags_t&);
template <class Archive> void load(Archive&, npl_mpls_header_flags_t&);

template <class Archive> void save(Archive&, const npl_mpls_header_t&);
template <class Archive> void load(Archive&, npl_mpls_header_t&);

template <class Archive> void save(Archive&, const npl_mpls_tp_em_t&);
template <class Archive> void load(Archive&, npl_mpls_tp_em_t&);

template <class Archive> void save(Archive&, const npl_native_frr_table_protection_entry_t&);
template <class Archive> void load(Archive&, npl_native_frr_table_protection_entry_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_destination1_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_destination1_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_destination2_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_destination2_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_destination_ip_tunnel_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_destination_ip_tunnel_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_destination_overlay_nh_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_destination_overlay_nh_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_destination_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_destination_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_destination_te_tunnel16b_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_destination_te_tunnel16b_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_narrow_raw_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_narrow_raw_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_stage2_ecmp_ce_ptr_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_stage2_ecmp_ce_ptr_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_stage2_ecmp_vpn_inter_as_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_stage2_p_nh_ce_ptr_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_stage2_p_nh_ce_ptr_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_stage3_nh_ce_ptr_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_stage3_nh_ce_ptr_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_table_protection_entry_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_table_protection_entry_t&);

template <class Archive> void save(Archive&, const npl_native_l2_lp_wide_raw_t&);
template <class Archive> void load(Archive&, npl_native_l2_lp_wide_raw_t&);

template <class Archive> void save(Archive&, const npl_native_protection_id_t&);
template <class Archive> void load(Archive&, npl_native_protection_id_t&);

template <class Archive> void save(Archive&, const npl_next_header_and_hop_limit_t&);
template <class Archive> void load(Archive&, npl_next_header_and_hop_limit_t&);

template <class Archive> void save(Archive&, const npl_no_acls_t&);
template <class Archive> void load(Archive&, npl_no_acls_t&);

template <class Archive> void save(Archive&, const npl_npu_encap_header_l2_dlp_t&);
template <class Archive> void load(Archive&, npl_npu_encap_header_l2_dlp_t&);

template <class Archive> void save(Archive&, const npl_num_labels_t&);
template <class Archive> void load(Archive&, npl_num_labels_t&);

template <class Archive> void save(Archive&, const npl_num_outer_transport_labels_t&);
template <class Archive> void load(Archive&, npl_num_outer_transport_labels_t&);

template <class Archive> void save(Archive&, const npl_og_lpm_compression_code_t&);
template <class Archive> void load(Archive&, npl_og_lpm_compression_code_t&);

template <class Archive> void save(Archive&, const npl_og_lpts_compression_code_t&);
template <class Archive> void load(Archive&, npl_og_lpts_compression_code_t&);

template <class Archive> void save(Archive&, const npl_og_pcl_id_t&);
template <class Archive> void load(Archive&, npl_og_pcl_id_t&);

template <class Archive> void save(Archive&, const npl_og_pd_compression_code_t&);
template <class Archive> void load(Archive&, npl_og_pd_compression_code_t&);

template <class Archive> void save(Archive&, const npl_oq_group_t&);
template <class Archive> void load(Archive&, npl_oq_group_t&);

template <class Archive> void save(Archive&, const npl_oqse_topology_4p_t&);
template <class Archive> void load(Archive&, npl_oqse_topology_4p_t&);

template <class Archive> void save(Archive&, const npl_overlay_nh_data_t&);
template <class Archive> void load(Archive&, npl_overlay_nh_data_t&);

template <class Archive> void save(Archive&, const npl_override_enable_ipv4_ipv6_uc_bits_t&);
template <class Archive> void load(Archive&, npl_override_enable_ipv4_ipv6_uc_bits_t&);

template <class Archive> void save(Archive&, const npl_path_lp_table_protection_entry_t&);
template <class Archive> void load(Archive&, npl_path_lp_table_protection_entry_t&);

template <class Archive> void save(Archive&, const npl_path_lp_wide_raw_t&);
template <class Archive> void load(Archive&, npl_path_lp_wide_raw_t&);

template <class Archive> void save(Archive&, const npl_path_protection_id_t&);
template <class Archive> void load(Archive&, npl_path_protection_id_t&);

template <class Archive> void save(Archive&, const npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t&);
template <class Archive> void load(Archive&, npl_pdoq_oq_ifc_mapping_result_t_anonymous_union_txpp_map_data_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_bank_pair_offset_t&);
template <class Archive> void load(Archive&, npl_pdvoq_bank_pair_offset_t&);

template <class Archive> void save(Archive&, const npl_pfc_em_lookup_t&);
template <class Archive> void load(Archive&, npl_pfc_em_lookup_t&);

template <class Archive> void save(Archive&, const npl_pfc_em_t&);
template <class Archive> void load(Archive&, npl_pfc_em_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_pif_ifg_base_t&);
template <class Archive> void load(Archive&, npl_pif_ifg_base_t&);

template <class Archive> void save(Archive&, const npl_port_npp_protection_table_protection_entry_t&);
template <class Archive> void load(Archive&, npl_port_npp_protection_table_protection_entry_t&);

template <class Archive> void save(Archive&, const npl_port_protection_id_t&);
template <class Archive> void load(Archive&, npl_port_protection_id_t&);

template <class Archive> void save(Archive&, const npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t&);
template <class Archive> void load(Archive&, npl_properties_t_anonymous_union_monitor_or_l3_dlp_ip_type_t&);

template <class Archive> void save(Archive&, const npl_protection_selector_t&);
template <class Archive> void load(Archive&, npl_protection_selector_t&);

template <class Archive> void save(Archive&, const npl_punt_controls_t&);
template <class Archive> void load(Archive&, npl_punt_controls_t&);

template <class Archive> void save(Archive&, const npl_punt_encap_data_lsb_t_anonymous_union_extra_t&);
template <class Archive> void load(Archive&, npl_punt_encap_data_lsb_t_anonymous_union_extra_t&);

template <class Archive> void save(Archive&, const npl_punt_l2_lp_t&);
template <class Archive> void load(Archive&, npl_punt_l2_lp_t&);

template <class Archive> void save(Archive&, const npl_punt_npu_host_macro_data_t&);
template <class Archive> void load(Archive&, npl_punt_npu_host_macro_data_t&);

template <class Archive> void save(Archive&, const npl_punt_nw_encap_ptr_t&);
template <class Archive> void load(Archive&, npl_punt_nw_encap_ptr_t&);

template <class Archive> void save(Archive&, const npl_punt_ssp_t&);
template <class Archive> void load(Archive&, npl_punt_ssp_t&);

template <class Archive> void save(Archive&, const npl_punt_sub_code_t_anonymous_union_sub_code_t&);
template <class Archive> void load(Archive&, npl_punt_sub_code_t_anonymous_union_sub_code_t&);

template <class Archive> void save(Archive&, const npl_pwe_to_l3_lookup_result_t&);
template <class Archive> void load(Archive&, npl_pwe_to_l3_lookup_result_t&);

template <class Archive> void save(Archive&, const npl_qos_and_acl_ids_t&);
template <class Archive> void load(Archive&, npl_qos_and_acl_ids_t&);

template <class Archive> void save(Archive&, const npl_qos_attributes_t&);
template <class Archive> void load(Archive&, npl_qos_attributes_t&);

template <class Archive> void save(Archive&, const npl_qos_encap_t&);
template <class Archive> void load(Archive&, npl_qos_encap_t&);

template <class Archive> void save(Archive&, const npl_qos_info_t&);
template <class Archive> void load(Archive&, npl_qos_info_t&);

template <class Archive> void save(Archive&, const npl_qos_tag_t&);
template <class Archive> void load(Archive&, npl_qos_tag_t&);

template <class Archive> void save(Archive&, const npl_quan_13b&);
template <class Archive> void load(Archive&, npl_quan_13b&);

template <class Archive> void save(Archive&, const npl_quan_15b&);
template <class Archive> void load(Archive&, npl_quan_15b&);

template <class Archive> void save(Archive&, const npl_quan_19b&);
template <class Archive> void load(Archive&, npl_quan_19b&);

template <class Archive> void save(Archive&, const npl_quan_1b&);
template <class Archive> void load(Archive&, npl_quan_1b&);

template <class Archive> void save(Archive&, const npl_quan_5b&);
template <class Archive> void load(Archive&, npl_quan_5b&);

template <class Archive> void save(Archive&, const npl_redirect_code_t&);
template <class Archive> void load(Archive&, npl_redirect_code_t&);

template <class Archive> void save(Archive&, const npl_relay_id_t&);
template <class Archive> void load(Archive&, npl_relay_id_t&);

template <class Archive> void save(Archive&, const npl_rtf_conf_set_and_stages_t&);
template <class Archive> void load(Archive&, npl_rtf_conf_set_and_stages_t&);

template <class Archive> void save(Archive&, const npl_rtf_iter_prop_over_fwd0_t&);
template <class Archive> void load(Archive&, npl_rtf_iter_prop_over_fwd0_t&);

template <class Archive> void save(Archive&, const npl_rtf_iter_prop_over_fwd1_t&);
template <class Archive> void load(Archive&, npl_rtf_iter_prop_over_fwd1_t&);

template <class Archive> void save(Archive&, const npl_rtf_result_profile_0_t_anonymous_union_force_t&);
template <class Archive> void load(Archive&, npl_rtf_result_profile_0_t_anonymous_union_force_t&);

template <class Archive> void save(Archive&, const npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t&);
template <class Archive> void load(Archive&, npl_rtf_result_profile_0_t_anonymous_union_mirror_cmd_or_offset_t&);

template <class Archive> void save(Archive&, const npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t&);
template <class Archive> void load(Archive&, npl_rtf_result_profile_1_t_anonymous_union_meter_or_counter_t&);

template <class Archive> void save(Archive&, const npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t&);
template <class Archive> void load(Archive&, npl_sec_acl_attributes_t_anonymous_union_slp_dlp_t&);

template <class Archive> void save(Archive&, const npl_sec_acl_ids_t&);
template <class Archive> void load(Archive&, npl_sec_acl_ids_t&);

template <class Archive> void save(Archive&, const npl_service_flags_t&);
template <class Archive> void load(Archive&, npl_service_flags_t&);

template <class Archive> void save(Archive&, const npl_sip_ip_tunnel_termination_attr_t&);
template <class Archive> void load(Archive&, npl_sip_ip_tunnel_termination_attr_t&);

template <class Archive> void save(Archive&, const npl_slp_based_fwd_and_per_vrf_mpls_fwd_t&);
template <class Archive> void load(Archive&, npl_slp_based_fwd_and_per_vrf_mpls_fwd_t&);

template <class Archive> void save(Archive&, const npl_snoop_code_t&);
template <class Archive> void load(Archive&, npl_snoop_code_t&);

template <class Archive> void save(Archive&, const npl_soft_lb_wa_enable_t&);
template <class Archive> void load(Archive&, npl_soft_lb_wa_enable_t&);

template <class Archive> void save(Archive&, const npl_split_voq_t&);
template <class Archive> void load(Archive&, npl_split_voq_t&);

template <class Archive> void save(Archive&, const npl_stop_on_step_and_next_stage_compressed_fields_t&);
template <class Archive> void load(Archive&, npl_stop_on_step_and_next_stage_compressed_fields_t&);

template <class Archive> void save(Archive&, const npl_tm_header_base_t&);
template <class Archive> void load(Archive&, npl_tm_header_base_t&);

template <class Archive> void save(Archive&, const npl_tpid_sa_lsb_t&);
template <class Archive> void load(Archive&, npl_tpid_sa_lsb_t&);

template <class Archive> void save(Archive&, const npl_ts_command_t&);
template <class Archive> void load(Archive&, npl_ts_command_t&);

template <class Archive> void save(Archive&, const npl_ttl_and_protocol_t&);
template <class Archive> void load(Archive&, npl_ttl_and_protocol_t&);

template <class Archive> void save(Archive&, const npl_tunnel_control_t&);
template <class Archive> void load(Archive&, npl_tunnel_control_t&);

template <class Archive> void save(Archive&, const npl_tunnel_type_q_counter_t&);
template <class Archive> void load(Archive&, npl_tunnel_type_q_counter_t&);

template <class Archive> void save(Archive&, const npl_udp_encap_data_t&);
template <class Archive> void load(Archive&, npl_udp_encap_data_t&);

template <class Archive> void save(Archive&, const npl_use_metedata_table_per_packet_format_t&);
template <class Archive> void load(Archive&, npl_use_metedata_table_per_packet_format_t&);

template <class Archive> void save(Archive&, const npl_vid2_or_flood_rcy_sm_vlans_t&);
template <class Archive> void load(Archive&, npl_vid2_or_flood_rcy_sm_vlans_t&);

template <class Archive> void save(Archive&, const npl_vlan_and_sa_lsb_encap_t&);
template <class Archive> void load(Archive&, npl_vlan_and_sa_lsb_encap_t&);

template <class Archive> void save(Archive&, const npl_vlan_edit_secondary_type_with_padding_t&);
template <class Archive> void load(Archive&, npl_vlan_edit_secondary_type_with_padding_t&);

template <class Archive> void save(Archive&, const npl_vlan_header_flags_t&);
template <class Archive> void load(Archive&, npl_vlan_header_flags_t&);

template <class Archive> void save(Archive&, const npl_vlan_profile_and_lp_type_t&);
template <class Archive> void load(Archive&, npl_vlan_profile_and_lp_type_t&);

template <class Archive> void save(Archive&, const npl_vlan_tag_tci_t&);
template <class Archive> void load(Archive&, npl_vlan_tag_tci_t&);

template <class Archive> void save(Archive&, const npl_voq_profile_len&);
template <class Archive> void load(Archive&, npl_voq_profile_len&);

template <class Archive> void save(Archive&, const npl_vxlan_encap_data_t&);
template <class Archive> void load(Archive&, npl_vxlan_encap_data_t&);

template<>
class serializer_class<npl_vxlan_relay_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vxlan_relay_encap_data_t& m) {
        uint64_t m_vni = m.vni;
            archive(::cereal::make_nvp("vni", m_vni));
            archive(::cereal::make_nvp("vni_counter", m.vni_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vxlan_relay_encap_data_t& m) {
        uint64_t m_vni;
            archive(::cereal::make_nvp("vni", m_vni));
            archive(::cereal::make_nvp("vni_counter", m.vni_counter));
        m.vni = m_vni;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vxlan_relay_encap_data_t& m)
{
    serializer_class<npl_vxlan_relay_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vxlan_relay_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_vxlan_relay_encap_data_t& m)
{
    serializer_class<npl_vxlan_relay_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vxlan_relay_encap_data_t&);



template<>
class serializer_class<npl_wfq_priority_weight_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_wfq_priority_weight_t& m) {
        uint64_t m_weight = m.weight;
            archive(::cereal::make_nvp("weight", m_weight));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_wfq_priority_weight_t& m) {
        uint64_t m_weight;
            archive(::cereal::make_nvp("weight", m_weight));
        m.weight = m_weight;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_wfq_priority_weight_t& m)
{
    serializer_class<npl_wfq_priority_weight_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_wfq_priority_weight_t&);

template <class Archive>
void
load(Archive& archive, npl_wfq_priority_weight_t& m)
{
    serializer_class<npl_wfq_priority_weight_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_wfq_priority_weight_t&);



template<>
class serializer_class<npl_wfq_weight_4p_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_wfq_weight_4p_entry_t& m) {
            archive(::cereal::make_nvp("priority", m.priority));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_wfq_weight_4p_entry_t& m) {
            archive(::cereal::make_nvp("priority", m.priority));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_wfq_weight_4p_entry_t& m)
{
    serializer_class<npl_wfq_weight_4p_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_wfq_weight_4p_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_wfq_weight_4p_entry_t& m)
{
    serializer_class<npl_wfq_weight_4p_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_wfq_weight_4p_entry_t&);



template<>
class serializer_class<npl_wfq_weight_8p_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_wfq_weight_8p_t& m) {
            archive(::cereal::make_nvp("priority", m.priority));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_wfq_weight_8p_t& m) {
            archive(::cereal::make_nvp("priority", m.priority));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_wfq_weight_8p_t& m)
{
    serializer_class<npl_wfq_weight_8p_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_wfq_weight_8p_t&);

template <class Archive>
void
load(Archive& archive, npl_wfq_weight_8p_t& m)
{
    serializer_class<npl_wfq_weight_8p_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_wfq_weight_8p_t&);



template<>
class serializer_class<npl_app_relay_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_app_relay_id_t& m) {
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_app_relay_id_t& m) {
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_app_relay_id_t& m)
{
    serializer_class<npl_app_relay_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_app_relay_id_t&);

template <class Archive>
void
load(Archive& archive, npl_app_relay_id_t& m)
{
    serializer_class<npl_app_relay_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_app_relay_id_t&);



template<>
class serializer_class<npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t& m) {
            archive(::cereal::make_nvp("rtf_conf_set_and_stages", m.rtf_conf_set_and_stages));
            archive(::cereal::make_nvp("ip_ver_and_post_fwd_stage", m.ip_ver_and_post_fwd_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t& m) {
            archive(::cereal::make_nvp("rtf_conf_set_and_stages", m.rtf_conf_set_and_stages));
            archive(::cereal::make_nvp("ip_ver_and_post_fwd_stage", m.ip_ver_and_post_fwd_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t& m)
{
    serializer_class<npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t&);

template <class Archive>
void
load(Archive& archive, npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t& m)
{
    serializer_class<npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t&);



template<>
class serializer_class<npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t& m) {
            archive(::cereal::make_nvp("ipv6", m.ipv6));
            archive(::cereal::make_nvp("ipv4", m.ipv4));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t& m) {
            archive(::cereal::make_nvp("ipv6", m.ipv6));
            archive(::cereal::make_nvp("ipv4", m.ipv4));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t& m)
{
    serializer_class<npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t& m)
{
    serializer_class<npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t&);



template<>
class serializer_class<npl_bfd_aux_transmit_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_aux_transmit_payload_t& m) {
        uint64_t m_interval_selector = m.interval_selector;
        uint64_t m_echo_mode_enabled = m.echo_mode_enabled;
            archive(::cereal::make_nvp("prot_trans", m.prot_trans));
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
            archive(::cereal::make_nvp("echo_mode_enabled", m_echo_mode_enabled));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_aux_transmit_payload_t& m) {
        uint64_t m_interval_selector;
        uint64_t m_echo_mode_enabled;
            archive(::cereal::make_nvp("prot_trans", m.prot_trans));
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
            archive(::cereal::make_nvp("echo_mode_enabled", m_echo_mode_enabled));
        m.interval_selector = m_interval_selector;
        m.echo_mode_enabled = m_echo_mode_enabled;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_aux_transmit_payload_t& m)
{
    serializer_class<npl_bfd_aux_transmit_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_aux_transmit_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_aux_transmit_payload_t& m)
{
    serializer_class<npl_bfd_aux_transmit_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_aux_transmit_payload_t&);



template<>
class serializer_class<npl_bfd_flags_state_t_anonymous_union_bfd_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_flags_state_t_anonymous_union_bfd_flags_t& m) {
        uint64_t m_flags = m.flags;
            archive(::cereal::make_nvp("indiv_flags", m.indiv_flags));
            archive(::cereal::make_nvp("flags", m_flags));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_flags_state_t_anonymous_union_bfd_flags_t& m) {
        uint64_t m_flags;
            archive(::cereal::make_nvp("indiv_flags", m.indiv_flags));
            archive(::cereal::make_nvp("flags", m_flags));
        m.flags = m_flags;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_flags_state_t_anonymous_union_bfd_flags_t& m)
{
    serializer_class<npl_bfd_flags_state_t_anonymous_union_bfd_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_flags_state_t_anonymous_union_bfd_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_flags_state_t_anonymous_union_bfd_flags_t& m)
{
    serializer_class<npl_bfd_flags_state_t_anonymous_union_bfd_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_flags_state_t_anonymous_union_bfd_flags_t&);



template<>
class serializer_class<npl_bfd_mp_table_extra_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_extra_payload_t& m) {
            archive(::cereal::make_nvp("mpls_label", m.mpls_label));
            archive(::cereal::make_nvp("extra_tx_b", m.extra_tx_b));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_extra_payload_t& m) {
            archive(::cereal::make_nvp("mpls_label", m.mpls_label));
            archive(::cereal::make_nvp("extra_tx_b", m.extra_tx_b));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_extra_payload_t& m)
{
    serializer_class<npl_bfd_mp_table_extra_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_extra_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_extra_payload_t& m)
{
    serializer_class<npl_bfd_mp_table_extra_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_extra_payload_t&);



template<>
class serializer_class<npl_bfd_mp_table_shared_msb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_shared_msb_t& m) {
            archive(::cereal::make_nvp("trans_data", m.trans_data));
            archive(::cereal::make_nvp("transport_label", m.transport_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_shared_msb_t& m) {
            archive(::cereal::make_nvp("trans_data", m.trans_data));
            archive(::cereal::make_nvp("transport_label", m.transport_label));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_shared_msb_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_msb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_shared_msb_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_shared_msb_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_msb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_shared_msb_t&);



template<>
class serializer_class<npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t& m) {
            archive(::cereal::make_nvp("offset", m.offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t& m) {
            archive(::cereal::make_nvp("offset", m.offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t& m)
{
    serializer_class<npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t& m)
{
    serializer_class<npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t&);



template<>
class serializer_class<npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t& m) {
            archive(::cereal::make_nvp("offset", m.offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t& m) {
            archive(::cereal::make_nvp("offset", m.offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t& m)
{
    serializer_class<npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t& m)
{
    serializer_class<npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t&);



template<>
class serializer_class<npl_demux_pif_ifg_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_demux_pif_ifg_t& m) {
        uint64_t m_pad = m.pad;
            archive(::cereal::make_nvp("pad", m_pad));
            archive(::cereal::make_nvp("pif_ifg", m.pif_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_demux_pif_ifg_t& m) {
        uint64_t m_pad;
            archive(::cereal::make_nvp("pad", m_pad));
            archive(::cereal::make_nvp("pif_ifg", m.pif_ifg));
        m.pad = m_pad;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_demux_pif_ifg_t& m)
{
    serializer_class<npl_demux_pif_ifg_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_demux_pif_ifg_t&);

template <class Archive>
void
load(Archive& archive, npl_demux_pif_ifg_t& m)
{
    serializer_class<npl_demux_pif_ifg_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_demux_pif_ifg_t&);



template<>
class serializer_class<npl_dlp_profile_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dlp_profile_t& m) {
            archive(::cereal::make_nvp("l2", m.l2));
            archive(::cereal::make_nvp("l3_sec", m.l3_sec));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dlp_profile_t& m) {
            archive(::cereal::make_nvp("l2", m.l2));
            archive(::cereal::make_nvp("l3_sec", m.l3_sec));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dlp_profile_t& m)
{
    serializer_class<npl_dlp_profile_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dlp_profile_t&);

template <class Archive>
void
load(Archive& archive, npl_dlp_profile_t& m)
{
    serializer_class<npl_dlp_profile_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dlp_profile_t&);



template<>
class serializer_class<npl_drop_color_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_drop_color_t& m) {
            archive(::cereal::make_nvp("drop_color", m.drop_color));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_drop_color_t& m) {
            archive(::cereal::make_nvp("drop_color", m.drop_color));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_drop_color_t& m)
{
    serializer_class<npl_drop_color_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_drop_color_t&);

template <class Archive>
void
load(Archive& archive, npl_drop_color_t& m)
{
    serializer_class<npl_drop_color_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_drop_color_t&);



template<>
class serializer_class<npl_dsp_attr_common_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_attr_common_t& m) {
        uint64_t m_dsp_is_dma = m.dsp_is_dma;
        uint64_t m_mask_egress_vlan_edit = m.mask_egress_vlan_edit;
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("dsp_is_dma", m_dsp_is_dma));
            archive(::cereal::make_nvp("dsp_map_info", m.dsp_map_info));
            archive(::cereal::make_nvp("mask_egress_vlan_edit", m_mask_egress_vlan_edit));
            archive(::cereal::make_nvp("dsp", m_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_attr_common_t& m) {
        uint64_t m_dsp_is_dma;
        uint64_t m_mask_egress_vlan_edit;
        uint64_t m_dsp;
            archive(::cereal::make_nvp("dsp_is_dma", m_dsp_is_dma));
            archive(::cereal::make_nvp("dsp_map_info", m.dsp_map_info));
            archive(::cereal::make_nvp("mask_egress_vlan_edit", m_mask_egress_vlan_edit));
            archive(::cereal::make_nvp("dsp", m_dsp));
        m.dsp_is_dma = m_dsp_is_dma;
        m.mask_egress_vlan_edit = m_mask_egress_vlan_edit;
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_attr_common_t& m)
{
    serializer_class<npl_dsp_attr_common_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_attr_common_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_attr_common_t& m)
{
    serializer_class<npl_dsp_attr_common_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_attr_common_t&);



template<>
class serializer_class<npl_dsp_l2_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l2_attributes_t& m) {
        uint64_t m_mc_pruning_low = m.mc_pruning_low;
        uint64_t m_mc_pruning_high = m.mc_pruning_high;
            archive(::cereal::make_nvp("mc_pruning_low", m_mc_pruning_low));
            archive(::cereal::make_nvp("mc_pruning_high", m_mc_pruning_high));
            archive(::cereal::make_nvp("dsp_attr_common", m.dsp_attr_common));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l2_attributes_t& m) {
        uint64_t m_mc_pruning_low;
        uint64_t m_mc_pruning_high;
            archive(::cereal::make_nvp("mc_pruning_low", m_mc_pruning_low));
            archive(::cereal::make_nvp("mc_pruning_high", m_mc_pruning_high));
            archive(::cereal::make_nvp("dsp_attr_common", m.dsp_attr_common));
        m.mc_pruning_low = m_mc_pruning_low;
        m.mc_pruning_high = m_mc_pruning_high;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l2_attributes_t& m)
{
    serializer_class<npl_dsp_l2_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l2_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l2_attributes_t& m)
{
    serializer_class<npl_dsp_l2_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l2_attributes_t&);



template<>
class serializer_class<npl_dsp_l3_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l3_attributes_t& m) {
        uint64_t m_mtu = m.mtu;
        uint64_t m_no_decrement_ttl = m.no_decrement_ttl;
            archive(::cereal::make_nvp("mtu", m_mtu));
            archive(::cereal::make_nvp("no_decrement_ttl", m_no_decrement_ttl));
            archive(::cereal::make_nvp("mpls_ip_ttl_propagation", m.mpls_ip_ttl_propagation));
            archive(::cereal::make_nvp("dsp_attr_common", m.dsp_attr_common));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l3_attributes_t& m) {
        uint64_t m_mtu;
        uint64_t m_no_decrement_ttl;
            archive(::cereal::make_nvp("mtu", m_mtu));
            archive(::cereal::make_nvp("no_decrement_ttl", m_no_decrement_ttl));
            archive(::cereal::make_nvp("mpls_ip_ttl_propagation", m.mpls_ip_ttl_propagation));
            archive(::cereal::make_nvp("dsp_attr_common", m.dsp_attr_common));
        m.mtu = m_mtu;
        m.no_decrement_ttl = m_no_decrement_ttl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l3_attributes_t& m)
{
    serializer_class<npl_dsp_l3_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l3_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l3_attributes_t& m)
{
    serializer_class<npl_dsp_l3_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l3_attributes_t&);



template<>
class serializer_class<npl_egress_sec_acl_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_sec_acl_result_t& m) {
        uint64_t m_mirror_valid = m.mirror_valid;
            archive(::cereal::make_nvp("drop_punt_or_permit", m.drop_punt_or_permit));
            archive(::cereal::make_nvp("mirror_valid", m_mirror_valid));
            archive(::cereal::make_nvp("drop_or_permit", m.drop_or_permit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_sec_acl_result_t& m) {
        uint64_t m_mirror_valid;
            archive(::cereal::make_nvp("drop_punt_or_permit", m.drop_punt_or_permit));
            archive(::cereal::make_nvp("mirror_valid", m_mirror_valid));
            archive(::cereal::make_nvp("drop_or_permit", m.drop_or_permit));
        m.mirror_valid = m_mirror_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_sec_acl_result_t& m)
{
    serializer_class<npl_egress_sec_acl_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_sec_acl_result_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_sec_acl_result_t& m)
{
    serializer_class<npl_egress_sec_acl_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_sec_acl_result_t&);



template<>
class serializer_class<npl_em_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_payload_t& m) {
            archive(::cereal::make_nvp("ethernet_oam", m.ethernet_oam));
            archive(::cereal::make_nvp("bfd", m.bfd));
            archive(::cereal::make_nvp("mpls_tp", m.mpls_tp));
            archive(::cereal::make_nvp("pfc", m.pfc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_payload_t& m) {
            archive(::cereal::make_nvp("ethernet_oam", m.ethernet_oam));
            archive(::cereal::make_nvp("bfd", m.bfd));
            archive(::cereal::make_nvp("mpls_tp", m.mpls_tp));
            archive(::cereal::make_nvp("pfc", m.pfc));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_payload_t& m)
{
    serializer_class<npl_em_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_em_payload_t& m)
{
    serializer_class<npl_em_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_payload_t&);



template<>
class serializer_class<npl_ene_inject_down_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_inject_down_payload_t& m) {
            archive(::cereal::make_nvp("ene_inject_down_encap_type", m.ene_inject_down_encap_type));
            archive(::cereal::make_nvp("ene_inject_phb", m.ene_inject_phb));
            archive(::cereal::make_nvp("ene_inject_destination", m.ene_inject_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_inject_down_payload_t& m) {
            archive(::cereal::make_nvp("ene_inject_down_encap_type", m.ene_inject_down_encap_type));
            archive(::cereal::make_nvp("ene_inject_phb", m.ene_inject_phb));
            archive(::cereal::make_nvp("ene_inject_destination", m.ene_inject_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_inject_down_payload_t& m)
{
    serializer_class<npl_ene_inject_down_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_inject_down_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_inject_down_payload_t& m)
{
    serializer_class<npl_ene_inject_down_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_inject_down_payload_t&);



template<>
class serializer_class<npl_ene_punt_dsp_and_ssp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_dsp_and_ssp_t& m) {
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("ssp", m.ssp));
            archive(::cereal::make_nvp("dsp", m_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_dsp_and_ssp_t& m) {
        uint64_t m_dsp;
            archive(::cereal::make_nvp("ssp", m.ssp));
            archive(::cereal::make_nvp("dsp", m_dsp));
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_dsp_and_ssp_t& m)
{
    serializer_class<npl_ene_punt_dsp_and_ssp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_dsp_and_ssp_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_dsp_and_ssp_t& m)
{
    serializer_class<npl_ene_punt_dsp_and_ssp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_dsp_and_ssp_t&);



template<>
class serializer_class<npl_eth_oam_aux_shared_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_aux_shared_payload_t& m) {
            archive(::cereal::make_nvp("meg_id", m.meg_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_aux_shared_payload_t& m) {
            archive(::cereal::make_nvp("meg_id", m.meg_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_aux_shared_payload_t& m)
{
    serializer_class<npl_eth_oam_aux_shared_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_aux_shared_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_aux_shared_payload_t& m)
{
    serializer_class<npl_eth_oam_aux_shared_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_aux_shared_payload_t&);



template<>
class serializer_class<npl_eth_rtf_iteration_properties_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rtf_iteration_properties_t& m) {
            archive(::cereal::make_nvp("f0_rtf_prop", m.f0_rtf_prop));
            archive(::cereal::make_nvp("stop_on_step_and_next_stage_compressed_fields", m.stop_on_step_and_next_stage_compressed_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rtf_iteration_properties_t& m) {
            archive(::cereal::make_nvp("f0_rtf_prop", m.f0_rtf_prop));
            archive(::cereal::make_nvp("stop_on_step_and_next_stage_compressed_fields", m.stop_on_step_and_next_stage_compressed_fields));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rtf_iteration_properties_t& m)
{
    serializer_class<npl_eth_rtf_iteration_properties_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rtf_iteration_properties_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rtf_iteration_properties_t& m)
{
    serializer_class<npl_eth_rtf_iteration_properties_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rtf_iteration_properties_t&);



template<>
class serializer_class<npl_ethernet_mac_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ethernet_mac_t& m) {
            archive(::cereal::make_nvp("da", m.da));
            archive(::cereal::make_nvp("sa", m.sa));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ethernet_mac_t& m) {
            archive(::cereal::make_nvp("da", m.da));
            archive(::cereal::make_nvp("sa", m.sa));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ethernet_mac_t& m)
{
    serializer_class<npl_ethernet_mac_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ethernet_mac_t&);

template <class Archive>
void
load(Archive& archive, npl_ethernet_mac_t& m)
{
    serializer_class<npl_ethernet_mac_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ethernet_mac_t&);



template<>
class serializer_class<npl_force_pipe_ttl_ingress_ptp_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_force_pipe_ttl_ingress_ptp_info_t& m) {
        uint64_t m_force_pipe_ttl = m.force_pipe_ttl;
            archive(::cereal::make_nvp("ingress_ptp_info", m.ingress_ptp_info));
            archive(::cereal::make_nvp("force_pipe_ttl", m_force_pipe_ttl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_force_pipe_ttl_ingress_ptp_info_t& m) {
        uint64_t m_force_pipe_ttl;
            archive(::cereal::make_nvp("ingress_ptp_info", m.ingress_ptp_info));
            archive(::cereal::make_nvp("force_pipe_ttl", m_force_pipe_ttl));
        m.force_pipe_ttl = m_force_pipe_ttl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_force_pipe_ttl_ingress_ptp_info_t& m)
{
    serializer_class<npl_force_pipe_ttl_ingress_ptp_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_force_pipe_ttl_ingress_ptp_info_t&);

template <class Archive>
void
load(Archive& archive, npl_force_pipe_ttl_ingress_ptp_info_t& m)
{
    serializer_class<npl_force_pipe_ttl_ingress_ptp_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_force_pipe_ttl_ingress_ptp_info_t&);



template<>
class serializer_class<npl_gre_tunnel_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_gre_tunnel_attributes_t& m) {
        uint64_t m_demux_count = m.demux_count;
        uint64_t m_sip_index = m.sip_index;
        uint64_t m_dip = m.dip;
        uint64_t m_gre_flags = m.gre_flags;
        uint64_t m_ttl = m.ttl;
            archive(::cereal::make_nvp("demux_count", m_demux_count));
            archive(::cereal::make_nvp("dip_entropy", m.dip_entropy));
            archive(::cereal::make_nvp("tunnel_qos_encap", m.tunnel_qos_encap));
            archive(::cereal::make_nvp("tunnel_control", m.tunnel_control));
            archive(::cereal::make_nvp("qos_info", m.qos_info));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("tunnel_type_q_counter", m.tunnel_type_q_counter));
            archive(::cereal::make_nvp("sip_index", m_sip_index));
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("gre_flags", m_gre_flags));
            archive(::cereal::make_nvp("ttl", m_ttl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_gre_tunnel_attributes_t& m) {
        uint64_t m_demux_count;
        uint64_t m_sip_index;
        uint64_t m_dip;
        uint64_t m_gre_flags;
        uint64_t m_ttl;
            archive(::cereal::make_nvp("demux_count", m_demux_count));
            archive(::cereal::make_nvp("dip_entropy", m.dip_entropy));
            archive(::cereal::make_nvp("tunnel_qos_encap", m.tunnel_qos_encap));
            archive(::cereal::make_nvp("tunnel_control", m.tunnel_control));
            archive(::cereal::make_nvp("qos_info", m.qos_info));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("tunnel_type_q_counter", m.tunnel_type_q_counter));
            archive(::cereal::make_nvp("sip_index", m_sip_index));
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("gre_flags", m_gre_flags));
            archive(::cereal::make_nvp("ttl", m_ttl));
        m.demux_count = m_demux_count;
        m.sip_index = m_sip_index;
        m.dip = m_dip;
        m.gre_flags = m_gre_flags;
        m.ttl = m_ttl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_gre_tunnel_attributes_t& m)
{
    serializer_class<npl_gre_tunnel_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_gre_tunnel_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_gre_tunnel_attributes_t& m)
{
    serializer_class<npl_gre_tunnel_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_gre_tunnel_attributes_t&);



template<>
class serializer_class<npl_header_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_header_flags_t& m) {
        uint64_t m_all_header_flags = m.all_header_flags;
            archive(::cereal::make_nvp("all_header_flags", m_all_header_flags));
            archive(::cereal::make_nvp("ipv4_header_flags", m.ipv4_header_flags));
            archive(::cereal::make_nvp("ipv6_header_flags", m.ipv6_header_flags));
            archive(::cereal::make_nvp("vlan_header_flags", m.vlan_header_flags));
            archive(::cereal::make_nvp("ethernet_header_flags", m.ethernet_header_flags));
            archive(::cereal::make_nvp("mpls_header_flags", m.mpls_header_flags));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_header_flags_t& m) {
        uint64_t m_all_header_flags;
            archive(::cereal::make_nvp("all_header_flags", m_all_header_flags));
            archive(::cereal::make_nvp("ipv4_header_flags", m.ipv4_header_flags));
            archive(::cereal::make_nvp("ipv6_header_flags", m.ipv6_header_flags));
            archive(::cereal::make_nvp("vlan_header_flags", m.vlan_header_flags));
            archive(::cereal::make_nvp("ethernet_header_flags", m.ethernet_header_flags));
            archive(::cereal::make_nvp("mpls_header_flags", m.mpls_header_flags));
        m.all_header_flags = m_all_header_flags;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_header_flags_t& m)
{
    serializer_class<npl_header_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_header_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_header_flags_t& m)
{
    serializer_class<npl_header_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_header_flags_t&);



template<>
class serializer_class<npl_header_format_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_header_format_t& m) {
            archive(::cereal::make_nvp("flags", m.flags));
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_header_format_t& m) {
            archive(::cereal::make_nvp("flags", m.flags));
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_header_format_t& m)
{
    serializer_class<npl_header_format_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_header_format_t&);

template <class Archive>
void
load(Archive& archive, npl_header_format_t& m)
{
    serializer_class<npl_header_format_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_header_format_t&);



template<>
class serializer_class<npl_hmc_cgm_profile_global_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_profile_global_results_t& m) {
        uint64_t m_wred_ema_weight = m.wred_ema_weight;
        uint64_t m_wred_fcn_enable = m.wred_fcn_enable;
        uint64_t m_shared_resource_threshold_mode = m.shared_resource_threshold_mode;
        uint64_t m_shared_pool_id = m.shared_pool_id;
            archive(::cereal::make_nvp("wred_ema_weight", m_wred_ema_weight));
            archive(::cereal::make_nvp("wred_fcn_probability_region", m.wred_fcn_probability_region));
            archive(::cereal::make_nvp("wred_region_borders", m.wred_region_borders));
            archive(::cereal::make_nvp("wred_fcn_enable", m_wred_fcn_enable));
            archive(::cereal::make_nvp("alpha_dpo1", m.alpha_dpo1));
            archive(::cereal::make_nvp("shared_resource_threshold_dp1", m.shared_resource_threshold_dp1));
            archive(::cereal::make_nvp("alpha_dpo0", m.alpha_dpo0));
            archive(::cereal::make_nvp("shared_resource_threshold_dp0", m.shared_resource_threshold_dp0));
            archive(::cereal::make_nvp("shared_resource_threshold_mode", m_shared_resource_threshold_mode));
            archive(::cereal::make_nvp("shared_pool_id", m_shared_pool_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_profile_global_results_t& m) {
        uint64_t m_wred_ema_weight;
        uint64_t m_wred_fcn_enable;
        uint64_t m_shared_resource_threshold_mode;
        uint64_t m_shared_pool_id;
            archive(::cereal::make_nvp("wred_ema_weight", m_wred_ema_weight));
            archive(::cereal::make_nvp("wred_fcn_probability_region", m.wred_fcn_probability_region));
            archive(::cereal::make_nvp("wred_region_borders", m.wred_region_borders));
            archive(::cereal::make_nvp("wred_fcn_enable", m_wred_fcn_enable));
            archive(::cereal::make_nvp("alpha_dpo1", m.alpha_dpo1));
            archive(::cereal::make_nvp("shared_resource_threshold_dp1", m.shared_resource_threshold_dp1));
            archive(::cereal::make_nvp("alpha_dpo0", m.alpha_dpo0));
            archive(::cereal::make_nvp("shared_resource_threshold_dp0", m.shared_resource_threshold_dp0));
            archive(::cereal::make_nvp("shared_resource_threshold_mode", m_shared_resource_threshold_mode));
            archive(::cereal::make_nvp("shared_pool_id", m_shared_pool_id));
        m.wred_ema_weight = m_wred_ema_weight;
        m.wred_fcn_enable = m_wred_fcn_enable;
        m.shared_resource_threshold_mode = m_shared_resource_threshold_mode;
        m.shared_pool_id = m_shared_pool_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_profile_global_results_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_profile_global_results_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_profile_global_results_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_profile_global_results_t&);



template<>
class serializer_class<npl_ibm_cmd_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_cmd_table_result_t& m) {
        uint64_t m_sampling_probability = m.sampling_probability;
        uint64_t m_is_mc = m.is_mc;
        uint64_t m_ignore_in_rxrq_sel = m.ignore_in_rxrq_sel;
        uint64_t m_mirror_to_dest = m.mirror_to_dest;
        uint64_t m_tc_map_profile = m.tc_map_profile;
        uint64_t m_destination_device = m.destination_device;
            archive(::cereal::make_nvp("sampling_probability", m_sampling_probability));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("ignore_in_rxrq_sel", m_ignore_in_rxrq_sel));
            archive(::cereal::make_nvp("mirror_to_dest", m_mirror_to_dest));
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("destination_device", m_destination_device));
            archive(::cereal::make_nvp("voq_or_bitmap", m.voq_or_bitmap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_cmd_table_result_t& m) {
        uint64_t m_sampling_probability;
        uint64_t m_is_mc;
        uint64_t m_ignore_in_rxrq_sel;
        uint64_t m_mirror_to_dest;
        uint64_t m_tc_map_profile;
        uint64_t m_destination_device;
            archive(::cereal::make_nvp("sampling_probability", m_sampling_probability));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("ignore_in_rxrq_sel", m_ignore_in_rxrq_sel));
            archive(::cereal::make_nvp("mirror_to_dest", m_mirror_to_dest));
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("destination_device", m_destination_device));
            archive(::cereal::make_nvp("voq_or_bitmap", m.voq_or_bitmap));
        m.sampling_probability = m_sampling_probability;
        m.is_mc = m_is_mc;
        m.ignore_in_rxrq_sel = m_ignore_in_rxrq_sel;
        m.mirror_to_dest = m_mirror_to_dest;
        m.tc_map_profile = m_tc_map_profile;
        m.destination_device = m_destination_device;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_cmd_table_result_t& m)
{
    serializer_class<npl_ibm_cmd_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_cmd_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_cmd_table_result_t& m)
{
    serializer_class<npl_ibm_cmd_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_cmd_table_result_t&);



template<>
class serializer_class<npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t& m) {
        uint64_t m_is_slp_dm = m.is_slp_dm;
            archive(::cereal::make_nvp("is_slp_dm", m_is_slp_dm));
            archive(::cereal::make_nvp("ingress_ptp_info", m.ingress_ptp_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t& m) {
        uint64_t m_is_slp_dm;
            archive(::cereal::make_nvp("is_slp_dm", m_is_slp_dm));
            archive(::cereal::make_nvp("ingress_ptp_info", m.ingress_ptp_info));
        m.is_slp_dm = m_is_slp_dm;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t& m)
{
    serializer_class<npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t& m)
{
    serializer_class<npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t&);



template<>
class serializer_class<npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t& m) {
        uint64_t m_mpls_label_placeholder = m.mpls_label_placeholder;
            archive(::cereal::make_nvp("initial_lp_id", m.initial_lp_id));
            archive(::cereal::make_nvp("mpls_label_placeholder", m_mpls_label_placeholder));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t& m) {
        uint64_t m_mpls_label_placeholder;
            archive(::cereal::make_nvp("initial_lp_id", m.initial_lp_id));
            archive(::cereal::make_nvp("mpls_label_placeholder", m_mpls_label_placeholder));
        m.mpls_label_placeholder = m_mpls_label_placeholder;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t& m)
{
    serializer_class<npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t&);

template <class Archive>
void
load(Archive& archive, npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t& m)
{
    serializer_class<npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t&);



template<>
class serializer_class<npl_initial_recycle_pd_nw_rx_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_initial_recycle_pd_nw_rx_data_t& m) {
        uint64_t m_initial_is_rcy_if = m.initial_is_rcy_if;
            archive(::cereal::make_nvp("init_data", m.init_data));
            archive(::cereal::make_nvp("initial_mapping_type", m.initial_mapping_type));
            archive(::cereal::make_nvp("initial_is_rcy_if", m_initial_is_rcy_if));
            archive(::cereal::make_nvp("initial_mac_lp_type", m.initial_mac_lp_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_initial_recycle_pd_nw_rx_data_t& m) {
        uint64_t m_initial_is_rcy_if;
            archive(::cereal::make_nvp("init_data", m.init_data));
            archive(::cereal::make_nvp("initial_mapping_type", m.initial_mapping_type));
            archive(::cereal::make_nvp("initial_is_rcy_if", m_initial_is_rcy_if));
            archive(::cereal::make_nvp("initial_mac_lp_type", m.initial_mac_lp_type));
        m.initial_is_rcy_if = m_initial_is_rcy_if;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_initial_recycle_pd_nw_rx_data_t& m)
{
    serializer_class<npl_initial_recycle_pd_nw_rx_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_initial_recycle_pd_nw_rx_data_t&);

template <class Archive>
void
load(Archive& archive, npl_initial_recycle_pd_nw_rx_data_t& m)
{
    serializer_class<npl_initial_recycle_pd_nw_rx_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_initial_recycle_pd_nw_rx_data_t&);



template<>
class serializer_class<npl_inject_down_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_header_t& m) {
            archive(::cereal::make_nvp("inject_down_encap_type", m.inject_down_encap_type));
            archive(::cereal::make_nvp("inject_phb", m.inject_phb));
            archive(::cereal::make_nvp("inject_destination", m.inject_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_header_t& m) {
            archive(::cereal::make_nvp("inject_down_encap_type", m.inject_down_encap_type));
            archive(::cereal::make_nvp("inject_phb", m.inject_phb));
            archive(::cereal::make_nvp("inject_destination", m.inject_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_header_t& m)
{
    serializer_class<npl_inject_down_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_header_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_header_t& m)
{
    serializer_class<npl_inject_down_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_header_t&);



template<>
class serializer_class<npl_inject_ts_and_lm_cmd_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_ts_and_lm_cmd_t& m) {
            archive(::cereal::make_nvp("time_stamp_cmd", m.time_stamp_cmd));
            archive(::cereal::make_nvp("counter_stamp_cmd", m.counter_stamp_cmd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_ts_and_lm_cmd_t& m) {
            archive(::cereal::make_nvp("time_stamp_cmd", m.time_stamp_cmd));
            archive(::cereal::make_nvp("counter_stamp_cmd", m.counter_stamp_cmd));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_ts_and_lm_cmd_t& m)
{
    serializer_class<npl_inject_ts_and_lm_cmd_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_ts_and_lm_cmd_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_ts_and_lm_cmd_t& m)
{
    serializer_class<npl_inject_ts_and_lm_cmd_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_ts_and_lm_cmd_t&);



template<>
class serializer_class<npl_inject_up_eth_qos_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_eth_qos_t& m) {
        uint64_t m_inject_up_qos_group = m.inject_up_qos_group;
        uint64_t m_inject_up_fwd_qos_tag = m.inject_up_fwd_qos_tag;
            archive(::cereal::make_nvp("inject_up_hdr_phb_src", m.inject_up_hdr_phb_src));
            archive(::cereal::make_nvp("inject_up_phb", m.inject_up_phb));
            archive(::cereal::make_nvp("inject_up_qos_group", m_inject_up_qos_group));
            archive(::cereal::make_nvp("inject_up_fwd_qos_tag", m_inject_up_fwd_qos_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_eth_qos_t& m) {
        uint64_t m_inject_up_qos_group;
        uint64_t m_inject_up_fwd_qos_tag;
            archive(::cereal::make_nvp("inject_up_hdr_phb_src", m.inject_up_hdr_phb_src));
            archive(::cereal::make_nvp("inject_up_phb", m.inject_up_phb));
            archive(::cereal::make_nvp("inject_up_qos_group", m_inject_up_qos_group));
            archive(::cereal::make_nvp("inject_up_fwd_qos_tag", m_inject_up_fwd_qos_tag));
        m.inject_up_qos_group = m_inject_up_qos_group;
        m.inject_up_fwd_qos_tag = m_inject_up_fwd_qos_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_eth_qos_t& m)
{
    serializer_class<npl_inject_up_eth_qos_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_eth_qos_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_eth_qos_t& m)
{
    serializer_class<npl_inject_up_eth_qos_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_eth_qos_t&);



template<>
class serializer_class<npl_ip_encap_data_t_anonymous_union_upper_layer_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_encap_data_t_anonymous_union_upper_layer_t& m) {
            archive(::cereal::make_nvp("vxlan_data", m.vxlan_data));
            archive(::cereal::make_nvp("gre_data", m.gre_data));
            archive(::cereal::make_nvp("udp_data", m.udp_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_encap_data_t_anonymous_union_upper_layer_t& m) {
            archive(::cereal::make_nvp("vxlan_data", m.vxlan_data));
            archive(::cereal::make_nvp("gre_data", m.gre_data));
            archive(::cereal::make_nvp("udp_data", m.udp_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_encap_data_t_anonymous_union_upper_layer_t& m)
{
    serializer_class<npl_ip_encap_data_t_anonymous_union_upper_layer_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_encap_data_t_anonymous_union_upper_layer_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_encap_data_t_anonymous_union_upper_layer_t& m)
{
    serializer_class<npl_ip_encap_data_t_anonymous_union_upper_layer_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_encap_data_t_anonymous_union_upper_layer_t&);



template<>
class serializer_class<npl_ip_lpm_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_lpm_result_t& m) {
        uint64_t m_no_hbm_access = m.no_hbm_access;
        uint64_t m_is_default_unused = m.is_default_unused;
            archive(::cereal::make_nvp("destination_or_default", m.destination_or_default));
            archive(::cereal::make_nvp("rtype_or_is_fec", m.rtype_or_is_fec));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_lpm_result_t& m) {
        uint64_t m_no_hbm_access;
        uint64_t m_is_default_unused;
            archive(::cereal::make_nvp("destination_or_default", m.destination_or_default));
            archive(::cereal::make_nvp("rtype_or_is_fec", m.rtype_or_is_fec));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
        m.no_hbm_access = m_no_hbm_access;
        m.is_default_unused = m_is_default_unused;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_lpm_result_t& m)
{
    serializer_class<npl_ip_lpm_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_lpm_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_lpm_result_t& m)
{
    serializer_class<npl_ip_lpm_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_lpm_result_t&);



template<>
class serializer_class<npl_ip_muxed_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_muxed_fields_t& m) {
        uint64_t m_muxed_is_bfd_and_udp = m.muxed_is_bfd_and_udp;
        uint64_t m_muxed_is_bfd = m.muxed_is_bfd;
        uint64_t m_muxed_is_hop_by_hop = m.muxed_is_hop_by_hop;
        uint64_t m_muxed_is_udp = m.muxed_is_udp;
            archive(::cereal::make_nvp("muxed_soft_lb_wa_enable", m.muxed_soft_lb_wa_enable));
            archive(::cereal::make_nvp("muxed_is_bfd_and_udp", m_muxed_is_bfd_and_udp));
            archive(::cereal::make_nvp("muxed_is_bfd", m_muxed_is_bfd));
            archive(::cereal::make_nvp("muxed_is_hop_by_hop", m_muxed_is_hop_by_hop));
            archive(::cereal::make_nvp("muxed_is_udp", m_muxed_is_udp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_muxed_fields_t& m) {
        uint64_t m_muxed_is_bfd_and_udp;
        uint64_t m_muxed_is_bfd;
        uint64_t m_muxed_is_hop_by_hop;
        uint64_t m_muxed_is_udp;
            archive(::cereal::make_nvp("muxed_soft_lb_wa_enable", m.muxed_soft_lb_wa_enable));
            archive(::cereal::make_nvp("muxed_is_bfd_and_udp", m_muxed_is_bfd_and_udp));
            archive(::cereal::make_nvp("muxed_is_bfd", m_muxed_is_bfd));
            archive(::cereal::make_nvp("muxed_is_hop_by_hop", m_muxed_is_hop_by_hop));
            archive(::cereal::make_nvp("muxed_is_udp", m_muxed_is_udp));
        m.muxed_is_bfd_and_udp = m_muxed_is_bfd_and_udp;
        m.muxed_is_bfd = m_muxed_is_bfd;
        m.muxed_is_hop_by_hop = m_muxed_is_hop_by_hop;
        m.muxed_is_udp = m_muxed_is_udp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_muxed_fields_t& m)
{
    serializer_class<npl_ip_muxed_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_muxed_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_muxed_fields_t& m)
{
    serializer_class<npl_ip_muxed_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_muxed_fields_t&);



template<>
class serializer_class<npl_ip_rtf_iteration_properties_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_rtf_iteration_properties_t& m) {
        uint64_t m_use_fwd1_interface = m.use_fwd1_interface;
            archive(::cereal::make_nvp("f0_rtf_prop", m.f0_rtf_prop));
            archive(::cereal::make_nvp("f1_rtf_prop", m.f1_rtf_prop));
            archive(::cereal::make_nvp("stop_on_step_and_next_stage_compressed_fields", m.stop_on_step_and_next_stage_compressed_fields));
            archive(::cereal::make_nvp("use_fwd1_interface", m_use_fwd1_interface));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_rtf_iteration_properties_t& m) {
        uint64_t m_use_fwd1_interface;
            archive(::cereal::make_nvp("f0_rtf_prop", m.f0_rtf_prop));
            archive(::cereal::make_nvp("f1_rtf_prop", m.f1_rtf_prop));
            archive(::cereal::make_nvp("stop_on_step_and_next_stage_compressed_fields", m.stop_on_step_and_next_stage_compressed_fields));
            archive(::cereal::make_nvp("use_fwd1_interface", m_use_fwd1_interface));
        m.use_fwd1_interface = m_use_fwd1_interface;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_rtf_iteration_properties_t& m)
{
    serializer_class<npl_ip_rtf_iteration_properties_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_rtf_iteration_properties_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_rtf_iteration_properties_t& m)
{
    serializer_class<npl_ip_rtf_iteration_properties_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_rtf_iteration_properties_t&);



template<>
class serializer_class<npl_ipv4_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_encap_data_t& m) {
            archive(::cereal::make_nvp("ene_ttl_and_protocol", m.ene_ttl_and_protocol));
            archive(::cereal::make_nvp("ene_ipv4_sip_dip", m.ene_ipv4_sip_dip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_encap_data_t& m) {
            archive(::cereal::make_nvp("ene_ttl_and_protocol", m.ene_ttl_and_protocol));
            archive(::cereal::make_nvp("ene_ipv4_sip_dip", m.ene_ipv4_sip_dip));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_encap_data_t& m)
{
    serializer_class<npl_ipv4_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_encap_data_t& m)
{
    serializer_class<npl_ipv4_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_encap_data_t&);



template<>
class serializer_class<npl_ipv4_ipv6_eth_init_rtf_stages_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ipv6_eth_init_rtf_stages_t& m) {
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("eth_init_rtf_stage", m.eth_init_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ipv6_eth_init_rtf_stages_t& m) {
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("eth_init_rtf_stage", m.eth_init_rtf_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ipv6_eth_init_rtf_stages_t& m)
{
    serializer_class<npl_ipv4_ipv6_eth_init_rtf_stages_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ipv6_eth_init_rtf_stages_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ipv6_eth_init_rtf_stages_t& m)
{
    serializer_class<npl_ipv4_ipv6_eth_init_rtf_stages_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ipv6_eth_init_rtf_stages_t&);



template<>
class serializer_class<npl_ipv6_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_encap_data_t& m) {
        uint64_t m_ene_ipv6_sip_msb = m.ene_ipv6_sip_msb;
            archive(::cereal::make_nvp("ene_nh_and_hl", m.ene_nh_and_hl));
            archive(::cereal::make_nvp("ene_ipv6_sip_msb", m_ene_ipv6_sip_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_encap_data_t& m) {
        uint64_t m_ene_ipv6_sip_msb;
            archive(::cereal::make_nvp("ene_nh_and_hl", m.ene_nh_and_hl));
            archive(::cereal::make_nvp("ene_ipv6_sip_msb", m_ene_ipv6_sip_msb));
        m.ene_ipv6_sip_msb = m_ene_ipv6_sip_msb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_encap_data_t& m)
{
    serializer_class<npl_ipv6_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_encap_data_t& m)
{
    serializer_class<npl_ipv6_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_encap_data_t&);



template<>
class serializer_class<npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t& m) {
        uint64_t m_vid2 = m.vid2;
            archive(::cereal::make_nvp("secondary_type_with_padding", m.secondary_type_with_padding));
            archive(::cereal::make_nvp("vid2", m_vid2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t& m) {
        uint64_t m_vid2;
            archive(::cereal::make_nvp("secondary_type_with_padding", m.secondary_type_with_padding));
            archive(::cereal::make_nvp("vid2", m_vid2));
        m.vid2 = m_vid2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t& m)
{
    serializer_class<npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t&);

template <class Archive>
void
load(Archive& archive, npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t& m)
{
    serializer_class<npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t&);



template<>
class serializer_class<npl_l2_ac_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_ac_encap_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_ac_encap_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_ac_encap_t& m)
{
    serializer_class<npl_l2_ac_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_ac_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_ac_encap_t& m)
{
    serializer_class<npl_l2_ac_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_ac_encap_t&);



template<>
class serializer_class<npl_l2_dlp_attr_on_nh_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_dlp_attr_on_nh_t& m) {
        uint64_t m_l2_tpid_prof = m.l2_tpid_prof;
            archive(::cereal::make_nvp("nh_ene_macro_code", m.nh_ene_macro_code));
            archive(::cereal::make_nvp("l2_tpid_prof", m_l2_tpid_prof));
            archive(::cereal::make_nvp("l2_dlp_qos_and_attr", m.l2_dlp_qos_and_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_dlp_attr_on_nh_t& m) {
        uint64_t m_l2_tpid_prof;
            archive(::cereal::make_nvp("nh_ene_macro_code", m.nh_ene_macro_code));
            archive(::cereal::make_nvp("l2_tpid_prof", m_l2_tpid_prof));
            archive(::cereal::make_nvp("l2_dlp_qos_and_attr", m.l2_dlp_qos_and_attr));
        m.l2_tpid_prof = m_l2_tpid_prof;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_dlp_attr_on_nh_t& m)
{
    serializer_class<npl_l2_dlp_attr_on_nh_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_dlp_attr_on_nh_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_dlp_attr_on_nh_t& m)
{
    serializer_class<npl_l2_dlp_attr_on_nh_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_dlp_attr_on_nh_t&);



template<>
class serializer_class<npl_l2_lp_with_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lp_with_padding_t& m) {
            archive(::cereal::make_nvp("l2_lp", m.l2_lp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lp_with_padding_t& m) {
            archive(::cereal::make_nvp("l2_lp", m.l2_lp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lp_with_padding_t& m)
{
    serializer_class<npl_l2_lp_with_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lp_with_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lp_with_padding_t& m)
{
    serializer_class<npl_l2_lp_with_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lp_with_padding_t&);



template<>
class serializer_class<npl_l2_lpts_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_payload_t& m) {
        uint64_t m_lacp = m.lacp;
        uint64_t m_l2cp0 = m.l2cp0;
        uint64_t m_l2cp1 = m.l2cp1;
        uint64_t m_l2cp2 = m.l2cp2;
        uint64_t m_l2cp3 = m.l2cp3;
        uint64_t m_l2cp4 = m.l2cp4;
        uint64_t m_l2cp5 = m.l2cp5;
        uint64_t m_l2cp6 = m.l2cp6;
        uint64_t m_l2cp7 = m.l2cp7;
        uint64_t m_cisco_protocols = m.cisco_protocols;
        uint64_t m_isis_over_l2 = m.isis_over_l2;
        uint64_t m_isis_drain = m.isis_drain;
        uint64_t m_isis_over_l3 = m.isis_over_l3;
        uint64_t m_arp = m.arp;
        uint64_t m_ptp_over_eth = m.ptp_over_eth;
        uint64_t m_macsec = m.macsec;
        uint64_t m_dhcpv4_server = m.dhcpv4_server;
        uint64_t m_dhcpv4_client = m.dhcpv4_client;
        uint64_t m_dhcpv6_server = m.dhcpv6_server;
        uint64_t m_dhcpv6_client = m.dhcpv6_client;
            archive(::cereal::make_nvp("lacp", m_lacp));
            archive(::cereal::make_nvp("l2cp0", m_l2cp0));
            archive(::cereal::make_nvp("l2cp1", m_l2cp1));
            archive(::cereal::make_nvp("l2cp2", m_l2cp2));
            archive(::cereal::make_nvp("l2cp3", m_l2cp3));
            archive(::cereal::make_nvp("l2cp4", m_l2cp4));
            archive(::cereal::make_nvp("l2cp5", m_l2cp5));
            archive(::cereal::make_nvp("l2cp6", m_l2cp6));
            archive(::cereal::make_nvp("l2cp7", m_l2cp7));
            archive(::cereal::make_nvp("cisco_protocols", m_cisco_protocols));
            archive(::cereal::make_nvp("isis_over_l2", m_isis_over_l2));
            archive(::cereal::make_nvp("isis_drain", m_isis_drain));
            archive(::cereal::make_nvp("isis_over_l3", m_isis_over_l3));
            archive(::cereal::make_nvp("arp", m_arp));
            archive(::cereal::make_nvp("ptp_over_eth", m_ptp_over_eth));
            archive(::cereal::make_nvp("macsec", m_macsec));
            archive(::cereal::make_nvp("dhcpv4_server", m_dhcpv4_server));
            archive(::cereal::make_nvp("dhcpv4_client", m_dhcpv4_client));
            archive(::cereal::make_nvp("dhcpv6_server", m_dhcpv6_server));
            archive(::cereal::make_nvp("dhcpv6_client", m_dhcpv6_client));
            archive(::cereal::make_nvp("rsvd", m.rsvd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_payload_t& m) {
        uint64_t m_lacp;
        uint64_t m_l2cp0;
        uint64_t m_l2cp1;
        uint64_t m_l2cp2;
        uint64_t m_l2cp3;
        uint64_t m_l2cp4;
        uint64_t m_l2cp5;
        uint64_t m_l2cp6;
        uint64_t m_l2cp7;
        uint64_t m_cisco_protocols;
        uint64_t m_isis_over_l2;
        uint64_t m_isis_drain;
        uint64_t m_isis_over_l3;
        uint64_t m_arp;
        uint64_t m_ptp_over_eth;
        uint64_t m_macsec;
        uint64_t m_dhcpv4_server;
        uint64_t m_dhcpv4_client;
        uint64_t m_dhcpv6_server;
        uint64_t m_dhcpv6_client;
            archive(::cereal::make_nvp("lacp", m_lacp));
            archive(::cereal::make_nvp("l2cp0", m_l2cp0));
            archive(::cereal::make_nvp("l2cp1", m_l2cp1));
            archive(::cereal::make_nvp("l2cp2", m_l2cp2));
            archive(::cereal::make_nvp("l2cp3", m_l2cp3));
            archive(::cereal::make_nvp("l2cp4", m_l2cp4));
            archive(::cereal::make_nvp("l2cp5", m_l2cp5));
            archive(::cereal::make_nvp("l2cp6", m_l2cp6));
            archive(::cereal::make_nvp("l2cp7", m_l2cp7));
            archive(::cereal::make_nvp("cisco_protocols", m_cisco_protocols));
            archive(::cereal::make_nvp("isis_over_l2", m_isis_over_l2));
            archive(::cereal::make_nvp("isis_drain", m_isis_drain));
            archive(::cereal::make_nvp("isis_over_l3", m_isis_over_l3));
            archive(::cereal::make_nvp("arp", m_arp));
            archive(::cereal::make_nvp("ptp_over_eth", m_ptp_over_eth));
            archive(::cereal::make_nvp("macsec", m_macsec));
            archive(::cereal::make_nvp("dhcpv4_server", m_dhcpv4_server));
            archive(::cereal::make_nvp("dhcpv4_client", m_dhcpv4_client));
            archive(::cereal::make_nvp("dhcpv6_server", m_dhcpv6_server));
            archive(::cereal::make_nvp("dhcpv6_client", m_dhcpv6_client));
            archive(::cereal::make_nvp("rsvd", m.rsvd));
        m.lacp = m_lacp;
        m.l2cp0 = m_l2cp0;
        m.l2cp1 = m_l2cp1;
        m.l2cp2 = m_l2cp2;
        m.l2cp3 = m_l2cp3;
        m.l2cp4 = m_l2cp4;
        m.l2cp5 = m_l2cp5;
        m.l2cp6 = m_l2cp6;
        m.l2cp7 = m_l2cp7;
        m.cisco_protocols = m_cisco_protocols;
        m.isis_over_l2 = m_isis_over_l2;
        m.isis_drain = m_isis_drain;
        m.isis_over_l3 = m_isis_over_l3;
        m.arp = m_arp;
        m.ptp_over_eth = m_ptp_over_eth;
        m.macsec = m_macsec;
        m.dhcpv4_server = m_dhcpv4_server;
        m.dhcpv4_client = m_dhcpv4_client;
        m.dhcpv6_server = m_dhcpv6_server;
        m.dhcpv6_client = m_dhcpv6_client;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_payload_t& m)
{
    serializer_class<npl_l2_lpts_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_payload_t& m)
{
    serializer_class<npl_l2_lpts_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_payload_t&);



template<>
class serializer_class<npl_l2_rtf_conf_set_and_init_stages_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_rtf_conf_set_and_init_stages_t& m) {
            archive(::cereal::make_nvp("rtf_conf_set_and_stages", m.rtf_conf_set_and_stages));
            archive(::cereal::make_nvp("eth_rtf_stage", m.eth_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_rtf_conf_set_and_init_stages_t& m) {
            archive(::cereal::make_nvp("rtf_conf_set_and_stages", m.rtf_conf_set_and_stages));
            archive(::cereal::make_nvp("eth_rtf_stage", m.eth_rtf_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_rtf_conf_set_and_init_stages_t& m)
{
    serializer_class<npl_l2_rtf_conf_set_and_init_stages_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_rtf_conf_set_and_init_stages_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_rtf_conf_set_and_init_stages_t& m)
{
    serializer_class<npl_l2_rtf_conf_set_and_init_stages_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_rtf_conf_set_and_init_stages_t&);



template<>
class serializer_class<npl_l3_dlp_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_encap_t& m) {
        uint64_t m_sa_prefix_index = m.sa_prefix_index;
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
            archive(::cereal::make_nvp("vlan_and_sa_lsb_encap", m.vlan_and_sa_lsb_encap));
            archive(::cereal::make_nvp("vid2_or_flood_rcy_sm_vlans", m.vid2_or_flood_rcy_sm_vlans));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_encap_t& m) {
        uint64_t m_sa_prefix_index;
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
            archive(::cereal::make_nvp("vlan_and_sa_lsb_encap", m.vlan_and_sa_lsb_encap));
            archive(::cereal::make_nvp("vid2_or_flood_rcy_sm_vlans", m.vid2_or_flood_rcy_sm_vlans));
        m.sa_prefix_index = m_sa_prefix_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_encap_t& m)
{
    serializer_class<npl_l3_dlp_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_encap_t& m)
{
    serializer_class<npl_l3_dlp_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_encap_t&);



template<>
class serializer_class<npl_l3_dlp_msbs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_msbs_t& m) {
            archive(::cereal::make_nvp("l3_dlp_msbs", m.l3_dlp_msbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_msbs_t& m) {
            archive(::cereal::make_nvp("l3_dlp_msbs", m.l3_dlp_msbs));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_msbs_t& m)
{
    serializer_class<npl_l3_dlp_msbs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_msbs_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_msbs_t& m)
{
    serializer_class<npl_l3_dlp_msbs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_msbs_t&);



template<>
class serializer_class<npl_l3_lp_additional_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_additional_attributes_t& m) {
        uint64_t m_enable_monitor = m.enable_monitor;
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("load_balance_profile", m.load_balance_profile));
            archive(::cereal::make_nvp("enable_monitor", m_enable_monitor));
            archive(::cereal::make_nvp("slp_based_fwd_and_per_vrf_mpls_fwd", m.slp_based_fwd_and_per_vrf_mpls_fwd));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_additional_attributes_t& m) {
        uint64_t m_enable_monitor;
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("load_balance_profile", m.load_balance_profile));
            archive(::cereal::make_nvp("enable_monitor", m_enable_monitor));
            archive(::cereal::make_nvp("slp_based_fwd_and_per_vrf_mpls_fwd", m.slp_based_fwd_and_per_vrf_mpls_fwd));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.enable_monitor = m_enable_monitor;
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_lp_additional_attributes_t& m)
{
    serializer_class<npl_l3_lp_additional_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_additional_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_additional_attributes_t& m)
{
    serializer_class<npl_l3_lp_additional_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_additional_attributes_t&);



template<>
class serializer_class<npl_l3_sa_lsb_on_nh_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_sa_lsb_on_nh_t& m) {
        uint64_t m_sa_prefix_index = m.sa_prefix_index;
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
            archive(::cereal::make_nvp("tpid_sa_lsb", m.tpid_sa_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_sa_lsb_on_nh_t& m) {
        uint64_t m_sa_prefix_index;
            archive(::cereal::make_nvp("sa_prefix_index", m_sa_prefix_index));
            archive(::cereal::make_nvp("tpid_sa_lsb", m.tpid_sa_lsb));
        m.sa_prefix_index = m_sa_prefix_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_sa_lsb_on_nh_t& m)
{
    serializer_class<npl_l3_sa_lsb_on_nh_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_sa_lsb_on_nh_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_sa_lsb_on_nh_t& m)
{
    serializer_class<npl_l3_sa_lsb_on_nh_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_sa_lsb_on_nh_t&);



template<>
class serializer_class<npl_l3_slp_msbs_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_slp_msbs_t& m) {
            archive(::cereal::make_nvp("l3_slp_msbs", m.l3_slp_msbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_slp_msbs_t& m) {
            archive(::cereal::make_nvp("l3_slp_msbs", m.l3_slp_msbs));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_slp_msbs_t& m)
{
    serializer_class<npl_l3_slp_msbs_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_slp_msbs_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_slp_msbs_t& m)
{
    serializer_class<npl_l3_slp_msbs_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_slp_msbs_t&);



template<>
class serializer_class<npl_l3_vxlan_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_vxlan_encap_t& m) {
        uint64_t m_overlay_nh = m.overlay_nh;
            archive(::cereal::make_nvp("tunnel_dlp", m.tunnel_dlp));
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_vxlan_encap_t& m) {
        uint64_t m_overlay_nh;
            archive(::cereal::make_nvp("tunnel_dlp", m.tunnel_dlp));
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
        m.overlay_nh = m_overlay_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_vxlan_encap_t& m)
{
    serializer_class<npl_l3_vxlan_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_vxlan_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_vxlan_encap_t& m)
{
    serializer_class<npl_l3_vxlan_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_vxlan_encap_t&);



template<>
class serializer_class<npl_l3_vxlan_relay_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_vxlan_relay_encap_data_t& m) {
        uint64_t m_vni = m.vni;
            archive(::cereal::make_nvp("overlay_nh_data", m.overlay_nh_data));
            archive(::cereal::make_nvp("vni", m_vni));
            archive(::cereal::make_nvp("vni_counter", m.vni_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_vxlan_relay_encap_data_t& m) {
        uint64_t m_vni;
            archive(::cereal::make_nvp("overlay_nh_data", m.overlay_nh_data));
            archive(::cereal::make_nvp("vni", m_vni));
            archive(::cereal::make_nvp("vni_counter", m.vni_counter));
        m.vni = m_vni;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_vxlan_relay_encap_data_t& m)
{
    serializer_class<npl_l3_vxlan_relay_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_vxlan_relay_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_vxlan_relay_encap_data_t& m)
{
    serializer_class<npl_l3_vxlan_relay_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_vxlan_relay_encap_data_t&);



template<>
class serializer_class<npl_label_or_num_labels_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_label_or_num_labels_t& m) {
        uint64_t m_label = m.label;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("num_labels", m.num_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_label_or_num_labels_t& m) {
        uint64_t m_label;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("num_labels", m.num_labels));
        m.label = m_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_label_or_num_labels_t& m)
{
    serializer_class<npl_label_or_num_labels_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_label_or_num_labels_t&);

template <class Archive>
void
load(Archive& archive, npl_label_or_num_labels_t& m)
{
    serializer_class<npl_label_or_num_labels_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_label_or_num_labels_t&);



template<>
class serializer_class<npl_ldp_over_te_tunnel_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ldp_over_te_tunnel_data_t& m) {
        uint64_t m_num_labels = m.num_labels;
            archive(::cereal::make_nvp("num_labels", m_num_labels));
            archive(::cereal::make_nvp("lsp_labels", m.lsp_labels));
            archive(::cereal::make_nvp("te_counter", m.te_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ldp_over_te_tunnel_data_t& m) {
        uint64_t m_num_labels;
            archive(::cereal::make_nvp("num_labels", m_num_labels));
            archive(::cereal::make_nvp("lsp_labels", m.lsp_labels));
            archive(::cereal::make_nvp("te_counter", m.te_counter));
        m.num_labels = m_num_labels;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ldp_over_te_tunnel_data_t& m)
{
    serializer_class<npl_ldp_over_te_tunnel_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ldp_over_te_tunnel_data_t&);

template <class Archive>
void
load(Archive& archive, npl_ldp_over_te_tunnel_data_t& m)
{
    serializer_class<npl_ldp_over_te_tunnel_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ldp_over_te_tunnel_data_t&);



template<>
class serializer_class<npl_lpts_object_groups_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_object_groups_t& m) {
            archive(::cereal::make_nvp("src_code", m.src_code));
            archive(::cereal::make_nvp("dest_code", m.dest_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_object_groups_t& m) {
            archive(::cereal::make_nvp("src_code", m.src_code));
            archive(::cereal::make_nvp("dest_code", m.dest_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_object_groups_t& m)
{
    serializer_class<npl_lpts_object_groups_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_object_groups_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_object_groups_t& m)
{
    serializer_class<npl_lpts_object_groups_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_object_groups_t&);



template<>
class serializer_class<npl_lpts_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_payload_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_payload_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("destination", m_destination));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_payload_t& m)
{
    serializer_class<npl_lpts_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_payload_t& m)
{
    serializer_class<npl_lpts_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_payload_t&);



template<>
class serializer_class<npl_lsp_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_destination_t& m) {
        uint64_t m_lsp_dest_prefix = m.lsp_dest_prefix;
            archive(::cereal::make_nvp("lsp_type", m.lsp_type));
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_destination_t& m) {
        uint64_t m_lsp_dest_prefix;
            archive(::cereal::make_nvp("lsp_type", m.lsp_type));
            archive(::cereal::make_nvp("lsp_dest_prefix", m_lsp_dest_prefix));
        m.lsp_dest_prefix = m_lsp_dest_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_destination_t& m)
{
    serializer_class<npl_lsp_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_destination_t& m)
{
    serializer_class<npl_lsp_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_destination_t&);



template<>
class serializer_class<npl_lsp_encap_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_encap_fields_t& m) {
            archive(::cereal::make_nvp("service_flags", m.service_flags));
            archive(::cereal::make_nvp("num_outer_transport_labels", m.num_outer_transport_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_encap_fields_t& m) {
            archive(::cereal::make_nvp("service_flags", m.service_flags));
            archive(::cereal::make_nvp("num_outer_transport_labels", m.num_outer_transport_labels));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_encap_fields_t& m)
{
    serializer_class<npl_lsp_encap_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_encap_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_encap_fields_t& m)
{
    serializer_class<npl_lsp_encap_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_encap_fields_t&);



template<>
class serializer_class<npl_lsp_labels_opt2_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_labels_opt2_t& m) {
        uint64_t m_label_0 = m.label_0;
            archive(::cereal::make_nvp("label_0", m_label_0));
            archive(::cereal::make_nvp("labels_1_2", m.labels_1_2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_labels_opt2_t& m) {
        uint64_t m_label_0;
            archive(::cereal::make_nvp("label_0", m_label_0));
            archive(::cereal::make_nvp("labels_1_2", m.labels_1_2));
        m.label_0 = m_label_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_labels_opt2_t& m)
{
    serializer_class<npl_lsp_labels_opt2_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_labels_opt2_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_labels_opt2_t& m)
{
    serializer_class<npl_lsp_labels_opt2_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_labels_opt2_t&);



template<>
class serializer_class<npl_lsr_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsr_encap_t& m) {
        uint64_t m_backup_te_tunnel = m.backup_te_tunnel;
            archive(::cereal::make_nvp("lsp", m.lsp));
            archive(::cereal::make_nvp("backup_te_tunnel", m_backup_te_tunnel));
            archive(::cereal::make_nvp("mldp_protection", m.mldp_protection));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsr_encap_t& m) {
        uint64_t m_backup_te_tunnel;
            archive(::cereal::make_nvp("lsp", m.lsp));
            archive(::cereal::make_nvp("backup_te_tunnel", m_backup_te_tunnel));
            archive(::cereal::make_nvp("mldp_protection", m.mldp_protection));
        m.backup_te_tunnel = m_backup_te_tunnel;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsr_encap_t& m)
{
    serializer_class<npl_lsr_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsr_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_lsr_encap_t& m)
{
    serializer_class<npl_lsr_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsr_encap_t&);



template<>
class serializer_class<npl_mac_af_npp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_af_npp_attributes_t& m) {
        uint64_t m_enable_sr_dm_accounting = m.enable_sr_dm_accounting;
        uint64_t m_npp_attributes = m.npp_attributes;
        uint64_t m_mac_relay_id = m.mac_relay_id;
        uint64_t m_enable_vlan_membership = m.enable_vlan_membership;
        uint64_t m_enable_vrf_for_l2 = m.enable_vrf_for_l2;
        uint64_t m_vlan_membership_index = m.vlan_membership_index;
        uint64_t m_enable_transparent_ptp = m.enable_transparent_ptp;
            archive(::cereal::make_nvp("enable_sr_dm_accounting", m_enable_sr_dm_accounting));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("mapping_type", m.mapping_type));
            archive(::cereal::make_nvp("port_vlan_tag", m.port_vlan_tag));
            archive(::cereal::make_nvp("mac_relay_id", m_mac_relay_id));
            archive(::cereal::make_nvp("enable_vlan_membership", m_enable_vlan_membership));
            archive(::cereal::make_nvp("enable_vrf_for_l2", m_enable_vrf_for_l2));
            archive(::cereal::make_nvp("vlan_membership_index", m_vlan_membership_index));
            archive(::cereal::make_nvp("enable_transparent_ptp", m_enable_transparent_ptp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_af_npp_attributes_t& m) {
        uint64_t m_enable_sr_dm_accounting;
        uint64_t m_npp_attributes;
        uint64_t m_mac_relay_id;
        uint64_t m_enable_vlan_membership;
        uint64_t m_enable_vrf_for_l2;
        uint64_t m_vlan_membership_index;
        uint64_t m_enable_transparent_ptp;
            archive(::cereal::make_nvp("enable_sr_dm_accounting", m_enable_sr_dm_accounting));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("mapping_type", m.mapping_type));
            archive(::cereal::make_nvp("port_vlan_tag", m.port_vlan_tag));
            archive(::cereal::make_nvp("mac_relay_id", m_mac_relay_id));
            archive(::cereal::make_nvp("enable_vlan_membership", m_enable_vlan_membership));
            archive(::cereal::make_nvp("enable_vrf_for_l2", m_enable_vrf_for_l2));
            archive(::cereal::make_nvp("vlan_membership_index", m_vlan_membership_index));
            archive(::cereal::make_nvp("enable_transparent_ptp", m_enable_transparent_ptp));
        m.enable_sr_dm_accounting = m_enable_sr_dm_accounting;
        m.npp_attributes = m_npp_attributes;
        m.mac_relay_id = m_mac_relay_id;
        m.enable_vlan_membership = m_enable_vlan_membership;
        m.enable_vrf_for_l2 = m_enable_vrf_for_l2;
        m.vlan_membership_index = m_vlan_membership_index;
        m.enable_transparent_ptp = m_enable_transparent_ptp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_af_npp_attributes_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_af_npp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_af_npp_attributes_t& m)
{
    serializer_class<npl_mac_af_npp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_af_npp_attributes_t&);



template<>
class serializer_class<npl_mac_forwarding_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_forwarding_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("mac_address", m.mac_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_forwarding_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("mac_address", m.mac_address));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_forwarding_key_t& m)
{
    serializer_class<npl_mac_forwarding_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_forwarding_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_forwarding_key_t& m)
{
    serializer_class<npl_mac_forwarding_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_forwarding_key_t&);



template<>
class serializer_class<npl_mac_lp_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_lp_attr_t& m) {
            archive(::cereal::make_nvp("vlan_profile_and_lp_type", m.vlan_profile_and_lp_type));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_lp_attr_t& m) {
            archive(::cereal::make_nvp("vlan_profile_and_lp_type", m.vlan_profile_and_lp_type));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_lp_attr_t& m)
{
    serializer_class<npl_mac_lp_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_lp_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_lp_attr_t& m)
{
    serializer_class<npl_mac_lp_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_lp_attr_t&);



template<>
class serializer_class<npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t& m)
{
    serializer_class<npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t& m)
{
    serializer_class<npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t&);



template<>
class serializer_class<npl_mac_relay_attributes_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_attributes_payload_t& m) {
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
            archive(::cereal::make_nvp("mac_l2_relay_attributes", m.mac_l2_relay_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_attributes_payload_t& m) {
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
            archive(::cereal::make_nvp("mac_l2_relay_attributes", m.mac_l2_relay_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_attributes_payload_t& m)
{
    serializer_class<npl_mac_relay_attributes_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_attributes_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_attributes_payload_t& m)
{
    serializer_class<npl_mac_relay_attributes_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_attributes_payload_t&);



template<>
class serializer_class<npl_mc_em_db_result_rx_single_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_result_rx_single_t& m) {
            archive(::cereal::make_nvp("tc_map_profile", m.tc_map_profile));
            archive(::cereal::make_nvp("base_voq_nr", m.base_voq_nr));
            archive(::cereal::make_nvp("mc_copy_id", m.mc_copy_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_result_rx_single_t& m) {
            archive(::cereal::make_nvp("tc_map_profile", m.tc_map_profile));
            archive(::cereal::make_nvp("base_voq_nr", m.base_voq_nr));
            archive(::cereal::make_nvp("mc_copy_id", m.mc_copy_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_result_rx_single_t& m)
{
    serializer_class<npl_mc_em_db_result_rx_single_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_result_rx_single_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_result_rx_single_t& m)
{
    serializer_class<npl_mc_em_db_result_rx_single_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_result_rx_single_t&);



template<>
class serializer_class<npl_mc_em_db_result_rx_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_result_rx_t& m) {
            archive(::cereal::make_nvp("result_1", m.result_1));
            archive(::cereal::make_nvp("result_0", m.result_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_result_rx_t& m) {
            archive(::cereal::make_nvp("result_1", m.result_1));
            archive(::cereal::make_nvp("result_0", m.result_0));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_result_rx_t& m)
{
    serializer_class<npl_mc_em_db_result_rx_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_result_rx_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_result_rx_t& m)
{
    serializer_class<npl_mc_em_db_result_rx_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_result_rx_t&);



template<>
class serializer_class<npl_mc_em_db_result_tx_format_0_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_result_tx_format_0_t& m) {
            archive(::cereal::make_nvp("tc_map_profile_1", m.tc_map_profile_1));
            archive(::cereal::make_nvp("tc_map_profile_0", m.tc_map_profile_0));
            archive(::cereal::make_nvp("oq_group_1", m.oq_group_1));
            archive(::cereal::make_nvp("oq_group_0", m.oq_group_0));
            archive(::cereal::make_nvp("mc_copy_id_1", m.mc_copy_id_1));
            archive(::cereal::make_nvp("mc_copy_id_0", m.mc_copy_id_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_result_tx_format_0_t& m) {
            archive(::cereal::make_nvp("tc_map_profile_1", m.tc_map_profile_1));
            archive(::cereal::make_nvp("tc_map_profile_0", m.tc_map_profile_0));
            archive(::cereal::make_nvp("oq_group_1", m.oq_group_1));
            archive(::cereal::make_nvp("oq_group_0", m.oq_group_0));
            archive(::cereal::make_nvp("mc_copy_id_1", m.mc_copy_id_1));
            archive(::cereal::make_nvp("mc_copy_id_0", m.mc_copy_id_0));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_result_tx_format_0_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_format_0_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_result_tx_format_0_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_result_tx_format_0_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_format_0_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_result_tx_format_0_t&);



template<>
class serializer_class<npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t& m) {
            archive(::cereal::make_nvp("format_0", m.format_0));
            archive(::cereal::make_nvp("format_1", m.format_1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t& m) {
            archive(::cereal::make_nvp("format_0", m.format_0));
            archive(::cereal::make_nvp("format_1", m.format_1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t&);



template<>
class serializer_class<npl_mc_slice_bitmap_table_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_slice_bitmap_table_entry_t& m) {
        uint64_t m_counterA_inc_enable = m.counterA_inc_enable;
            archive(::cereal::make_nvp("counterA_inc_enable", m_counterA_inc_enable));
            archive(::cereal::make_nvp("group_size_or_bitmap", m.group_size_or_bitmap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_slice_bitmap_table_entry_t& m) {
        uint64_t m_counterA_inc_enable;
            archive(::cereal::make_nvp("counterA_inc_enable", m_counterA_inc_enable));
            archive(::cereal::make_nvp("group_size_or_bitmap", m.group_size_or_bitmap));
        m.counterA_inc_enable = m_counterA_inc_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_slice_bitmap_table_entry_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_slice_bitmap_table_entry_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_slice_bitmap_table_entry_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_slice_bitmap_table_entry_t&);



template<>
class serializer_class<npl_mcid_array_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mcid_array_t& m) {
            archive(::cereal::make_nvp("mcid", m.mcid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mcid_array_t& m) {
            archive(::cereal::make_nvp("mcid", m.mcid));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mcid_array_t& m)
{
    serializer_class<npl_mcid_array_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mcid_array_t&);

template <class Archive>
void
load(Archive& archive, npl_mcid_array_t& m)
{
    serializer_class<npl_mcid_array_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mcid_array_t&);



template<>
class serializer_class<npl_mcid_array_wrapper_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mcid_array_wrapper_t& m) {
        uint64_t m_key = m.key;
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("key", m_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mcid_array_wrapper_t& m) {
        uint64_t m_key;
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("key", m_key));
        m.key = m_key;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mcid_array_wrapper_t& m)
{
    serializer_class<npl_mcid_array_wrapper_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mcid_array_wrapper_t&);

template <class Archive>
void
load(Archive& archive, npl_mcid_array_wrapper_t& m)
{
    serializer_class<npl_mcid_array_wrapper_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mcid_array_wrapper_t&);



template<>
class serializer_class<npl_mmm_tm_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mmm_tm_header_t& m) {
        uint64_t m_multicast_id = m.multicast_id;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("multicast_id", m_multicast_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mmm_tm_header_t& m) {
        uint64_t m_multicast_id;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("multicast_id", m_multicast_id));
        m.multicast_id = m_multicast_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mmm_tm_header_t& m)
{
    serializer_class<npl_mmm_tm_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mmm_tm_header_t&);

template <class Archive>
void
load(Archive& archive, npl_mmm_tm_header_t& m)
{
    serializer_class<npl_mmm_tm_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mmm_tm_header_t&);



template<>
class serializer_class<npl_more_labels_and_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_more_labels_and_flags_t& m) {
        uint64_t m_enable_sr_dm_accounting = m.enable_sr_dm_accounting;
        uint64_t m_multi_counter_enable = m.multi_counter_enable;
        uint64_t m_total_num_labels = m.total_num_labels;
            archive(::cereal::make_nvp("more_labels", m.more_labels));
            archive(::cereal::make_nvp("enable_sr_dm_accounting", m_enable_sr_dm_accounting));
            archive(::cereal::make_nvp("multi_counter_enable", m_multi_counter_enable));
            archive(::cereal::make_nvp("service_flags", m.service_flags));
            archive(::cereal::make_nvp("total_num_labels", m_total_num_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_more_labels_and_flags_t& m) {
        uint64_t m_enable_sr_dm_accounting;
        uint64_t m_multi_counter_enable;
        uint64_t m_total_num_labels;
            archive(::cereal::make_nvp("more_labels", m.more_labels));
            archive(::cereal::make_nvp("enable_sr_dm_accounting", m_enable_sr_dm_accounting));
            archive(::cereal::make_nvp("multi_counter_enable", m_multi_counter_enable));
            archive(::cereal::make_nvp("service_flags", m.service_flags));
            archive(::cereal::make_nvp("total_num_labels", m_total_num_labels));
        m.enable_sr_dm_accounting = m_enable_sr_dm_accounting;
        m.multi_counter_enable = m_multi_counter_enable;
        m.total_num_labels = m_total_num_labels;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_more_labels_and_flags_t& m)
{
    serializer_class<npl_more_labels_and_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_more_labels_and_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_more_labels_and_flags_t& m)
{
    serializer_class<npl_more_labels_and_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_more_labels_and_flags_t&);



template<>
class serializer_class<npl_mpls_termination_l3vpn_uc_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_l3vpn_uc_t& m) {
            archive(::cereal::make_nvp("allow_ipv4_ipv6_fwd_bits", m.allow_ipv4_ipv6_fwd_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_l3vpn_uc_t& m) {
            archive(::cereal::make_nvp("allow_ipv4_ipv6_fwd_bits", m.allow_ipv4_ipv6_fwd_bits));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_l3vpn_uc_t& m)
{
    serializer_class<npl_mpls_termination_l3vpn_uc_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_l3vpn_uc_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_l3vpn_uc_t& m)
{
    serializer_class<npl_mpls_termination_l3vpn_uc_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_l3vpn_uc_t&);



template<>
class serializer_class<npl_mpls_termination_pwe_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_pwe_t& m) {
        uint64_t m_is_pwe_raw = m.is_pwe_raw;
        uint64_t m_enable_mpls_tp_oam = m.enable_mpls_tp_oam;
        uint64_t m_fat_exists = m.fat_exists;
        uint64_t m_cw_exists = m.cw_exists;
            archive(::cereal::make_nvp("is_pwe_raw", m_is_pwe_raw));
            archive(::cereal::make_nvp("enable_mpls_tp_oam", m_enable_mpls_tp_oam));
            archive(::cereal::make_nvp("fat_exists", m_fat_exists));
            archive(::cereal::make_nvp("cw_exists", m_cw_exists));
            archive(::cereal::make_nvp("bfd_channel", m.bfd_channel));
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("mac_lp_attr", m.mac_lp_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_pwe_t& m) {
        uint64_t m_is_pwe_raw;
        uint64_t m_enable_mpls_tp_oam;
        uint64_t m_fat_exists;
        uint64_t m_cw_exists;
            archive(::cereal::make_nvp("is_pwe_raw", m_is_pwe_raw));
            archive(::cereal::make_nvp("enable_mpls_tp_oam", m_enable_mpls_tp_oam));
            archive(::cereal::make_nvp("fat_exists", m_fat_exists));
            archive(::cereal::make_nvp("cw_exists", m_cw_exists));
            archive(::cereal::make_nvp("bfd_channel", m.bfd_channel));
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("mac_lp_attr", m.mac_lp_attr));
        m.is_pwe_raw = m_is_pwe_raw;
        m.enable_mpls_tp_oam = m_enable_mpls_tp_oam;
        m.fat_exists = m_fat_exists;
        m.cw_exists = m_cw_exists;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_pwe_t& m)
{
    serializer_class<npl_mpls_termination_pwe_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_pwe_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_pwe_t& m)
{
    serializer_class<npl_mpls_termination_pwe_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_pwe_t&);



template<>
class serializer_class<npl_mum_tm_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mum_tm_header_t& m) {
        uint64_t m_reserved = m.reserved;
        uint64_t m_destination_device = m.destination_device;
        uint64_t m_destination_slice = m.destination_slice;
        uint64_t m_destination_txrq = m.destination_txrq;
        uint64_t m_multicast_id = m.multicast_id;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("destination_device", m_destination_device));
            archive(::cereal::make_nvp("destination_slice", m_destination_slice));
            archive(::cereal::make_nvp("destination_txrq", m_destination_txrq));
            archive(::cereal::make_nvp("multicast_id", m_multicast_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mum_tm_header_t& m) {
        uint64_t m_reserved;
        uint64_t m_destination_device;
        uint64_t m_destination_slice;
        uint64_t m_destination_txrq;
        uint64_t m_multicast_id;
            archive(::cereal::make_nvp("base", m.base));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("destination_device", m_destination_device));
            archive(::cereal::make_nvp("destination_slice", m_destination_slice));
            archive(::cereal::make_nvp("destination_txrq", m_destination_txrq));
            archive(::cereal::make_nvp("multicast_id", m_multicast_id));
        m.reserved = m_reserved;
        m.destination_device = m_destination_device;
        m.destination_slice = m_destination_slice;
        m.destination_txrq = m_destination_txrq;
        m.multicast_id = m_multicast_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mum_tm_header_t& m)
{
    serializer_class<npl_mum_tm_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mum_tm_header_t&);

template <class Archive>
void
load(Archive& archive, npl_mum_tm_header_t& m)
{
    serializer_class<npl_mum_tm_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mum_tm_header_t&);



template<>
class serializer_class<npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t& m) {
            archive(::cereal::make_nvp("sip_ip_tunnel_termination_attr", m.sip_ip_tunnel_termination_attr));
            archive(::cereal::make_nvp("tunnel_slp_id", m.tunnel_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t& m) {
            archive(::cereal::make_nvp("sip_ip_tunnel_termination_attr", m.sip_ip_tunnel_termination_attr));
            archive(::cereal::make_nvp("tunnel_slp_id", m.tunnel_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t& m)
{
    serializer_class<npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t&);

template <class Archive>
void
load(Archive& archive, npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t& m)
{
    serializer_class<npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t&);



template<>
class serializer_class<npl_native_ce_ptr_table_result_narrow_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_ce_ptr_table_result_narrow_t& m) {
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("destination2", m.destination2));
            archive(::cereal::make_nvp("stage2_ecmp_vpn_inter_as", m.stage2_ecmp_vpn_inter_as));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_ce_ptr_table_result_narrow_t& m) {
            archive(::cereal::make_nvp("destination1", m.destination1));
            archive(::cereal::make_nvp("destination2", m.destination2));
            archive(::cereal::make_nvp("stage2_ecmp_vpn_inter_as", m.stage2_ecmp_vpn_inter_as));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_ce_ptr_table_result_narrow_t& m)
{
    serializer_class<npl_native_ce_ptr_table_result_narrow_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_ce_ptr_table_result_narrow_t&);

template <class Archive>
void
load(Archive& archive, npl_native_ce_ptr_table_result_narrow_t& m)
{
    serializer_class<npl_native_ce_ptr_table_result_narrow_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_ce_ptr_table_result_narrow_t&);



template<>
class serializer_class<npl_native_ce_ptr_table_result_wide_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_ce_ptr_table_result_wide_t& m) {
            archive(::cereal::make_nvp("destination_te_tunnel16b", m.destination_te_tunnel16b));
            archive(::cereal::make_nvp("destination_ip_tunnel", m.destination_ip_tunnel));
            archive(::cereal::make_nvp("destination_ecmp_ce_ptr", m.destination_ecmp_ce_ptr));
            archive(::cereal::make_nvp("destination_stage3_nh", m.destination_stage3_nh));
            archive(::cereal::make_nvp("destination_stage2_p_nh", m.destination_stage2_p_nh));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_ce_ptr_table_result_wide_t& m) {
            archive(::cereal::make_nvp("destination_te_tunnel16b", m.destination_te_tunnel16b));
            archive(::cereal::make_nvp("destination_ip_tunnel", m.destination_ip_tunnel));
            archive(::cereal::make_nvp("destination_ecmp_ce_ptr", m.destination_ecmp_ce_ptr));
            archive(::cereal::make_nvp("destination_stage3_nh", m.destination_stage3_nh));
            archive(::cereal::make_nvp("destination_stage2_p_nh", m.destination_stage2_p_nh));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_ce_ptr_table_result_wide_t& m)
{
    serializer_class<npl_native_ce_ptr_table_result_wide_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_ce_ptr_table_result_wide_t&);

template <class Archive>
void
load(Archive& archive, npl_native_ce_ptr_table_result_wide_t& m)
{
    serializer_class<npl_native_ce_ptr_table_result_wide_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_ce_ptr_table_result_wide_t&);



template<>
class serializer_class<npl_native_frr_table_result_protected_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_frr_table_result_protected_t& m) {
        uint64_t m_type = m.type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_frr_table_result_protected_t& m) {
        uint64_t m_type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
        m.type = m_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_frr_table_result_protected_t& m)
{
    serializer_class<npl_native_frr_table_result_protected_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_frr_table_result_protected_t&);

template <class Archive>
void
load(Archive& archive, npl_native_frr_table_result_protected_t& m)
{
    serializer_class<npl_native_frr_table_result_protected_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_frr_table_result_protected_t&);



template<>
class serializer_class<npl_native_l2_lp_table_result_protected_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_table_result_protected_t& m) {
        uint64_t m_type = m.type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_table_result_protected_t& m) {
        uint64_t m_type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
        m.type = m_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_table_result_protected_t& m)
{
    serializer_class<npl_native_l2_lp_table_result_protected_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_table_result_protected_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_table_result_protected_t& m)
{
    serializer_class<npl_native_l2_lp_table_result_protected_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_table_result_protected_t&);



template<>
class serializer_class<npl_native_l2_lp_table_result_wide_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_native_l2_lp_table_result_wide_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination_te_tunnel16b", m.destination_te_tunnel16b));
            archive(::cereal::make_nvp("destination_overlay_nh", m.destination_overlay_nh));
            archive(::cereal::make_nvp("destination_ip_tunnel", m.destination_ip_tunnel));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_native_l2_lp_table_result_wide_t& m) {
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("destination_te_tunnel16b", m.destination_te_tunnel16b));
            archive(::cereal::make_nvp("destination_overlay_nh", m.destination_overlay_nh));
            archive(::cereal::make_nvp("destination_ip_tunnel", m.destination_ip_tunnel));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_native_l2_lp_table_result_wide_t& m)
{
    serializer_class<npl_native_l2_lp_table_result_wide_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_native_l2_lp_table_result_wide_t&);

template <class Archive>
void
load(Archive& archive, npl_native_l2_lp_table_result_wide_t& m)
{
    serializer_class<npl_native_l2_lp_table_result_wide_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_native_l2_lp_table_result_wide_t&);



template<>
class serializer_class<npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t& m) {
            archive(::cereal::make_nvp("l2_dlp_attr", m.l2_dlp_attr));
            archive(::cereal::make_nvp("l3_sa_lsb", m.l3_sa_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t& m) {
            archive(::cereal::make_nvp("l2_dlp_attr", m.l2_dlp_attr));
            archive(::cereal::make_nvp("l3_sa_lsb", m.l3_sa_lsb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t& m)
{
    serializer_class<npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t& m)
{
    serializer_class<npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t&);



template<>
class serializer_class<npl_npu_dsp_pif_ifg_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_dsp_pif_ifg_t& m) {
        uint64_t m_use_npu_header_pif_ifg = m.use_npu_header_pif_ifg;
            archive(::cereal::make_nvp("padded_pif_ifg", m.padded_pif_ifg));
            archive(::cereal::make_nvp("use_npu_header_pif_ifg", m_use_npu_header_pif_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_dsp_pif_ifg_t& m) {
        uint64_t m_use_npu_header_pif_ifg;
            archive(::cereal::make_nvp("padded_pif_ifg", m.padded_pif_ifg));
            archive(::cereal::make_nvp("use_npu_header_pif_ifg", m_use_npu_header_pif_ifg));
        m.use_npu_header_pif_ifg = m_use_npu_header_pif_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_dsp_pif_ifg_t& m)
{
    serializer_class<npl_npu_dsp_pif_ifg_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_dsp_pif_ifg_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_dsp_pif_ifg_t& m)
{
    serializer_class<npl_npu_dsp_pif_ifg_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_dsp_pif_ifg_t&);



template<>
class serializer_class<npl_object_groups_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_object_groups_t& m) {
            archive(::cereal::make_nvp("src_code", m.src_code));
            archive(::cereal::make_nvp("dest_code", m.dest_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_object_groups_t& m) {
            archive(::cereal::make_nvp("src_code", m.src_code));
            archive(::cereal::make_nvp("dest_code", m.dest_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_object_groups_t& m)
{
    serializer_class<npl_object_groups_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_object_groups_t&);

template <class Archive>
void
load(Archive& archive, npl_object_groups_t& m)
{
    serializer_class<npl_object_groups_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_object_groups_t&);



template<>
class serializer_class<npl_og_lpm_code_or_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_lpm_code_or_destination_t& m) {
            archive(::cereal::make_nvp("lpm_code", m.lpm_code));
            archive(::cereal::make_nvp("lpts_code", m.lpts_code));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_lpm_code_or_destination_t& m) {
            archive(::cereal::make_nvp("lpm_code", m.lpm_code));
            archive(::cereal::make_nvp("lpts_code", m.lpts_code));
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_lpm_code_or_destination_t& m)
{
    serializer_class<npl_og_lpm_code_or_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_lpm_code_or_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_og_lpm_code_or_destination_t& m)
{
    serializer_class<npl_og_lpm_code_or_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_lpm_code_or_destination_t&);



template<>
class serializer_class<npl_og_lpm_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_lpm_result_t& m) {
        uint64_t m_rtype = m.rtype;
        uint64_t m_no_hbm_access = m.no_hbm_access;
        uint64_t m_is_default_unused = m.is_default_unused;
            archive(::cereal::make_nvp("lpm_code_or_dest", m.lpm_code_or_dest));
            archive(::cereal::make_nvp("rtype", m_rtype));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_lpm_result_t& m) {
        uint64_t m_rtype;
        uint64_t m_no_hbm_access;
        uint64_t m_is_default_unused;
            archive(::cereal::make_nvp("lpm_code_or_dest", m.lpm_code_or_dest));
            archive(::cereal::make_nvp("rtype", m_rtype));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
        m.rtype = m_rtype;
        m.no_hbm_access = m_no_hbm_access;
        m.is_default_unused = m_is_default_unused;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_lpm_result_t& m)
{
    serializer_class<npl_og_lpm_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_lpm_result_t&);

template <class Archive>
void
load(Archive& archive, npl_og_lpm_result_t& m)
{
    serializer_class<npl_og_lpm_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_lpm_result_t&);



template<>
class serializer_class<npl_og_pcl_config_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_pcl_config_t& m) {
        uint64_t m_compress = m.compress;
            archive(::cereal::make_nvp("compress", m_compress));
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_pcl_config_t& m) {
        uint64_t m_compress;
            archive(::cereal::make_nvp("compress", m_compress));
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
        m.compress = m_compress;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_pcl_config_t& m)
{
    serializer_class<npl_og_pcl_config_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_pcl_config_t&);

template <class Archive>
void
load(Archive& archive, npl_og_pcl_config_t& m)
{
    serializer_class<npl_og_pcl_config_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_pcl_config_t&);



template<>
class serializer_class<npl_output_learn_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_output_learn_info_t& m) {
        uint64_t m_slp = m.slp;
            archive(::cereal::make_nvp("slp", m_slp));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_output_learn_info_t& m) {
        uint64_t m_slp;
            archive(::cereal::make_nvp("slp", m_slp));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
        m.slp = m_slp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_output_learn_info_t& m)
{
    serializer_class<npl_output_learn_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_output_learn_info_t&);

template <class Archive>
void
load(Archive& archive, npl_output_learn_info_t& m)
{
    serializer_class<npl_output_learn_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_output_learn_info_t&);



template<>
class serializer_class<npl_output_learn_record_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_output_learn_record_t& m) {
        uint64_t m_ethernet_address = m.ethernet_address;
        uint64_t m_mact_ldb = m.mact_ldb;
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("learn_info", m.learn_info));
            archive(::cereal::make_nvp("ethernet_address", m_ethernet_address));
            archive(::cereal::make_nvp("mact_ldb", m_mact_ldb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_output_learn_record_t& m) {
        uint64_t m_ethernet_address;
        uint64_t m_mact_ldb;
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("learn_info", m.learn_info));
            archive(::cereal::make_nvp("ethernet_address", m_ethernet_address));
            archive(::cereal::make_nvp("mact_ldb", m_mact_ldb));
        m.ethernet_address = m_ethernet_address;
        m.mact_ldb = m_mact_ldb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_output_learn_record_t& m)
{
    serializer_class<npl_output_learn_record_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_output_learn_record_t&);

template <class Archive>
void
load(Archive& archive, npl_output_learn_record_t& m)
{
    serializer_class<npl_output_learn_record_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_output_learn_record_t&);



template<>
class serializer_class<npl_overload_union_dlp_profile_union_t_user_app_data_defined_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_overload_union_dlp_profile_union_t_user_app_data_defined_t& m) {
        uint64_t m_user_app_data_defined = m.user_app_data_defined;
            archive(::cereal::make_nvp("user_app_dlp_profile", m.user_app_dlp_profile));
            archive(::cereal::make_nvp("user_app_data_defined", m_user_app_data_defined));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_overload_union_dlp_profile_union_t_user_app_data_defined_t& m) {
        uint64_t m_user_app_data_defined;
            archive(::cereal::make_nvp("user_app_dlp_profile", m.user_app_dlp_profile));
            archive(::cereal::make_nvp("user_app_data_defined", m_user_app_data_defined));
        m.user_app_data_defined = m_user_app_data_defined;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_overload_union_dlp_profile_union_t_user_app_data_defined_t& m)
{
    serializer_class<npl_overload_union_dlp_profile_union_t_user_app_data_defined_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_overload_union_dlp_profile_union_t_user_app_data_defined_t&);

template <class Archive>
void
load(Archive& archive, npl_overload_union_dlp_profile_union_t_user_app_data_defined_t& m)
{
    serializer_class<npl_overload_union_dlp_profile_union_t_user_app_data_defined_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_overload_union_dlp_profile_union_t_user_app_data_defined_t&);



template<>
class serializer_class<npl_path_lp_table_result_protected_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_result_protected_t& m) {
        uint64_t m_type = m.type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_result_protected_t& m) {
        uint64_t m_type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
        m.type = m_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_result_protected_t& m)
{
    serializer_class<npl_path_lp_table_result_protected_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_result_protected_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_result_protected_t& m)
{
    serializer_class<npl_path_lp_table_result_protected_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_result_protected_t&);



template<>
class serializer_class<npl_path_lp_table_result_wide_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_result_wide_t& m) {
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_result_wide_t& m) {
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_result_wide_t& m)
{
    serializer_class<npl_path_lp_table_result_wide_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_result_wide_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_result_wide_t& m)
{
    serializer_class<npl_path_lp_table_result_wide_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_result_wide_t&);



template<>
class serializer_class<npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t& m) {
            archive(::cereal::make_nvp("init_recycle_fields", m.init_recycle_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t& m) {
            archive(::cereal::make_nvp("init_recycle_fields", m.init_recycle_fields));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t& m)
{
    serializer_class<npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t&);

template <class Archive>
void
load(Archive& archive, npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t& m)
{
    serializer_class<npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t&);



template<>
class serializer_class<npl_pdoq_oq_ifc_mapping_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdoq_oq_ifc_mapping_result_t& m) {
        uint64_t m_fcn_profile = m.fcn_profile;
        uint64_t m_dest_pif = m.dest_pif;
            archive(::cereal::make_nvp("fcn_profile", m_fcn_profile));
            archive(::cereal::make_nvp("txpp_map_data", m.txpp_map_data));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdoq_oq_ifc_mapping_result_t& m) {
        uint64_t m_fcn_profile;
        uint64_t m_dest_pif;
            archive(::cereal::make_nvp("fcn_profile", m_fcn_profile));
            archive(::cereal::make_nvp("txpp_map_data", m.txpp_map_data));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
        m.fcn_profile = m_fcn_profile;
        m.dest_pif = m_dest_pif;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdoq_oq_ifc_mapping_result_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdoq_oq_ifc_mapping_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pdoq_oq_ifc_mapping_result_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdoq_oq_ifc_mapping_result_t&);



template<>
class serializer_class<npl_pdvoq_bank_pair_offset_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_bank_pair_offset_result_t& m) {
            archive(::cereal::make_nvp("array", m.array));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_bank_pair_offset_result_t& m) {
            archive(::cereal::make_nvp("array", m.array));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_bank_pair_offset_result_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_bank_pair_offset_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_bank_pair_offset_result_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_bank_pair_offset_result_t&);



template<>
class serializer_class<npl_pdvoq_slice_voq_properties_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_slice_voq_properties_result_t& m) {
        uint64_t m_type = m.type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("profile", m.profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_slice_voq_properties_result_t& m) {
        uint64_t m_type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("profile", m.profile));
        m.type = m_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_slice_voq_properties_result_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_slice_voq_properties_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_slice_voq_properties_result_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_slice_voq_properties_result_t&);



template<>
class serializer_class<npl_pfc_em_compound_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_em_compound_results_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_em_compound_results_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_em_compound_results_t& m)
{
    serializer_class<npl_pfc_em_compound_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_em_compound_results_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_em_compound_results_t& m)
{
    serializer_class<npl_pfc_em_compound_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_em_compound_results_t&);



template<>
class serializer_class<npl_port_npp_protection_table_result_protected_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_table_result_protected_t& m) {
        uint64_t m_type = m.type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_table_result_protected_t& m) {
        uint64_t m_type;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("path", m.path));
            archive(::cereal::make_nvp("protection_id", m.protection_id));
            archive(::cereal::make_nvp("primary", m.primary));
            archive(::cereal::make_nvp("protecting", m.protecting));
        m.type = m_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_table_result_protected_t& m)
{
    serializer_class<npl_port_npp_protection_table_result_protected_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_table_result_protected_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_table_result_protected_t& m)
{
    serializer_class<npl_port_npp_protection_table_result_protected_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_table_result_protected_t&);



template<>
class serializer_class<npl_post_fwd_params_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_post_fwd_params_t& m) {
            archive(::cereal::make_nvp("use_metedata_table_per_packet_format", m.use_metedata_table_per_packet_format));
            archive(::cereal::make_nvp("ip_ver_and_post_fwd_stage", m.ip_ver_and_post_fwd_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_post_fwd_params_t& m) {
            archive(::cereal::make_nvp("use_metedata_table_per_packet_format", m.use_metedata_table_per_packet_format));
            archive(::cereal::make_nvp("ip_ver_and_post_fwd_stage", m.ip_ver_and_post_fwd_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_post_fwd_params_t& m)
{
    serializer_class<npl_post_fwd_params_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_post_fwd_params_t&);

template <class Archive>
void
load(Archive& archive, npl_post_fwd_params_t& m)
{
    serializer_class<npl_post_fwd_params_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_post_fwd_params_t&);



template<>
class serializer_class<npl_properties_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_properties_t& m) {
            archive(::cereal::make_nvp("l3_dlp_id_ext", m.l3_dlp_id_ext));
            archive(::cereal::make_nvp("monitor_or_l3_dlp_ip_type", m.monitor_or_l3_dlp_ip_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_properties_t& m) {
            archive(::cereal::make_nvp("l3_dlp_id_ext", m.l3_dlp_id_ext));
            archive(::cereal::make_nvp("monitor_or_l3_dlp_ip_type", m.monitor_or_l3_dlp_ip_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_properties_t& m)
{
    serializer_class<npl_properties_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_properties_t&);

template <class Archive>
void
load(Archive& archive, npl_properties_t& m)
{
    serializer_class<npl_properties_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_properties_t&);



template<>
class serializer_class<npl_punt_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_code_t& m) {
        uint64_t m_punt_mirror_code = m.punt_mirror_code;
            archive(::cereal::make_nvp("punt_redirect_code", m.punt_redirect_code));
            archive(::cereal::make_nvp("snoop_code", m.snoop_code));
            archive(::cereal::make_nvp("punt_mirror_code", m_punt_mirror_code));
            archive(::cereal::make_nvp("lpts_reason", m.lpts_reason));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_code_t& m) {
        uint64_t m_punt_mirror_code;
            archive(::cereal::make_nvp("punt_redirect_code", m.punt_redirect_code));
            archive(::cereal::make_nvp("snoop_code", m.snoop_code));
            archive(::cereal::make_nvp("punt_mirror_code", m_punt_mirror_code));
            archive(::cereal::make_nvp("lpts_reason", m.lpts_reason));
        m.punt_mirror_code = m_punt_mirror_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_code_t& m)
{
    serializer_class<npl_punt_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_code_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_code_t& m)
{
    serializer_class<npl_punt_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_code_t&);



template<>
class serializer_class<npl_punt_encap_data_lsb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_encap_data_lsb_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
            archive(::cereal::make_nvp("punt_nw_encap_type", m.punt_nw_encap_type));
            archive(::cereal::make_nvp("extra", m.extra));
            archive(::cereal::make_nvp("punt_controls", m.punt_controls));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_encap_data_lsb_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
            archive(::cereal::make_nvp("punt_nw_encap_type", m.punt_nw_encap_type));
            archive(::cereal::make_nvp("extra", m.extra));
            archive(::cereal::make_nvp("punt_controls", m.punt_controls));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_encap_data_lsb_t& m)
{
    serializer_class<npl_punt_encap_data_lsb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_encap_data_lsb_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_encap_data_lsb_t& m)
{
    serializer_class<npl_punt_encap_data_lsb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_encap_data_lsb_t&);



template<>
class serializer_class<npl_punt_npu_host_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_npu_host_data_t& m) {
            archive(::cereal::make_nvp("npu_host_macro_data", m.npu_host_macro_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_npu_host_data_t& m) {
            archive(::cereal::make_nvp("npu_host_macro_data", m.npu_host_macro_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_npu_host_data_t& m)
{
    serializer_class<npl_punt_npu_host_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_npu_host_data_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_npu_host_data_t& m)
{
    serializer_class<npl_punt_npu_host_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_npu_host_data_t&);



template<>
class serializer_class<npl_punt_shared_lsb_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_shared_lsb_encap_t& m) {
            archive(::cereal::make_nvp("punt_ts_cmd", m.punt_ts_cmd));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("punt_cud_type", m.punt_cud_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_shared_lsb_encap_t& m) {
            archive(::cereal::make_nvp("punt_ts_cmd", m.punt_ts_cmd));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("punt_cud_type", m.punt_cud_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_shared_lsb_encap_t& m)
{
    serializer_class<npl_punt_shared_lsb_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_shared_lsb_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_shared_lsb_encap_t& m)
{
    serializer_class<npl_punt_shared_lsb_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_shared_lsb_encap_t&);



template<>
class serializer_class<npl_punt_src_and_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_src_and_code_t& m) {
            archive(::cereal::make_nvp("punt_source", m.punt_source));
            archive(::cereal::make_nvp("punt_code", m.punt_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_src_and_code_t& m) {
            archive(::cereal::make_nvp("punt_source", m.punt_source));
            archive(::cereal::make_nvp("punt_code", m.punt_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_src_and_code_t& m)
{
    serializer_class<npl_punt_src_and_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_src_and_code_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_src_and_code_t& m)
{
    serializer_class<npl_punt_src_and_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_src_and_code_t&);



template<>
class serializer_class<npl_punt_ssp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_ssp_attributes_t& m) {
            archive(::cereal::make_nvp("split_voq", m.split_voq));
            archive(::cereal::make_nvp("ssp", m.ssp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_ssp_attributes_t& m) {
            archive(::cereal::make_nvp("split_voq", m.split_voq));
            archive(::cereal::make_nvp("ssp", m.ssp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_ssp_attributes_t& m)
{
    serializer_class<npl_punt_ssp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_ssp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_ssp_attributes_t& m)
{
    serializer_class<npl_punt_ssp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_ssp_attributes_t&);



template<>
class serializer_class<npl_punt_sub_code_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_sub_code_t& m) {
            archive(::cereal::make_nvp("sub_code", m.sub_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_sub_code_t& m) {
            archive(::cereal::make_nvp("sub_code", m.sub_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_sub_code_t& m)
{
    serializer_class<npl_punt_sub_code_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_sub_code_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_sub_code_t& m)
{
    serializer_class<npl_punt_sub_code_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_sub_code_t&);



template<>
class serializer_class<npl_punt_sub_code_with_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_sub_code_with_padding_t& m) {
            archive(::cereal::make_nvp("ene_punt_sub_code", m.ene_punt_sub_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_sub_code_with_padding_t& m) {
            archive(::cereal::make_nvp("ene_punt_sub_code", m.ene_punt_sub_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_sub_code_with_padding_t& m)
{
    serializer_class<npl_punt_sub_code_with_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_sub_code_with_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_sub_code_with_padding_t& m)
{
    serializer_class<npl_punt_sub_code_with_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_sub_code_with_padding_t&);



template<>
class serializer_class<npl_pwe_to_l3_compound_lookup_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_to_l3_compound_lookup_result_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_to_l3_compound_lookup_result_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_to_l3_compound_lookup_result_t& m)
{
    serializer_class<npl_pwe_to_l3_compound_lookup_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_to_l3_compound_lookup_result_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_to_l3_compound_lookup_result_t& m)
{
    serializer_class<npl_pwe_to_l3_compound_lookup_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_to_l3_compound_lookup_result_t&);



template<>
class serializer_class<npl_qos_mapping_key_t_anonymous_union_key_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_mapping_key_t_anonymous_union_key_union_t& m) {
        uint64_t m_mpls_exp = m.mpls_exp;
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mpls_exp", m_mpls_exp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_mapping_key_t_anonymous_union_key_union_t& m) {
        uint64_t m_mpls_exp;
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mpls_exp", m_mpls_exp));
        m.mpls_exp = m_mpls_exp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_mapping_key_t_anonymous_union_key_union_t& m)
{
    serializer_class<npl_qos_mapping_key_t_anonymous_union_key_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_mapping_key_t_anonymous_union_key_union_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_mapping_key_t_anonymous_union_key_union_t& m)
{
    serializer_class<npl_qos_mapping_key_t_anonymous_union_key_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_mapping_key_t_anonymous_union_key_union_t&);



template<>
class serializer_class<npl_redirect_stage_og_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_stage_og_key_t& m) {
        uint64_t m_lpts_is_mc = m.lpts_is_mc;
        uint64_t m_lpts_og_app_id = m.lpts_og_app_id;
            archive(::cereal::make_nvp("lpts_is_mc", m_lpts_is_mc));
            archive(::cereal::make_nvp("lpts_og_app_id", m_lpts_og_app_id));
            archive(::cereal::make_nvp("lpts_packet_flags", m.lpts_packet_flags));
            archive(::cereal::make_nvp("lpts_object_groups", m.lpts_object_groups));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_stage_og_key_t& m) {
        uint64_t m_lpts_is_mc;
        uint64_t m_lpts_og_app_id;
            archive(::cereal::make_nvp("lpts_is_mc", m_lpts_is_mc));
            archive(::cereal::make_nvp("lpts_og_app_id", m_lpts_og_app_id));
            archive(::cereal::make_nvp("lpts_packet_flags", m.lpts_packet_flags));
            archive(::cereal::make_nvp("lpts_object_groups", m.lpts_object_groups));
        m.lpts_is_mc = m_lpts_is_mc;
        m.lpts_og_app_id = m_lpts_og_app_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_stage_og_key_t& m)
{
    serializer_class<npl_redirect_stage_og_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_stage_og_key_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_stage_og_key_t& m)
{
    serializer_class<npl_redirect_stage_og_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_stage_og_key_t&);



template<>
class serializer_class<npl_relay_attr_table_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_relay_attr_table_payload_t& m) {
            archive(::cereal::make_nvp("relay_attr", m.relay_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_relay_attr_table_payload_t& m) {
            archive(::cereal::make_nvp("relay_attr", m.relay_attr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_relay_attr_table_payload_t& m)
{
    serializer_class<npl_relay_attr_table_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_relay_attr_table_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_relay_attr_table_payload_t& m)
{
    serializer_class<npl_relay_attr_table_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_relay_attr_table_payload_t&);



template<>
class serializer_class<npl_rtf_next_macro_pack_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_next_macro_pack_fields_t& m) {
            archive(::cereal::make_nvp("curr_and_next_prot_type", m.curr_and_next_prot_type));
            archive(::cereal::make_nvp("stop_on_step_and_next_stage_compressed_fields", m.stop_on_step_and_next_stage_compressed_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_next_macro_pack_fields_t& m) {
            archive(::cereal::make_nvp("curr_and_next_prot_type", m.curr_and_next_prot_type));
            archive(::cereal::make_nvp("stop_on_step_and_next_stage_compressed_fields", m.stop_on_step_and_next_stage_compressed_fields));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_next_macro_pack_fields_t& m)
{
    serializer_class<npl_rtf_next_macro_pack_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_next_macro_pack_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_next_macro_pack_fields_t& m)
{
    serializer_class<npl_rtf_next_macro_pack_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_next_macro_pack_fields_t&);



template<>
class serializer_class<npl_rtf_result_profile_0_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_result_profile_0_t& m) {
        uint64_t m_q_m_offset_5bits = m.q_m_offset_5bits;
        uint64_t m_override_phb = m.override_phb;
        uint64_t m_override_qos_group = m.override_qos_group;
            archive(::cereal::make_nvp("mirror_action", m.mirror_action));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("q_m_offset_5bits", m_q_m_offset_5bits));
            archive(::cereal::make_nvp("counter_action_type", m.counter_action_type));
            archive(::cereal::make_nvp("mirror_cmd_or_offset", m.mirror_cmd_or_offset));
            archive(::cereal::make_nvp("override_phb", m_override_phb));
            archive(::cereal::make_nvp("rtf_sec_action", m.rtf_sec_action));
            archive(::cereal::make_nvp("override_qos_group", m_override_qos_group));
            archive(::cereal::make_nvp("ingress_qos_remark", m.ingress_qos_remark));
            archive(::cereal::make_nvp("force", m.force));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_result_profile_0_t& m) {
        uint64_t m_q_m_offset_5bits;
        uint64_t m_override_phb;
        uint64_t m_override_qos_group;
            archive(::cereal::make_nvp("mirror_action", m.mirror_action));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("q_m_offset_5bits", m_q_m_offset_5bits));
            archive(::cereal::make_nvp("counter_action_type", m.counter_action_type));
            archive(::cereal::make_nvp("mirror_cmd_or_offset", m.mirror_cmd_or_offset));
            archive(::cereal::make_nvp("override_phb", m_override_phb));
            archive(::cereal::make_nvp("rtf_sec_action", m.rtf_sec_action));
            archive(::cereal::make_nvp("override_qos_group", m_override_qos_group));
            archive(::cereal::make_nvp("ingress_qos_remark", m.ingress_qos_remark));
            archive(::cereal::make_nvp("force", m.force));
        m.q_m_offset_5bits = m_q_m_offset_5bits;
        m.override_phb = m_override_phb;
        m.override_qos_group = m_override_qos_group;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_result_profile_0_t& m)
{
    serializer_class<npl_rtf_result_profile_0_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_result_profile_0_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_result_profile_0_t& m)
{
    serializer_class<npl_rtf_result_profile_0_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_result_profile_0_t&);



template<>
class serializer_class<npl_rtf_result_profile_1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_result_profile_1_t& m) {
        uint64_t m_override_qos_group = m.override_qos_group;
            archive(::cereal::make_nvp("rtf_res_profile_1_action", m.rtf_res_profile_1_action));
            archive(::cereal::make_nvp("meter_or_counter", m.meter_or_counter));
            archive(::cereal::make_nvp("override_qos_group", m_override_qos_group));
            archive(::cereal::make_nvp("ingress_qos_remark", m.ingress_qos_remark));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_result_profile_1_t& m) {
        uint64_t m_override_qos_group;
            archive(::cereal::make_nvp("rtf_res_profile_1_action", m.rtf_res_profile_1_action));
            archive(::cereal::make_nvp("meter_or_counter", m.meter_or_counter));
            archive(::cereal::make_nvp("override_qos_group", m_override_qos_group));
            archive(::cereal::make_nvp("ingress_qos_remark", m.ingress_qos_remark));
            archive(::cereal::make_nvp("destination", m.destination));
        m.override_qos_group = m_override_qos_group;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_result_profile_1_t& m)
{
    serializer_class<npl_rtf_result_profile_1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_result_profile_1_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_result_profile_1_t& m)
{
    serializer_class<npl_rtf_result_profile_1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_result_profile_1_t&);



template<>
class serializer_class<npl_sch_oqse_cfg_result_4p_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sch_oqse_cfg_result_4p_t& m) {
            archive(::cereal::make_nvp("logical_port_map", m.logical_port_map));
            archive(::cereal::make_nvp("oqse_topology", m.oqse_topology));
            archive(::cereal::make_nvp("oqse_wfq_weight", m.oqse_wfq_weight));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sch_oqse_cfg_result_4p_t& m) {
            archive(::cereal::make_nvp("logical_port_map", m.logical_port_map));
            archive(::cereal::make_nvp("oqse_topology", m.oqse_topology));
            archive(::cereal::make_nvp("oqse_wfq_weight", m.oqse_wfq_weight));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sch_oqse_cfg_result_4p_t& m)
{
    serializer_class<npl_sch_oqse_cfg_result_4p_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sch_oqse_cfg_result_4p_t&);

template <class Archive>
void
load(Archive& archive, npl_sch_oqse_cfg_result_4p_t& m)
{
    serializer_class<npl_sch_oqse_cfg_result_4p_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sch_oqse_cfg_result_4p_t&);



template<>
class serializer_class<npl_sch_oqse_cfg_result_8p_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sch_oqse_cfg_result_8p_t& m) {
            archive(::cereal::make_nvp("logical_port_map", m.logical_port_map));
            archive(::cereal::make_nvp("oqse_topology", m.oqse_topology));
            archive(::cereal::make_nvp("oqse_wfq_weight", m.oqse_wfq_weight));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sch_oqse_cfg_result_8p_t& m) {
            archive(::cereal::make_nvp("logical_port_map", m.logical_port_map));
            archive(::cereal::make_nvp("oqse_topology", m.oqse_topology));
            archive(::cereal::make_nvp("oqse_wfq_weight", m.oqse_wfq_weight));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sch_oqse_cfg_result_8p_t& m)
{
    serializer_class<npl_sch_oqse_cfg_result_8p_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sch_oqse_cfg_result_8p_t&);

template <class Archive>
void
load(Archive& archive, npl_sch_oqse_cfg_result_8p_t& m)
{
    serializer_class<npl_sch_oqse_cfg_result_8p_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sch_oqse_cfg_result_8p_t&);



template<>
class serializer_class<npl_sch_oqse_cfg_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sch_oqse_cfg_result_t& m) {
            archive(::cereal::make_nvp("single_8p", m.single_8p));
            archive(::cereal::make_nvp("pair_4p", m.pair_4p));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sch_oqse_cfg_result_t& m) {
            archive(::cereal::make_nvp("single_8p", m.single_8p));
            archive(::cereal::make_nvp("pair_4p", m.pair_4p));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sch_oqse_cfg_result_t& m)
{
    serializer_class<npl_sch_oqse_cfg_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sch_oqse_cfg_result_t&);

template <class Archive>
void
load(Archive& archive, npl_sch_oqse_cfg_result_t& m)
{
    serializer_class<npl_sch_oqse_cfg_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sch_oqse_cfg_result_t&);



template<>
class serializer_class<npl_sec_acl_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sec_acl_attributes_t& m) {
        uint64_t m_rtf_conf_set_ptr = m.rtf_conf_set_ptr;
        uint64_t m_per_pkt_type_count = m.per_pkt_type_count;
        uint64_t m_l2_lpts_slp_attributes = m.l2_lpts_slp_attributes;
            archive(::cereal::make_nvp("rtf_conf_set_ptr", m_rtf_conf_set_ptr));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("slp_dlp", m.slp_dlp));
            archive(::cereal::make_nvp("per_pkt_type_count", m_per_pkt_type_count));
            archive(::cereal::make_nvp("port_mirror_type", m.port_mirror_type));
            archive(::cereal::make_nvp("l2_lpts_slp_attributes", m_l2_lpts_slp_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sec_acl_attributes_t& m) {
        uint64_t m_rtf_conf_set_ptr;
        uint64_t m_per_pkt_type_count;
        uint64_t m_l2_lpts_slp_attributes;
            archive(::cereal::make_nvp("rtf_conf_set_ptr", m_rtf_conf_set_ptr));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("slp_dlp", m.slp_dlp));
            archive(::cereal::make_nvp("per_pkt_type_count", m_per_pkt_type_count));
            archive(::cereal::make_nvp("port_mirror_type", m.port_mirror_type));
            archive(::cereal::make_nvp("l2_lpts_slp_attributes", m_l2_lpts_slp_attributes));
        m.rtf_conf_set_ptr = m_rtf_conf_set_ptr;
        m.per_pkt_type_count = m_per_pkt_type_count;
        m.l2_lpts_slp_attributes = m_l2_lpts_slp_attributes;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sec_acl_attributes_t& m)
{
    serializer_class<npl_sec_acl_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sec_acl_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_sec_acl_attributes_t& m)
{
    serializer_class<npl_sec_acl_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sec_acl_attributes_t&);



}

