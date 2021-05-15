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

template <class Archive> void save(Archive&, const npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t&);
template <class Archive> void load(Archive&, npl_base_l3_lp_attributes_t_anonymous_union_rtf_conf_set_and_stages_or_post_fwd_stage_t&);

template <class Archive> void save(Archive&, const npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t&);
template <class Archive> void load(Archive&, npl_bfd_aux_shared_payload_t_anonymous_union_prot_shared_t&);

template <class Archive> void save(Archive&, const npl_bfd_aux_transmit_payload_t&);
template <class Archive> void load(Archive&, npl_bfd_aux_transmit_payload_t&);

template <class Archive> void save(Archive&, const npl_bfd_flags_state_t_anonymous_union_bfd_flags_t&);
template <class Archive> void load(Archive&, npl_bfd_flags_state_t_anonymous_union_bfd_flags_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_common_cntr_5bits_offset_and_padding_t&);
template <class Archive> void load(Archive&, npl_common_cntr_5bits_offset_and_padding_t&);

template <class Archive> void save(Archive&, const npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t&);
template <class Archive> void load(Archive&, npl_common_cntr_offset_and_padding_t_anonymous_union_cntr_offset_t&);

template <class Archive> void save(Archive&, const npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t&);
template <class Archive> void load(Archive&, npl_common_cntr_offset_packed_t_anonymous_union_cntr_offset_t&);

template <class Archive> void save(Archive&, const npl_compressed_counter_t&);
template <class Archive> void load(Archive&, npl_compressed_counter_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_drop_color_t&);
template <class Archive> void load(Archive&, npl_drop_color_t&);

template <class Archive> void save(Archive&, const npl_egress_qos_result_t_anonymous_union_remark_l3_t&);
template <class Archive> void load(Archive&, npl_egress_qos_result_t_anonymous_union_remark_l3_t&);

template <class Archive> void save(Archive&, const npl_egress_sec_acl_result_t&);
template <class Archive> void load(Archive&, npl_egress_sec_acl_result_t&);

template <class Archive> void save(Archive&, const npl_encap_mpls_exp_t&);
template <class Archive> void load(Archive&, npl_encap_mpls_exp_t&);

template <class Archive> void save(Archive&, const npl_ene_inject_down_payload_t&);
template <class Archive> void load(Archive&, npl_ene_inject_down_payload_t&);

template <class Archive> void save(Archive&, const npl_ene_punt_dsp_and_ssp_t&);
template <class Archive> void load(Archive&, npl_ene_punt_dsp_and_ssp_t&);

template <class Archive> void save(Archive&, const npl_ethernet_mac_t&);
template <class Archive> void load(Archive&, npl_ethernet_mac_t&);

template <class Archive> void save(Archive&, const npl_exp_bos_and_label_t&);
template <class Archive> void load(Archive&, npl_exp_bos_and_label_t&);

template <class Archive> void save(Archive&, const npl_force_pipe_ttl_ingress_ptp_info_t&);
template <class Archive> void load(Archive&, npl_force_pipe_ttl_ingress_ptp_info_t&);

template <class Archive> void save(Archive&, const npl_header_format_t&);
template <class Archive> void load(Archive&, npl_header_format_t&);

template <class Archive> void save(Archive&, const npl_ingress_lpts_og_app_data_t&);
template <class Archive> void load(Archive&, npl_ingress_lpts_og_app_data_t&);

template <class Archive> void save(Archive&, const npl_ingress_qos_mapping_remark_t&);
template <class Archive> void load(Archive&, npl_ingress_qos_mapping_remark_t&);

template <class Archive> void save(Archive&, const npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t&);
template <class Archive> void load(Archive&, npl_ingress_qos_result_t_anonymous_union_fwd_class_qos_group_u_t&);

template <class Archive> void save(Archive&, const npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t&);
template <class Archive> void load(Archive&, npl_initial_pd_nw_rx_data_t_anonymous_union_init_data_t&);

template <class Archive> void save(Archive&, const npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t&);
template <class Archive> void load(Archive&, npl_initial_pd_nw_rx_data_t_anonymous_union_mapping_key_t&);

template <class Archive> void save(Archive&, const npl_inject_down_header_t&);
template <class Archive> void load(Archive&, npl_inject_down_header_t&);

template <class Archive> void save(Archive&, const npl_inject_ts_and_lm_cmd_t&);
template <class Archive> void load(Archive&, npl_inject_ts_and_lm_cmd_t&);

template <class Archive> void save(Archive&, const npl_inject_up_destination_override_t&);
template <class Archive> void load(Archive&, npl_inject_up_destination_override_t&);

template <class Archive> void save(Archive&, const npl_inject_up_eth_header_t_anonymous_union_from_port_t&);
template <class Archive> void load(Archive&, npl_inject_up_eth_header_t_anonymous_union_from_port_t&);

template <class Archive> void save(Archive&, const npl_inject_up_eth_qos_t&);
template <class Archive> void load(Archive&, npl_inject_up_eth_qos_t&);

template <class Archive> void save(Archive&, const npl_ip_encap_data_t_anonymous_union_upper_layer_t&);
template <class Archive> void load(Archive&, npl_ip_encap_data_t_anonymous_union_upper_layer_t&);

template <class Archive> void save(Archive&, const npl_ipv4_encap_data_t&);
template <class Archive> void load(Archive&, npl_ipv4_encap_data_t&);

template <class Archive> void save(Archive&, const npl_ipv6_encap_data_t&);
template <class Archive> void load(Archive&, npl_ipv6_encap_data_t&);

template <class Archive> void save(Archive&, const npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t&);
template <class Archive> void load(Archive&, npl_ive_profile_and_data_t_anonymous_union_secondary_type_or_vid_2_t&);

template <class Archive> void save(Archive&, const npl_l2_ac_encap_t&);
template <class Archive> void load(Archive&, npl_l2_ac_encap_t&);

template <class Archive> void save(Archive&, const npl_l2_dlp_t&);
template <class Archive> void load(Archive&, npl_l2_dlp_t&);

template <class Archive> void save(Archive&, const npl_l2_global_slp_t&);
template <class Archive> void load(Archive&, npl_l2_global_slp_t&);

template <class Archive> void save(Archive&, const npl_l2_relay_id_t&);
template <class Archive> void load(Archive&, npl_l2_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l2vpn_label_encap_data_t&);
template <class Archive> void load(Archive&, npl_l2vpn_label_encap_data_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_encap_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_encap_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_lsbs_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_lsbs_t&);

template <class Archive> void save(Archive&, const npl_l3_dlp_msbs_t&);
template <class Archive> void load(Archive&, npl_l3_dlp_msbs_t&);

template <class Archive> void save(Archive&, const npl_l3_ecn_ctrl_t&);
template <class Archive> void load(Archive&, npl_l3_ecn_ctrl_t&);

template <class Archive> void save(Archive&, const npl_l3_lp_additional_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_lp_additional_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_pfc_data_t&);
template <class Archive> void load(Archive&, npl_l3_pfc_data_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l3_slp_lsbs_t&);
template <class Archive> void load(Archive&, npl_l3_slp_lsbs_t&);

template <class Archive> void save(Archive&, const npl_l3_slp_msbs_t&);
template <class Archive> void load(Archive&, npl_l3_slp_msbs_t&);

template <class Archive> void save(Archive&, const npl_l3_vxlan_encap_t&);
template <class Archive> void load(Archive&, npl_l3_vxlan_encap_t&);

template <class Archive> void save(Archive&, const npl_label_or_num_labels_t&);
template <class Archive> void load(Archive&, npl_label_or_num_labels_t&);

template <class Archive> void save(Archive&, const npl_ldp_over_te_tunnel_data_t&);
template <class Archive> void load(Archive&, npl_ldp_over_te_tunnel_data_t&);

template <class Archive> void save(Archive&, const npl_lm_command_t&);
template <class Archive> void load(Archive&, npl_lm_command_t&);

template <class Archive> void save(Archive&, const npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t&);
template <class Archive> void load(Archive&, npl_lpts_tcam_first_result_encap_data_msb_t_anonymous_union_encap_punt_code_t&);

template <class Archive> void save(Archive&, const npl_lsp_destination_t&);
template <class Archive> void load(Archive&, npl_lsp_destination_t&);

template <class Archive> void save(Archive&, const npl_lsp_labels_opt2_t&);
template <class Archive> void load(Archive&, npl_lsp_labels_opt2_t&);

template <class Archive> void save(Archive&, const npl_lsp_labels_opt3_t&);
template <class Archive> void load(Archive&, npl_lsp_labels_opt3_t&);

template <class Archive> void save(Archive&, const npl_lsp_labels_t&);
template <class Archive> void load(Archive&, npl_lsp_labels_t&);

template <class Archive> void save(Archive&, const npl_lsr_encap_t&);
template <class Archive> void load(Archive&, npl_lsr_encap_t&);

template <class Archive> void save(Archive&, const npl_mac_addr_t&);
template <class Archive> void load(Archive&, npl_mac_addr_t&);

template <class Archive> void save(Archive&, const npl_mac_l2_relay_attributes_t&);
template <class Archive> void load(Archive&, npl_mac_l2_relay_attributes_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t&);
template <class Archive> void load(Archive&, npl_mac_relay_attributes_inf_payload_t_anonymous_union_l2_relay_id_or_l3_attr_u_t&);

template <class Archive> void save(Archive&, const npl_mac_relay_attributes_payload_t&);
template <class Archive> void load(Archive&, npl_mac_relay_attributes_payload_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db_result_rx_t&);
template <class Archive> void load(Archive&, npl_mc_em_db_result_rx_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t&);
template <class Archive> void load(Archive&, npl_mc_em_db_result_tx_t_anonymous_union_format_0_or_1_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_t&);

template <class Archive> void save(Archive&, const npl_mmm_tm_header_t&);
template <class Archive> void load(Archive&, npl_mmm_tm_header_t&);

template <class Archive> void save(Archive&, const npl_more_labels_and_flags_t&);
template <class Archive> void load(Archive&, npl_more_labels_and_flags_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_l3vpn_uc_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_l3vpn_uc_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_mldp_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_mldp_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_pwe_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_pwe_t&);

template <class Archive> void save(Archive&, const npl_mum_tm_header_t&);
template <class Archive> void load(Archive&, npl_mum_tm_header_t&);

template <class Archive> void save(Archive&, const npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t&);
template <class Archive> void load(Archive&, npl_my_ipv4_table_payload_t_anonymous_union_ip_tunnel_termination_attr_or_slp_t&);

template <class Archive> void save(Archive&, const npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t&);
template <class Archive> void load(Archive&, npl_nh_payload_t_anonymous_union_l3_sa_vlan_or_l2_dlp_attr_t&);

template <class Archive> void save(Archive&, const npl_npu_dsp_pif_ifg_t&);
template <class Archive> void load(Archive&, npl_npu_dsp_pif_ifg_t&);

template <class Archive> void save(Archive&, const npl_npu_encap_header_l2_dlp_t&);
template <class Archive> void load(Archive&, npl_npu_encap_header_l2_dlp_t&);

template <class Archive> void save(Archive&, const npl_npu_l3_mc_accounting_encap_data_t&);
template <class Archive> void load(Archive&, npl_npu_l3_mc_accounting_encap_data_t&);

template <class Archive> void save(Archive&, const npl_og_lpm_code_or_destination_t&);
template <class Archive> void load(Archive&, npl_og_lpm_code_or_destination_t&);

template <class Archive> void save(Archive&, const npl_og_pcl_config_t&);
template <class Archive> void load(Archive&, npl_og_pcl_config_t&);

template <class Archive> void save(Archive&, const npl_overload_union_dlp_profile_union_t_user_app_data_defined_t&);
template <class Archive> void load(Archive&, npl_overload_union_dlp_profile_union_t_user_app_data_defined_t&);

template <class Archive> void save(Archive&, const npl_pcp_dei_t&);
template <class Archive> void load(Archive&, npl_pcp_dei_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_properties_t&);
template <class Archive> void load(Archive&, npl_properties_t&);

template <class Archive> void save(Archive&, const npl_punt_encap_data_lsb_t&);
template <class Archive> void load(Archive&, npl_punt_encap_data_lsb_t&);

template <class Archive> void save(Archive&, const npl_punt_eth_transport_update_t&);
template <class Archive> void load(Archive&, npl_punt_eth_transport_update_t&);

template <class Archive> void save(Archive&, const npl_punt_npu_host_data_t&);
template <class Archive> void load(Archive&, npl_punt_npu_host_data_t&);

template <class Archive> void save(Archive&, const npl_punt_shared_lsb_encap_t&);
template <class Archive> void load(Archive&, npl_punt_shared_lsb_encap_t&);

template <class Archive> void save(Archive&, const npl_punt_sub_code_t&);
template <class Archive> void load(Archive&, npl_punt_sub_code_t&);

template <class Archive> void save(Archive&, const npl_qos_attributes_t&);
template <class Archive> void load(Archive&, npl_qos_attributes_t&);

template <class Archive> void save(Archive&, const npl_qos_encap_t&);
template <class Archive> void load(Archive&, npl_qos_encap_t&);

template <class Archive> void save(Archive&, const npl_qos_mapping_key_t_anonymous_union_key_union_t&);
template <class Archive> void load(Archive&, npl_qos_mapping_key_t_anonymous_union_key_union_t&);

template <class Archive> void save(Archive&, const npl_quan_1b&);
template <class Archive> void load(Archive&, npl_quan_1b&);

template <class Archive> void save(Archive&, const npl_rtf_result_profile_0_t&);
template <class Archive> void load(Archive&, npl_rtf_result_profile_0_t&);

template <class Archive> void save(Archive&, const npl_rtf_result_profile_1_t&);
template <class Archive> void load(Archive&, npl_rtf_result_profile_1_t&);

template <class Archive> void save(Archive&, const npl_rtf_result_profile_2_t&);
template <class Archive> void load(Archive&, npl_rtf_result_profile_2_t&);

template <class Archive> void save(Archive&, const npl_rtf_result_profile_3_t&);
template <class Archive> void load(Archive&, npl_rtf_result_profile_3_t&);

template <class Archive> void save(Archive&, const npl_sec_acl_attributes_t&);
template <class Archive> void load(Archive&, npl_sec_acl_attributes_t&);

template <class Archive> void save(Archive&, const npl_source_if_t&);
template <class Archive> void load(Archive&, npl_source_if_t&);

template <class Archive> void save(Archive&, const npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t&);
template <class Archive> void load(Archive&, npl_sport_or_l4_protocol_t_anonymous_union_sport_or_l4_protocol_type_t&);

template <class Archive> void save(Archive&, const npl_svi_eve_sub_type_plus_prf_t&);
template <class Archive> void load(Archive&, npl_svi_eve_sub_type_plus_prf_t&);

template <class Archive> void save(Archive&, const npl_svi_eve_vid2_plus_prf_t&);
template <class Archive> void load(Archive&, npl_svi_eve_vid2_plus_prf_t&);

template <class Archive> void save(Archive&, const npl_te_headend_nhlfe_t&);
template <class Archive> void load(Archive&, npl_te_headend_nhlfe_t&);

template <class Archive> void save(Archive&, const npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t&);
template <class Archive> void load(Archive&, npl_te_midpoint_nhlfe_t_anonymous_union_lsp_t&);

template <class Archive> void save(Archive&, const npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t&);
template <class Archive> void load(Archive&, npl_tunnel_headend_encap_t_anonymous_union_te_asbr_t&);

template <class Archive> void save(Archive&, const npl_udf_t&);
template <class Archive> void load(Archive&, npl_udf_t&);

template <class Archive> void save(Archive&, const npl_unicast_flb_tm_header_t&);
template <class Archive> void load(Archive&, npl_unicast_flb_tm_header_t&);

template <class Archive> void save(Archive&, const npl_unicast_plb_tm_header_t&);
template <class Archive> void load(Archive&, npl_unicast_plb_tm_header_t&);

template <class Archive> void save(Archive&, const npl_unscheduled_recycle_code_t&);
template <class Archive> void load(Archive&, npl_unscheduled_recycle_code_t&);

template <class Archive> void save(Archive&, const npl_vlan_id_t&);
template <class Archive> void load(Archive&, npl_vlan_id_t&);

template <class Archive> void save(Archive&, const npl_vpl_label_and_valid_t&);
template <class Archive> void load(Archive&, npl_vpl_label_and_valid_t&);

template<>
class serializer_class<npl_shared_l2_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_shared_l2_lp_attributes_t& m) {
        uint64_t m_p2p = m.p2p;
        uint64_t m_qos_id = m.qos_id;
        uint64_t m_lp_profile = m.lp_profile;
        uint64_t m_stp_state_block = m.stp_state_block;
        uint64_t m_mirror_cmd = m.mirror_cmd;
            archive(::cereal::make_nvp("p2p", m_p2p));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("stp_state_block", m_stp_state_block));
            archive(::cereal::make_nvp("mirror_cmd", m_mirror_cmd));
            archive(::cereal::make_nvp("sec_acl_attributes", m.sec_acl_attributes));
            archive(::cereal::make_nvp("q_counter", m.q_counter));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_shared_l2_lp_attributes_t& m) {
        uint64_t m_p2p;
        uint64_t m_qos_id;
        uint64_t m_lp_profile;
        uint64_t m_stp_state_block;
        uint64_t m_mirror_cmd;
            archive(::cereal::make_nvp("p2p", m_p2p));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("stp_state_block", m_stp_state_block));
            archive(::cereal::make_nvp("mirror_cmd", m_mirror_cmd));
            archive(::cereal::make_nvp("sec_acl_attributes", m.sec_acl_attributes));
            archive(::cereal::make_nvp("q_counter", m.q_counter));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
        m.p2p = m_p2p;
        m.qos_id = m_qos_id;
        m.lp_profile = m_lp_profile;
        m.stp_state_block = m_stp_state_block;
        m.mirror_cmd = m_mirror_cmd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_shared_l2_lp_attributes_t& m)
{
    serializer_class<npl_shared_l2_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_shared_l2_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_shared_l2_lp_attributes_t& m)
{
    serializer_class<npl_shared_l2_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_shared_l2_lp_attributes_t&);



template<>
class serializer_class<npl_single_label_encap_data_t_anonymous_union_udat_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_single_label_encap_data_t_anonymous_union_udat_t& m) {
        uint64_t m_gre_key = m.gre_key;
            archive(::cereal::make_nvp("gre_key", m_gre_key));
            archive(::cereal::make_nvp("label_and_valid", m.label_and_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_single_label_encap_data_t_anonymous_union_udat_t& m) {
        uint64_t m_gre_key;
            archive(::cereal::make_nvp("gre_key", m_gre_key));
            archive(::cereal::make_nvp("label_and_valid", m.label_and_valid));
        m.gre_key = m_gre_key;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_single_label_encap_data_t_anonymous_union_udat_t& m)
{
    serializer_class<npl_single_label_encap_data_t_anonymous_union_udat_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_single_label_encap_data_t_anonymous_union_udat_t&);

template <class Archive>
void
load(Archive& archive, npl_single_label_encap_data_t_anonymous_union_udat_t& m)
{
    serializer_class<npl_single_label_encap_data_t_anonymous_union_udat_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_single_label_encap_data_t_anonymous_union_udat_t&);



template<>
class serializer_class<npl_slice_and_source_if_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slice_and_source_if_t& m) {
        uint64_t m_slice_id_on_npu = m.slice_id_on_npu;
            archive(::cereal::make_nvp("slice_id_on_npu", m_slice_id_on_npu));
            archive(::cereal::make_nvp("source_if_on_npu", m.source_if_on_npu));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slice_and_source_if_t& m) {
        uint64_t m_slice_id_on_npu;
            archive(::cereal::make_nvp("slice_id_on_npu", m_slice_id_on_npu));
            archive(::cereal::make_nvp("source_if_on_npu", m.source_if_on_npu));
        m.slice_id_on_npu = m_slice_id_on_npu;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slice_and_source_if_t& m)
{
    serializer_class<npl_slice_and_source_if_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slice_and_source_if_t&);

template <class Archive>
void
load(Archive& archive, npl_slice_and_source_if_t& m)
{
    serializer_class<npl_slice_and_source_if_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slice_and_source_if_t&);



template<>
class serializer_class<npl_sport_or_l4_protocol_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sport_or_l4_protocol_t& m) {
            archive(::cereal::make_nvp("sport_or_l4_protocol_type", m.sport_or_l4_protocol_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sport_or_l4_protocol_t& m) {
            archive(::cereal::make_nvp("sport_or_l4_protocol_type", m.sport_or_l4_protocol_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sport_or_l4_protocol_t& m)
{
    serializer_class<npl_sport_or_l4_protocol_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sport_or_l4_protocol_t&);

template <class Archive>
void
load(Archive& archive, npl_sport_or_l4_protocol_t& m)
{
    serializer_class<npl_sport_or_l4_protocol_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sport_or_l4_protocol_t&);



template<>
class serializer_class<npl_svi_eve_sub_type_plus_pad_plus_prf_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svi_eve_sub_type_plus_pad_plus_prf_t& m) {
            archive(::cereal::make_nvp("sub_type_plus_prf", m.sub_type_plus_prf));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svi_eve_sub_type_plus_pad_plus_prf_t& m) {
            archive(::cereal::make_nvp("sub_type_plus_prf", m.sub_type_plus_prf));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svi_eve_sub_type_plus_pad_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_sub_type_plus_pad_plus_prf_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svi_eve_sub_type_plus_pad_plus_prf_t&);

template <class Archive>
void
load(Archive& archive, npl_svi_eve_sub_type_plus_pad_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_sub_type_plus_pad_plus_prf_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svi_eve_sub_type_plus_pad_plus_prf_t&);



template<>
class serializer_class<npl_te_midpoint_nhlfe_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_te_midpoint_nhlfe_t& m) {
        uint64_t m_mp_label = m.mp_label;
        uint64_t m_midpoint_nh = m.midpoint_nh;
            archive(::cereal::make_nvp("mp_label", m_mp_label));
            archive(::cereal::make_nvp("lsp", m.lsp));
            archive(::cereal::make_nvp("midpoint_nh", m_midpoint_nh));
            archive(::cereal::make_nvp("counter_offset", m.counter_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_te_midpoint_nhlfe_t& m) {
        uint64_t m_mp_label;
        uint64_t m_midpoint_nh;
            archive(::cereal::make_nvp("mp_label", m_mp_label));
            archive(::cereal::make_nvp("lsp", m.lsp));
            archive(::cereal::make_nvp("midpoint_nh", m_midpoint_nh));
            archive(::cereal::make_nvp("counter_offset", m.counter_offset));
        m.mp_label = m_mp_label;
        m.midpoint_nh = m_midpoint_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_te_midpoint_nhlfe_t& m)
{
    serializer_class<npl_te_midpoint_nhlfe_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_te_midpoint_nhlfe_t&);

template <class Archive>
void
load(Archive& archive, npl_te_midpoint_nhlfe_t& m)
{
    serializer_class<npl_te_midpoint_nhlfe_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_te_midpoint_nhlfe_t&);



template<>
class serializer_class<npl_tunnel_headend_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_headend_encap_t& m) {
            archive(::cereal::make_nvp("lsp_destination", m.lsp_destination));
            archive(::cereal::make_nvp("te_asbr", m.te_asbr));
            archive(::cereal::make_nvp("mldp_protection", m.mldp_protection));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_headend_encap_t& m) {
            archive(::cereal::make_nvp("lsp_destination", m.lsp_destination));
            archive(::cereal::make_nvp("te_asbr", m.te_asbr));
            archive(::cereal::make_nvp("mldp_protection", m.mldp_protection));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_headend_encap_t& m)
{
    serializer_class<npl_tunnel_headend_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_headend_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_headend_encap_t& m)
{
    serializer_class<npl_tunnel_headend_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_headend_encap_t&);



template<>
class serializer_class<npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t& m) {
            archive(::cereal::make_nvp("force_pipe_ttl_ingress_ptp_null", m.force_pipe_ttl_ingress_ptp_null));
            archive(::cereal::make_nvp("force_pipe_ttl_ingress_ptp_info", m.force_pipe_ttl_ingress_ptp_info));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t& m) {
            archive(::cereal::make_nvp("force_pipe_ttl_ingress_ptp_null", m.force_pipe_ttl_ingress_ptp_null));
            archive(::cereal::make_nvp("force_pipe_ttl_ingress_ptp_info", m.force_pipe_ttl_ingress_ptp_info));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t& m)
{
    serializer_class<npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t& m)
{
    serializer_class<npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_type_and_force_pipe_ttl_ingress_ptp_info_t&);



template<>
class serializer_class<npl_tx_to_rx_rcy_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_to_rx_rcy_data_t& m) {
        uint64_t m_unscheduled_recycle_data = m.unscheduled_recycle_data;
            archive(::cereal::make_nvp("unscheduled_recycle_code", m.unscheduled_recycle_code));
            archive(::cereal::make_nvp("unscheduled_recycle_data", m_unscheduled_recycle_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_to_rx_rcy_data_t& m) {
        uint64_t m_unscheduled_recycle_data;
            archive(::cereal::make_nvp("unscheduled_recycle_code", m.unscheduled_recycle_code));
            archive(::cereal::make_nvp("unscheduled_recycle_data", m_unscheduled_recycle_data));
        m.unscheduled_recycle_data = m_unscheduled_recycle_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_to_rx_rcy_data_t& m)
{
    serializer_class<npl_tx_to_rx_rcy_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_to_rx_rcy_data_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_to_rx_rcy_data_t& m)
{
    serializer_class<npl_tx_to_rx_rcy_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_to_rx_rcy_data_t&);



template<>
class serializer_class<npl_ud_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ud_key_t& m) {
            archive(::cereal::make_nvp("udfs", m.udfs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ud_key_t& m) {
            archive(::cereal::make_nvp("udfs", m.udfs));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ud_key_t& m)
{
    serializer_class<npl_ud_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ud_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ud_key_t& m)
{
    serializer_class<npl_ud_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ud_key_t&);



template<>
class serializer_class<npl_unicast_flb_tm_header_padded_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_unicast_flb_tm_header_padded_t& m) {
            archive(::cereal::make_nvp("unicast_flb_tm_header", m.unicast_flb_tm_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_unicast_flb_tm_header_padded_t& m) {
            archive(::cereal::make_nvp("unicast_flb_tm_header", m.unicast_flb_tm_header));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_unicast_flb_tm_header_padded_t& m)
{
    serializer_class<npl_unicast_flb_tm_header_padded_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_unicast_flb_tm_header_padded_t&);

template <class Archive>
void
load(Archive& archive, npl_unicast_flb_tm_header_padded_t& m)
{
    serializer_class<npl_unicast_flb_tm_header_padded_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_unicast_flb_tm_header_padded_t&);



template<>
class serializer_class<npl_unicast_plb_tm_header_padded_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_unicast_plb_tm_header_padded_t& m) {
            archive(::cereal::make_nvp("unicast_plb_tm_header", m.unicast_plb_tm_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_unicast_plb_tm_header_padded_t& m) {
            archive(::cereal::make_nvp("unicast_plb_tm_header", m.unicast_plb_tm_header));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_unicast_plb_tm_header_padded_t& m)
{
    serializer_class<npl_unicast_plb_tm_header_padded_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_unicast_plb_tm_header_padded_t&);

template <class Archive>
void
load(Archive& archive, npl_unicast_plb_tm_header_padded_t& m)
{
    serializer_class<npl_unicast_plb_tm_header_padded_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_unicast_plb_tm_header_padded_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t& m) {
        uint64_t m_drop_green_u = m.drop_green_u;
            archive(::cereal::make_nvp("drop_green", m.drop_green));
            archive(::cereal::make_nvp("drop_green_u", m_drop_green_u));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t& m) {
        uint64_t m_drop_green_u;
            archive(::cereal::make_nvp("drop_green", m.drop_green));
            archive(::cereal::make_nvp("drop_green_u", m_drop_green_u));
        m.drop_green_u = m_drop_green_u;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_g_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t& m) {
        uint64_t m_drop_yellow_u = m.drop_yellow_u;
            archive(::cereal::make_nvp("drop_yellow", m.drop_yellow));
            archive(::cereal::make_nvp("drop_yellow_u", m_drop_yellow_u));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t& m) {
        uint64_t m_drop_yellow_u;
            archive(::cereal::make_nvp("drop_yellow", m.drop_yellow));
            archive(::cereal::make_nvp("drop_yellow_u", m_drop_yellow_u));
        m.drop_yellow_u = m_drop_yellow_u;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t_anonymous_union_drop_y_t&);



template<>
class serializer_class<npl_additional_labels_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_additional_labels_t& m) {
        uint64_t m_label_3 = m.label_3;
        uint64_t m_label_4 = m.label_4;
        uint64_t m_label_5 = m.label_5;
        uint64_t m_label_6 = m.label_6;
        uint64_t m_label_7 = m.label_7;
            archive(::cereal::make_nvp("label_3", m_label_3));
            archive(::cereal::make_nvp("label_4", m_label_4));
            archive(::cereal::make_nvp("label_5", m_label_5));
            archive(::cereal::make_nvp("label_6", m_label_6));
            archive(::cereal::make_nvp("label_7", m_label_7));
            archive(::cereal::make_nvp("label_8_or_num_labels", m.label_8_or_num_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_additional_labels_t& m) {
        uint64_t m_label_3;
        uint64_t m_label_4;
        uint64_t m_label_5;
        uint64_t m_label_6;
        uint64_t m_label_7;
            archive(::cereal::make_nvp("label_3", m_label_3));
            archive(::cereal::make_nvp("label_4", m_label_4));
            archive(::cereal::make_nvp("label_5", m_label_5));
            archive(::cereal::make_nvp("label_6", m_label_6));
            archive(::cereal::make_nvp("label_7", m_label_7));
            archive(::cereal::make_nvp("label_8_or_num_labels", m.label_8_or_num_labels));
        m.label_3 = m_label_3;
        m.label_4 = m_label_4;
        m.label_5 = m_label_5;
        m.label_6 = m_label_6;
        m.label_7 = m_label_7;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_additional_labels_t& m)
{
    serializer_class<npl_additional_labels_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_additional_labels_t&);

template <class Archive>
void
load(Archive& archive, npl_additional_labels_t& m)
{
    serializer_class<npl_additional_labels_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_additional_labels_t&);



template<>
class serializer_class<npl_bfd_aux_shared_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_aux_shared_payload_t& m) {
        uint64_t m_local_discriminator = m.local_discriminator;
        uint64_t m_remote_discriminator = m.remote_discriminator;
        uint64_t m_tos = m.tos;
        uint64_t m_local_diag_code = m.local_diag_code;
        uint64_t m_requires_inject_up = m.requires_inject_up;
            archive(::cereal::make_nvp("local_discriminator", m_local_discriminator));
            archive(::cereal::make_nvp("remote_discriminator", m_remote_discriminator));
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("local_diag_code", m_local_diag_code));
            archive(::cereal::make_nvp("requires_inject_up", m_requires_inject_up));
            archive(::cereal::make_nvp("session_type", m.session_type));
            archive(::cereal::make_nvp("prot_shared", m.prot_shared));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_aux_shared_payload_t& m) {
        uint64_t m_local_discriminator;
        uint64_t m_remote_discriminator;
        uint64_t m_tos;
        uint64_t m_local_diag_code;
        uint64_t m_requires_inject_up;
            archive(::cereal::make_nvp("local_discriminator", m_local_discriminator));
            archive(::cereal::make_nvp("remote_discriminator", m_remote_discriminator));
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("local_diag_code", m_local_diag_code));
            archive(::cereal::make_nvp("requires_inject_up", m_requires_inject_up));
            archive(::cereal::make_nvp("session_type", m.session_type));
            archive(::cereal::make_nvp("prot_shared", m.prot_shared));
        m.local_discriminator = m_local_discriminator;
        m.remote_discriminator = m_remote_discriminator;
        m.tos = m_tos;
        m.local_diag_code = m_local_diag_code;
        m.requires_inject_up = m_requires_inject_up;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_aux_shared_payload_t& m)
{
    serializer_class<npl_bfd_aux_shared_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_aux_shared_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_aux_shared_payload_t& m)
{
    serializer_class<npl_bfd_aux_shared_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_aux_shared_payload_t&);



template<>
class serializer_class<npl_bfd_em_lookup_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_em_lookup_t& m) {
        uint64_t m_encap_result = m.encap_result;
        uint64_t m_meter = m.meter;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("encap_result", m_encap_result));
            archive(::cereal::make_nvp("meter", m_meter));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("punt_encap_data", m.punt_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_em_lookup_t& m) {
        uint64_t m_encap_result;
        uint64_t m_meter;
        uint64_t m_destination;
            archive(::cereal::make_nvp("encap_result", m_encap_result));
            archive(::cereal::make_nvp("meter", m_meter));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("punt_encap_data", m.punt_encap_data));
        m.encap_result = m_encap_result;
        m.meter = m_meter;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_em_lookup_t& m)
{
    serializer_class<npl_bfd_em_lookup_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_em_lookup_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_em_lookup_t& m)
{
    serializer_class<npl_bfd_em_lookup_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_em_lookup_t&);



template<>
class serializer_class<npl_bfd_flags_state_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_flags_state_t& m) {
        uint64_t m_state = m.state;
            archive(::cereal::make_nvp("state", m_state));
            archive(::cereal::make_nvp("bfd_flags", m.bfd_flags));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_flags_state_t& m) {
        uint64_t m_state;
            archive(::cereal::make_nvp("state", m_state));
            archive(::cereal::make_nvp("bfd_flags", m.bfd_flags));
        m.state = m_state;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_flags_state_t& m)
{
    serializer_class<npl_bfd_flags_state_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_flags_state_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_flags_state_t& m)
{
    serializer_class<npl_bfd_flags_state_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_flags_state_t&);



template<>
class serializer_class<npl_bfd_remote_session_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_remote_session_attributes_t& m) {
        uint64_t m_last_time = m.last_time;
        uint64_t m_rmep_profile = m.rmep_profile;
        uint64_t m_rmep_valid = m.rmep_valid;
            archive(::cereal::make_nvp("last_time", m_last_time));
            archive(::cereal::make_nvp("remote_info", m.remote_info));
            archive(::cereal::make_nvp("rmep_profile", m_rmep_profile));
            archive(::cereal::make_nvp("rmep_valid", m_rmep_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_remote_session_attributes_t& m) {
        uint64_t m_last_time;
        uint64_t m_rmep_profile;
        uint64_t m_rmep_valid;
            archive(::cereal::make_nvp("last_time", m_last_time));
            archive(::cereal::make_nvp("remote_info", m.remote_info));
            archive(::cereal::make_nvp("rmep_profile", m_rmep_profile));
            archive(::cereal::make_nvp("rmep_valid", m_rmep_valid));
        m.last_time = m_last_time;
        m.rmep_profile = m_rmep_profile;
        m.rmep_valid = m_rmep_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_remote_session_attributes_t& m)
{
    serializer_class<npl_bfd_remote_session_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_remote_session_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_remote_session_attributes_t& m)
{
    serializer_class<npl_bfd_remote_session_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_remote_session_attributes_t&);



template<>
class serializer_class<npl_common_cntr_offset_and_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_cntr_offset_and_padding_t& m) {
            archive(::cereal::make_nvp("cntr_offset", m.cntr_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_cntr_offset_and_padding_t& m) {
            archive(::cereal::make_nvp("cntr_offset", m.cntr_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_cntr_offset_and_padding_t& m)
{
    serializer_class<npl_common_cntr_offset_and_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_cntr_offset_and_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_common_cntr_offset_and_padding_t& m)
{
    serializer_class<npl_common_cntr_offset_and_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_cntr_offset_and_padding_t&);



template<>
class serializer_class<npl_common_cntr_offset_packed_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_cntr_offset_packed_t& m) {
            archive(::cereal::make_nvp("cntr_offset", m.cntr_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_cntr_offset_packed_t& m) {
            archive(::cereal::make_nvp("cntr_offset", m.cntr_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_cntr_offset_packed_t& m)
{
    serializer_class<npl_common_cntr_offset_packed_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_cntr_offset_packed_t&);

template <class Archive>
void
load(Archive& archive, npl_common_cntr_offset_packed_t& m)
{
    serializer_class<npl_common_cntr_offset_packed_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_cntr_offset_packed_t&);



template<>
class serializer_class<npl_destination_prefix_lp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_destination_prefix_lp_t& m) {
        uint64_t m_prefix = m.prefix;
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("lsbs", m.lsbs));
            archive(::cereal::make_nvp("msbs", m.msbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_destination_prefix_lp_t& m) {
        uint64_t m_prefix;
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("lsbs", m.lsbs));
            archive(::cereal::make_nvp("msbs", m.msbs));
        m.prefix = m_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_destination_prefix_lp_t& m)
{
    serializer_class<npl_destination_prefix_lp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_destination_prefix_lp_t&);

template <class Archive>
void
load(Archive& archive, npl_destination_prefix_lp_t& m)
{
    serializer_class<npl_destination_prefix_lp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_destination_prefix_lp_t&);



template<>
class serializer_class<npl_dlp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dlp_attributes_t& m) {
        uint64_t m_lp_profile = m.lp_profile;
            archive(::cereal::make_nvp("acl_drop_offset", m.acl_drop_offset));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("port_mirror_type", m.port_mirror_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dlp_attributes_t& m) {
        uint64_t m_lp_profile;
            archive(::cereal::make_nvp("acl_drop_offset", m.acl_drop_offset));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
            archive(::cereal::make_nvp("port_mirror_type", m.port_mirror_type));
        m.lp_profile = m_lp_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dlp_attributes_t& m)
{
    serializer_class<npl_dlp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dlp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_dlp_attributes_t& m)
{
    serializer_class<npl_dlp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dlp_attributes_t&);



template<>
class serializer_class<npl_dlp_profile_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dlp_profile_union_t& m) {
        uint64_t m_data = m.data;
            archive(::cereal::make_nvp("data", m_data));
            archive(::cereal::make_nvp("overload_union_user_app_data_defined", m.overload_union_user_app_data_defined));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dlp_profile_union_t& m) {
        uint64_t m_data;
            archive(::cereal::make_nvp("data", m_data));
            archive(::cereal::make_nvp("overload_union_user_app_data_defined", m.overload_union_user_app_data_defined));
        m.data = m_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dlp_profile_union_t& m)
{
    serializer_class<npl_dlp_profile_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dlp_profile_union_t&);

template <class Archive>
void
load(Archive& archive, npl_dlp_profile_union_t& m)
{
    serializer_class<npl_dlp_profile_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dlp_profile_union_t&);



template<>
class serializer_class<npl_egress_ipv6_acl_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_ipv6_acl_result_t& m) {
            archive(::cereal::make_nvp("sec", m.sec));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_ipv6_acl_result_t& m) {
            archive(::cereal::make_nvp("sec", m.sec));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_ipv6_acl_result_t& m)
{
    serializer_class<npl_egress_ipv6_acl_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_ipv6_acl_result_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_ipv6_acl_result_t& m)
{
    serializer_class<npl_egress_ipv6_acl_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_ipv6_acl_result_t&);



template<>
class serializer_class<npl_egress_qos_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_qos_result_t& m) {
        uint64_t m_fwd_remark_exp = m.fwd_remark_exp;
        uint64_t m_remark_l2 = m.remark_l2;
        uint64_t m_fwd_remark_dscp = m.fwd_remark_dscp;
            archive(::cereal::make_nvp("fwd_remark_exp", m_fwd_remark_exp));
            archive(::cereal::make_nvp("remark_l2", m_remark_l2));
            archive(::cereal::make_nvp("remark_l3", m.remark_l3));
            archive(::cereal::make_nvp("q_offset", m.q_offset));
            archive(::cereal::make_nvp("fwd_remark_dscp", m_fwd_remark_dscp));
            archive(::cereal::make_nvp("encap", m.encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_qos_result_t& m) {
        uint64_t m_fwd_remark_exp;
        uint64_t m_remark_l2;
        uint64_t m_fwd_remark_dscp;
            archive(::cereal::make_nvp("fwd_remark_exp", m_fwd_remark_exp));
            archive(::cereal::make_nvp("remark_l2", m_remark_l2));
            archive(::cereal::make_nvp("remark_l3", m.remark_l3));
            archive(::cereal::make_nvp("q_offset", m.q_offset));
            archive(::cereal::make_nvp("fwd_remark_dscp", m_fwd_remark_dscp));
            archive(::cereal::make_nvp("encap", m.encap));
        m.fwd_remark_exp = m_fwd_remark_exp;
        m.remark_l2 = m_remark_l2;
        m.fwd_remark_dscp = m_fwd_remark_dscp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_qos_result_t& m)
{
    serializer_class<npl_egress_qos_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_qos_result_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_qos_result_t& m)
{
    serializer_class<npl_egress_qos_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_qos_result_t&);



template<>
class serializer_class<npl_em_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_destination_t& m) {
            archive(::cereal::make_nvp("em_rpf_src", m.em_rpf_src));
            archive(::cereal::make_nvp("dest", m.dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_destination_t& m) {
            archive(::cereal::make_nvp("em_rpf_src", m.em_rpf_src));
            archive(::cereal::make_nvp("dest", m.dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_destination_t& m)
{
    serializer_class<npl_em_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_em_destination_t& m)
{
    serializer_class<npl_em_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_destination_t&);



template<>
class serializer_class<npl_ene_inject_down_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_inject_down_header_t& m) {
            archive(::cereal::make_nvp("ene_inject_down_payload", m.ene_inject_down_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_inject_down_header_t& m) {
            archive(::cereal::make_nvp("ene_inject_down_payload", m.ene_inject_down_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_inject_down_header_t& m)
{
    serializer_class<npl_ene_inject_down_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_inject_down_header_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_inject_down_header_t& m)
{
    serializer_class<npl_ene_inject_down_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_inject_down_header_t&);



template<>
class serializer_class<npl_ene_punt_sub_code_and_dsp_and_ssp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_sub_code_and_dsp_and_ssp_t& m) {
            archive(::cereal::make_nvp("ene_punt_sub_code", m.ene_punt_sub_code));
            archive(::cereal::make_nvp("ene_punt_dsp_and_ssp", m.ene_punt_dsp_and_ssp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_sub_code_and_dsp_and_ssp_t& m) {
            archive(::cereal::make_nvp("ene_punt_sub_code", m.ene_punt_sub_code));
            archive(::cereal::make_nvp("ene_punt_dsp_and_ssp", m.ene_punt_dsp_and_ssp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_sub_code_and_dsp_and_ssp_t& m)
{
    serializer_class<npl_ene_punt_sub_code_and_dsp_and_ssp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_sub_code_and_dsp_and_ssp_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_sub_code_and_dsp_and_ssp_t& m)
{
    serializer_class<npl_ene_punt_sub_code_and_dsp_and_ssp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_sub_code_and_dsp_and_ssp_t&);



template<>
class serializer_class<npl_ethernet_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ethernet_header_t& m) {
        uint64_t m_ether_type_or_tpid = m.ether_type_or_tpid;
            archive(::cereal::make_nvp("mac_addr", m.mac_addr));
            archive(::cereal::make_nvp("ether_type_or_tpid", m_ether_type_or_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ethernet_header_t& m) {
        uint64_t m_ether_type_or_tpid;
            archive(::cereal::make_nvp("mac_addr", m.mac_addr));
            archive(::cereal::make_nvp("ether_type_or_tpid", m_ether_type_or_tpid));
        m.ether_type_or_tpid = m_ether_type_or_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ethernet_header_t& m)
{
    serializer_class<npl_ethernet_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ethernet_header_t&);

template <class Archive>
void
load(Archive& archive, npl_ethernet_header_t& m)
{
    serializer_class<npl_ethernet_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ethernet_header_t&);



template<>
class serializer_class<npl_fi_core_tcam_assoc_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_core_tcam_assoc_data_t& m) {
        uint64_t m_next_macro = m.next_macro;
        uint64_t m_last_macro = m.last_macro;
        uint64_t m_start_new_header = m.start_new_header;
        uint64_t m_start_new_layer = m.start_new_layer;
        uint64_t m_advance_data = m.advance_data;
        uint64_t m_tcam_mask_alu_header_size = m.tcam_mask_alu_header_size;
        uint64_t m_tcam_mask_hw_logic_advance_data = m.tcam_mask_hw_logic_advance_data;
        uint64_t m_tcam_mask_hw_logic_last_macro = m.tcam_mask_hw_logic_last_macro;
        uint64_t m_tcam_mask_hw_logic_header_size = m.tcam_mask_hw_logic_header_size;
        uint64_t m_header_size = m.header_size;
            archive(::cereal::make_nvp("next_macro", m_next_macro));
            archive(::cereal::make_nvp("last_macro", m_last_macro));
            archive(::cereal::make_nvp("start_new_header", m_start_new_header));
            archive(::cereal::make_nvp("start_new_layer", m_start_new_layer));
            archive(::cereal::make_nvp("advance_data", m_advance_data));
            archive(::cereal::make_nvp("tcam_mask_alu_header_format", m.tcam_mask_alu_header_format));
            archive(::cereal::make_nvp("tcam_mask_alu_header_size", m_tcam_mask_alu_header_size));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_advance_data", m_tcam_mask_hw_logic_advance_data));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_last_macro", m_tcam_mask_hw_logic_last_macro));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_header_format", m.tcam_mask_hw_logic_header_format));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_header_size", m_tcam_mask_hw_logic_header_size));
            archive(::cereal::make_nvp("header_format", m.header_format));
            archive(::cereal::make_nvp("header_size", m_header_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_core_tcam_assoc_data_t& m) {
        uint64_t m_next_macro;
        uint64_t m_last_macro;
        uint64_t m_start_new_header;
        uint64_t m_start_new_layer;
        uint64_t m_advance_data;
        uint64_t m_tcam_mask_alu_header_size;
        uint64_t m_tcam_mask_hw_logic_advance_data;
        uint64_t m_tcam_mask_hw_logic_last_macro;
        uint64_t m_tcam_mask_hw_logic_header_size;
        uint64_t m_header_size;
            archive(::cereal::make_nvp("next_macro", m_next_macro));
            archive(::cereal::make_nvp("last_macro", m_last_macro));
            archive(::cereal::make_nvp("start_new_header", m_start_new_header));
            archive(::cereal::make_nvp("start_new_layer", m_start_new_layer));
            archive(::cereal::make_nvp("advance_data", m_advance_data));
            archive(::cereal::make_nvp("tcam_mask_alu_header_format", m.tcam_mask_alu_header_format));
            archive(::cereal::make_nvp("tcam_mask_alu_header_size", m_tcam_mask_alu_header_size));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_advance_data", m_tcam_mask_hw_logic_advance_data));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_last_macro", m_tcam_mask_hw_logic_last_macro));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_header_format", m.tcam_mask_hw_logic_header_format));
            archive(::cereal::make_nvp("tcam_mask_hw_logic_header_size", m_tcam_mask_hw_logic_header_size));
            archive(::cereal::make_nvp("header_format", m.header_format));
            archive(::cereal::make_nvp("header_size", m_header_size));
        m.next_macro = m_next_macro;
        m.last_macro = m_last_macro;
        m.start_new_header = m_start_new_header;
        m.start_new_layer = m_start_new_layer;
        m.advance_data = m_advance_data;
        m.tcam_mask_alu_header_size = m_tcam_mask_alu_header_size;
        m.tcam_mask_hw_logic_advance_data = m_tcam_mask_hw_logic_advance_data;
        m.tcam_mask_hw_logic_last_macro = m_tcam_mask_hw_logic_last_macro;
        m.tcam_mask_hw_logic_header_size = m_tcam_mask_hw_logic_header_size;
        m.header_size = m_header_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_core_tcam_assoc_data_t& m)
{
    serializer_class<npl_fi_core_tcam_assoc_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_core_tcam_assoc_data_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_core_tcam_assoc_data_t& m)
{
    serializer_class<npl_fi_core_tcam_assoc_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_core_tcam_assoc_data_t&);



template<>
class serializer_class<npl_ingress_lpts_og_app_config_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_lpts_og_app_config_t& m) {
            archive(::cereal::make_nvp("app_data", m.app_data));
            archive(::cereal::make_nvp("src", m.src));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_lpts_og_app_config_t& m) {
            archive(::cereal::make_nvp("app_data", m.app_data));
            archive(::cereal::make_nvp("src", m.src));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_lpts_og_app_config_t& m)
{
    serializer_class<npl_ingress_lpts_og_app_config_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_lpts_og_app_config_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_lpts_og_app_config_t& m)
{
    serializer_class<npl_ingress_lpts_og_app_config_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_lpts_og_app_config_t&);



template<>
class serializer_class<npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t& m) {
            archive(::cereal::make_nvp("q_m_offset_5bits", m.q_m_offset_5bits));
            archive(::cereal::make_nvp("q_m_offset", m.q_m_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t& m) {
            archive(::cereal::make_nvp("q_m_offset_5bits", m.q_m_offset_5bits));
            archive(::cereal::make_nvp("q_m_offset", m.q_m_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t& m)
{
    serializer_class<npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t& m)
{
    serializer_class<npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_qos_acl_result_t_anonymous_union_ctr_offest_union_t&);



template<>
class serializer_class<npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t& m) {
            archive(::cereal::make_nvp("q_m_offset_5bits", m.q_m_offset_5bits));
            archive(::cereal::make_nvp("q_m_offset", m.q_m_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t& m) {
            archive(::cereal::make_nvp("q_m_offset_5bits", m.q_m_offset_5bits));
            archive(::cereal::make_nvp("q_m_offset", m.q_m_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t& m)
{
    serializer_class<npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t& m)
{
    serializer_class<npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_qos_result_t_anonymous_union_ctr_offest_union_t&);



template<>
class serializer_class<npl_initial_pd_nw_rx_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_initial_pd_nw_rx_data_t& m) {
        uint64_t m_initial_is_rcy_if = m.initial_is_rcy_if;
        uint64_t m_pfc_enable = m.pfc_enable;
        uint64_t m_initial_vlan_profile = m.initial_vlan_profile;
            archive(::cereal::make_nvp("init_data", m.init_data));
            archive(::cereal::make_nvp("initial_mapping_type", m.initial_mapping_type));
            archive(::cereal::make_nvp("initial_is_rcy_if", m_initial_is_rcy_if));
            archive(::cereal::make_nvp("pfc_enable", m_pfc_enable));
            archive(::cereal::make_nvp("initial_mac_lp_type", m.initial_mac_lp_type));
            archive(::cereal::make_nvp("initial_lp_type", m.initial_lp_type));
            archive(::cereal::make_nvp("initial_vlan_profile", m_initial_vlan_profile));
            archive(::cereal::make_nvp("mapping_key", m.mapping_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_initial_pd_nw_rx_data_t& m) {
        uint64_t m_initial_is_rcy_if;
        uint64_t m_pfc_enable;
        uint64_t m_initial_vlan_profile;
            archive(::cereal::make_nvp("init_data", m.init_data));
            archive(::cereal::make_nvp("initial_mapping_type", m.initial_mapping_type));
            archive(::cereal::make_nvp("initial_is_rcy_if", m_initial_is_rcy_if));
            archive(::cereal::make_nvp("pfc_enable", m_pfc_enable));
            archive(::cereal::make_nvp("initial_mac_lp_type", m.initial_mac_lp_type));
            archive(::cereal::make_nvp("initial_lp_type", m.initial_lp_type));
            archive(::cereal::make_nvp("initial_vlan_profile", m_initial_vlan_profile));
            archive(::cereal::make_nvp("mapping_key", m.mapping_key));
        m.initial_is_rcy_if = m_initial_is_rcy_if;
        m.pfc_enable = m_pfc_enable;
        m.initial_vlan_profile = m_initial_vlan_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_initial_pd_nw_rx_data_t& m)
{
    serializer_class<npl_initial_pd_nw_rx_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_initial_pd_nw_rx_data_t&);

template <class Archive>
void
load(Archive& archive, npl_initial_pd_nw_rx_data_t& m)
{
    serializer_class<npl_initial_pd_nw_rx_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_initial_pd_nw_rx_data_t&);



template<>
class serializer_class<npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t& m) {
            archive(::cereal::make_nvp("time_and_cntr_stamp_cmd", m.time_and_cntr_stamp_cmd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t& m) {
            archive(::cereal::make_nvp("time_and_cntr_stamp_cmd", m.time_and_cntr_stamp_cmd));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t& m)
{
    serializer_class<npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t& m)
{
    serializer_class<npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t&);



template<>
class serializer_class<npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t& m) {
            archive(::cereal::make_nvp("inject_down", m.inject_down));
            archive(::cereal::make_nvp("ene_inject_down", m.ene_inject_down));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t& m) {
            archive(::cereal::make_nvp("inject_down", m.inject_down));
            archive(::cereal::make_nvp("ene_inject_down", m.ene_inject_down));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t& m)
{
    serializer_class<npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t& m)
{
    serializer_class<npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t&);



template<>
class serializer_class<npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t& m) {
            archive(::cereal::make_nvp("inject_up_qos", m.inject_up_qos));
            archive(::cereal::make_nvp("inject_up_dest", m.inject_up_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t& m) {
            archive(::cereal::make_nvp("inject_up_qos", m.inject_up_qos));
            archive(::cereal::make_nvp("inject_up_dest", m.inject_up_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t& m)
{
    serializer_class<npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t& m)
{
    serializer_class<npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_eth_header_t_anonymous_union_qos_or_dest_t&);



template<>
class serializer_class<npl_ip_encap_data_t_anonymous_union_ip_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_encap_data_t_anonymous_union_ip_t& m) {
            archive(::cereal::make_nvp("v4", m.v4));
            archive(::cereal::make_nvp("v6", m.v6));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_encap_data_t_anonymous_union_ip_t& m) {
            archive(::cereal::make_nvp("v4", m.v4));
            archive(::cereal::make_nvp("v6", m.v6));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_encap_data_t_anonymous_union_ip_t& m)
{
    serializer_class<npl_ip_encap_data_t_anonymous_union_ip_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_encap_data_t_anonymous_union_ip_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_encap_data_t_anonymous_union_ip_t& m)
{
    serializer_class<npl_ip_encap_data_t_anonymous_union_ip_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_encap_data_t_anonymous_union_ip_t&);



template<>
class serializer_class<npl_ive_profile_and_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ive_profile_and_data_t& m) {
        uint64_t m_prf = m.prf;
        uint64_t m_vid1 = m.vid1;
            archive(::cereal::make_nvp("main_type", m.main_type));
            archive(::cereal::make_nvp("secondary_type_or_vid_2", m.secondary_type_or_vid_2));
            archive(::cereal::make_nvp("prf", m_prf));
            archive(::cereal::make_nvp("vid1", m_vid1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ive_profile_and_data_t& m) {
        uint64_t m_prf;
        uint64_t m_vid1;
            archive(::cereal::make_nvp("main_type", m.main_type));
            archive(::cereal::make_nvp("secondary_type_or_vid_2", m.secondary_type_or_vid_2));
            archive(::cereal::make_nvp("prf", m_prf));
            archive(::cereal::make_nvp("vid1", m_vid1));
        m.prf = m_prf;
        m.vid1 = m_vid1;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ive_profile_and_data_t& m)
{
    serializer_class<npl_ive_profile_and_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ive_profile_and_data_t&);

template <class Archive>
void
load(Archive& archive, npl_ive_profile_and_data_t& m)
{
    serializer_class<npl_ive_profile_and_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ive_profile_and_data_t&);



template<>
class serializer_class<npl_l2_relay_id_or_l3_attr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_relay_id_or_l3_attr_t& m) {
        uint64_t m_l2_vpn_pwe_id = m.l2_vpn_pwe_id;
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
            archive(::cereal::make_nvp("l2_vpn_pwe_id", m_l2_vpn_pwe_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_relay_id_or_l3_attr_t& m) {
        uint64_t m_l2_vpn_pwe_id;
            archive(::cereal::make_nvp("relay_id", m.relay_id));
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
            archive(::cereal::make_nvp("l2_vpn_pwe_id", m_l2_vpn_pwe_id));
        m.l2_vpn_pwe_id = m_l2_vpn_pwe_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_relay_id_or_l3_attr_t& m)
{
    serializer_class<npl_l2_relay_id_or_l3_attr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_relay_id_or_l3_attr_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_relay_id_or_l3_attr_t& m)
{
    serializer_class<npl_l2_relay_id_or_l3_attr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_relay_id_or_l3_attr_t&);



template<>
class serializer_class<npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t& m) {
            archive(::cereal::make_nvp("l3_dlp_encap", m.l3_dlp_encap));
            archive(::cereal::make_nvp("ldp_over_te_tunnel_data", m.ldp_over_te_tunnel_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t& m) {
            archive(::cereal::make_nvp("l3_dlp_encap", m.l3_dlp_encap));
            archive(::cereal::make_nvp("ldp_over_te_tunnel_data", m.ldp_over_te_tunnel_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t& m)
{
    serializer_class<npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t& m)
{
    serializer_class<npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_attributes_t_anonymous_union_l3_dlp_encap_or_te_labels_t&);



template<>
class serializer_class<npl_l3_dlp_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_id_t& m) {
            archive(::cereal::make_nvp("msbs", m.msbs));
            archive(::cereal::make_nvp("lsbs", m.lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_id_t& m) {
            archive(::cereal::make_nvp("msbs", m.msbs));
            archive(::cereal::make_nvp("lsbs", m.lsbs));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_id_t& m)
{
    serializer_class<npl_l3_dlp_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_id_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_id_t& m)
{
    serializer_class<npl_l3_dlp_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_id_t&);



template<>
class serializer_class<npl_l3_dlp_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_info_t& m) {
            archive(::cereal::make_nvp("l3_ecn_ctrl", m.l3_ecn_ctrl));
            archive(::cereal::make_nvp("dlp_attributes", m.dlp_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_info_t& m) {
            archive(::cereal::make_nvp("l3_ecn_ctrl", m.l3_ecn_ctrl));
            archive(::cereal::make_nvp("dlp_attributes", m.dlp_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_info_t& m)
{
    serializer_class<npl_l3_dlp_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_info_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_info_t& m)
{
    serializer_class<npl_l3_dlp_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_info_t&);



template<>
class serializer_class<npl_l3_dlp_qos_and_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_qos_and_attributes_t& m) {
            archive(::cereal::make_nvp("l3_dlp_info", m.l3_dlp_info));
            archive(::cereal::make_nvp("qos_attributes", m.qos_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_qos_and_attributes_t& m) {
            archive(::cereal::make_nvp("l3_dlp_info", m.l3_dlp_info));
            archive(::cereal::make_nvp("qos_attributes", m.qos_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_qos_and_attributes_t& m)
{
    serializer_class<npl_l3_dlp_qos_and_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_qos_and_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_qos_and_attributes_t& m)
{
    serializer_class<npl_l3_dlp_qos_and_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_qos_and_attributes_t&);



template<>
class serializer_class<npl_l3_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_t& m)
{
    serializer_class<npl_l3_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_t& m)
{
    serializer_class<npl_l3_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_t&);



template<>
class serializer_class<npl_l3_slp_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_slp_id_t& m) {
            archive(::cereal::make_nvp("msbs", m.msbs));
            archive(::cereal::make_nvp("lsbs", m.lsbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_slp_id_t& m) {
            archive(::cereal::make_nvp("msbs", m.msbs));
            archive(::cereal::make_nvp("lsbs", m.lsbs));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_slp_id_t& m)
{
    serializer_class<npl_l3_slp_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_slp_id_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_slp_id_t& m)
{
    serializer_class<npl_l3_slp_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_slp_id_t&);



template<>
class serializer_class<npl_label_or_more_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_label_or_more_t& m) {
        uint64_t m_label = m.label;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("more", m.more));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_label_or_more_t& m) {
        uint64_t m_label;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("more", m.more));
        m.label = m_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_label_or_more_t& m)
{
    serializer_class<npl_label_or_more_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_label_or_more_t&);

template <class Archive>
void
load(Archive& archive, npl_label_or_more_t& m)
{
    serializer_class<npl_label_or_more_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_label_or_more_t&);



template<>
class serializer_class<npl_lpts_tcam_first_result_encap_data_msb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lpts_tcam_first_result_encap_data_msb_t& m) {
            archive(::cereal::make_nvp("encap_punt_code", m.encap_punt_code));
            archive(::cereal::make_nvp("ingress_punt_src", m.ingress_punt_src));
            archive(::cereal::make_nvp("punt_sub_code", m.punt_sub_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lpts_tcam_first_result_encap_data_msb_t& m) {
            archive(::cereal::make_nvp("encap_punt_code", m.encap_punt_code));
            archive(::cereal::make_nvp("ingress_punt_src", m.ingress_punt_src));
            archive(::cereal::make_nvp("punt_sub_code", m.punt_sub_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lpts_tcam_first_result_encap_data_msb_t& m)
{
    serializer_class<npl_lpts_tcam_first_result_encap_data_msb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lpts_tcam_first_result_encap_data_msb_t&);

template <class Archive>
void
load(Archive& archive, npl_lpts_tcam_first_result_encap_data_msb_t& m)
{
    serializer_class<npl_lpts_tcam_first_result_encap_data_msb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lpts_tcam_first_result_encap_data_msb_t&);



template<>
class serializer_class<npl_lsp_labels_opt1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_labels_opt1_t& m) {
            archive(::cereal::make_nvp("labels_0_1", m.labels_0_1));
            archive(::cereal::make_nvp("label_2_or_more", m.label_2_or_more));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_labels_opt1_t& m) {
            archive(::cereal::make_nvp("labels_0_1", m.labels_0_1));
            archive(::cereal::make_nvp("label_2_or_more", m.label_2_or_more));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_labels_opt1_t& m)
{
    serializer_class<npl_lsp_labels_opt1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_labels_opt1_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_labels_opt1_t& m)
{
    serializer_class<npl_lsp_labels_opt1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_labels_opt1_t&);



template<>
class serializer_class<npl_mac_relay_attributes_inf_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_attributes_inf_payload_t& m) {
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
            archive(::cereal::make_nvp("mac_l2_relay_attributes", m.mac_l2_relay_attributes));
            archive(::cereal::make_nvp("l2_relay_id_or_l3_attr_u", m.l2_relay_id_or_l3_attr_u));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_attributes_inf_payload_t& m) {
            archive(::cereal::make_nvp("l3_lp_additional_attributes", m.l3_lp_additional_attributes));
            archive(::cereal::make_nvp("mac_l2_relay_attributes", m.mac_l2_relay_attributes));
            archive(::cereal::make_nvp("l2_relay_id_or_l3_attr_u", m.l2_relay_id_or_l3_attr_u));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_attributes_inf_payload_t& m)
{
    serializer_class<npl_mac_relay_attributes_inf_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_attributes_inf_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_attributes_inf_payload_t& m)
{
    serializer_class<npl_mac_relay_attributes_inf_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_attributes_inf_payload_t&);



template<>
class serializer_class<npl_mac_relay_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_attributes_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("l2_relay_id_or_l3_attr_u", m.l2_relay_id_or_l3_attr_u));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_attributes_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("l2_relay_id_or_l3_attr_u", m.l2_relay_id_or_l3_attr_u));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_attributes_t& m)
{
    serializer_class<npl_mac_relay_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_attributes_t& m)
{
    serializer_class<npl_mac_relay_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_attributes_t&);



template<>
class serializer_class<npl_mc_em_db_result_tx_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_result_tx_t& m) {
        uint64_t m_format = m.format;
            archive(::cereal::make_nvp("format_0_or_1", m.format_0_or_1));
            archive(::cereal::make_nvp("format", m_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_result_tx_t& m) {
        uint64_t m_format;
            archive(::cereal::make_nvp("format_0_or_1", m.format_0_or_1));
            archive(::cereal::make_nvp("format", m_format));
        m.format = m_format;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_result_tx_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_result_tx_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_result_tx_t& m)
{
    serializer_class<npl_mc_em_db_result_tx_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_result_tx_t&);



template<>
class serializer_class<npl_mmm_tm_header_padded_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mmm_tm_header_padded_t& m) {
            archive(::cereal::make_nvp("mmm_tm_header", m.mmm_tm_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mmm_tm_header_padded_t& m) {
            archive(::cereal::make_nvp("mmm_tm_header", m.mmm_tm_header));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mmm_tm_header_padded_t& m)
{
    serializer_class<npl_mmm_tm_header_padded_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mmm_tm_header_padded_t&);

template <class Archive>
void
load(Archive& archive, npl_mmm_tm_header_padded_t& m)
{
    serializer_class<npl_mmm_tm_header_padded_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mmm_tm_header_padded_t&);



template<>
class serializer_class<npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t& m) {
            archive(::cereal::make_nvp("mldp_info", m.mldp_info));
            archive(::cereal::make_nvp("vpn_info", m.vpn_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t& m) {
            archive(::cereal::make_nvp("mldp_info", m.mldp_info));
            archive(::cereal::make_nvp("vpn_info", m.vpn_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t& m)
{
    serializer_class<npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t& m)
{
    serializer_class<npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_l3vpn_t_anonymous_union_vpn_mldp_info_t&);



template<>
class serializer_class<npl_my_ipv4_table_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_ipv4_table_payload_t& m) {
            archive(::cereal::make_nvp("ip_termination_type", m.ip_termination_type));
            archive(::cereal::make_nvp("ip_tunnel_termination_attr_or_slp", m.ip_tunnel_termination_attr_or_slp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_ipv4_table_payload_t& m) {
            archive(::cereal::make_nvp("ip_termination_type", m.ip_termination_type));
            archive(::cereal::make_nvp("ip_tunnel_termination_attr_or_slp", m.ip_tunnel_termination_attr_or_slp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_ipv4_table_payload_t& m)
{
    serializer_class<npl_my_ipv4_table_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_ipv4_table_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_my_ipv4_table_payload_t& m)
{
    serializer_class<npl_my_ipv4_table_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_ipv4_table_payload_t&);



template<>
class serializer_class<npl_nh_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nh_payload_t& m) {
        uint64_t m_eve_vid1 = m.eve_vid1;
        uint64_t m_l2_port = m.l2_port;
        uint64_t m_l2_flood = m.l2_flood;
            archive(::cereal::make_nvp("eve_vid1", m_eve_vid1));
            archive(::cereal::make_nvp("l2_port", m_l2_port));
            archive(::cereal::make_nvp("l2_flood", m_l2_flood));
            archive(::cereal::make_nvp("l3_sa_vlan_or_l2_dlp_attr", m.l3_sa_vlan_or_l2_dlp_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nh_payload_t& m) {
        uint64_t m_eve_vid1;
        uint64_t m_l2_port;
        uint64_t m_l2_flood;
            archive(::cereal::make_nvp("eve_vid1", m_eve_vid1));
            archive(::cereal::make_nvp("l2_port", m_l2_port));
            archive(::cereal::make_nvp("l2_flood", m_l2_flood));
            archive(::cereal::make_nvp("l3_sa_vlan_or_l2_dlp_attr", m.l3_sa_vlan_or_l2_dlp_attr));
        m.eve_vid1 = m_eve_vid1;
        m.l2_port = m_l2_port;
        m.l2_flood = m_l2_flood;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nh_payload_t& m)
{
    serializer_class<npl_nh_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nh_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_nh_payload_t& m)
{
    serializer_class<npl_nh_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nh_payload_t&);



template<>
class serializer_class<npl_npu_encap_header_l3_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_encap_header_l3_dlp_t& m) {
            archive(::cereal::make_nvp("l3_dlp_id", m.l3_dlp_id));
            archive(::cereal::make_nvp("properties", m.properties));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_encap_header_l3_dlp_t& m) {
            archive(::cereal::make_nvp("l3_dlp_id", m.l3_dlp_id));
            archive(::cereal::make_nvp("properties", m.properties));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_encap_header_l3_dlp_t& m)
{
    serializer_class<npl_npu_encap_header_l3_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_encap_header_l3_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_encap_header_l3_dlp_t& m)
{
    serializer_class<npl_npu_encap_header_l3_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_encap_header_l3_dlp_t&);



template<>
class serializer_class<npl_npu_ip_collapsed_mc_encap_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_ip_collapsed_mc_encap_header_t& m) {
            archive(::cereal::make_nvp("collapsed_mc_encap_type", m.collapsed_mc_encap_type));
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("punt", m.punt));
            archive(::cereal::make_nvp("resolve_local_mcid", m.resolve_local_mcid));
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_ip_collapsed_mc_encap_header_t& m) {
            archive(::cereal::make_nvp("collapsed_mc_encap_type", m.collapsed_mc_encap_type));
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("punt", m.punt));
            archive(::cereal::make_nvp("resolve_local_mcid", m.resolve_local_mcid));
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_ip_collapsed_mc_encap_header_t& m)
{
    serializer_class<npl_npu_ip_collapsed_mc_encap_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_ip_collapsed_mc_encap_header_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_ip_collapsed_mc_encap_header_t& m)
{
    serializer_class<npl_npu_ip_collapsed_mc_encap_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_ip_collapsed_mc_encap_header_t&);



template<>
class serializer_class<npl_npu_l3_common_dlp_nh_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l3_common_dlp_nh_encap_t& m) {
        uint64_t m_nh = m.nh;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("nh", m_nh));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l3_common_dlp_nh_encap_t& m) {
        uint64_t m_nh;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("nh", m_nh));
        m.nh = m_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l3_common_dlp_nh_encap_t& m)
{
    serializer_class<npl_npu_l3_common_dlp_nh_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l3_common_dlp_nh_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l3_common_dlp_nh_encap_t& m)
{
    serializer_class<npl_npu_l3_common_dlp_nh_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l3_common_dlp_nh_encap_t&);



template<>
class serializer_class<npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t& m) {
            archive(::cereal::make_nvp("npu_l3_common_dlp_nh_encap", m.npu_l3_common_dlp_nh_encap));
            archive(::cereal::make_nvp("npu_l3_mc_accounting_encap_data", m.npu_l3_mc_accounting_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t& m) {
            archive(::cereal::make_nvp("npu_l3_common_dlp_nh_encap", m.npu_l3_common_dlp_nh_encap));
            archive(::cereal::make_nvp("npu_l3_mc_accounting_encap_data", m.npu_l3_mc_accounting_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t& m)
{
    serializer_class<npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t& m)
{
    serializer_class<npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l3_common_encap_header_t_anonymous_union_l3_dlp_nh_encap_t&);



template<>
class serializer_class<npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t& m) {
        uint64_t m_gre_tunnel_dlp = m.gre_tunnel_dlp;
            archive(::cereal::make_nvp("tunnel_headend", m.tunnel_headend));
            archive(::cereal::make_nvp("lsr", m.lsr));
            archive(::cereal::make_nvp("vxlan", m.vxlan));
            archive(::cereal::make_nvp("gre_tunnel_dlp", m_gre_tunnel_dlp));
            archive(::cereal::make_nvp("npu_pif_ifg", m.npu_pif_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t& m) {
        uint64_t m_gre_tunnel_dlp;
            archive(::cereal::make_nvp("tunnel_headend", m.tunnel_headend));
            archive(::cereal::make_nvp("lsr", m.lsr));
            archive(::cereal::make_nvp("vxlan", m.vxlan));
            archive(::cereal::make_nvp("gre_tunnel_dlp", m_gre_tunnel_dlp));
            archive(::cereal::make_nvp("npu_pif_ifg", m.npu_pif_ifg));
        m.gre_tunnel_dlp = m_gre_tunnel_dlp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t& m)
{
    serializer_class<npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t& m)
{
    serializer_class<npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l3_encap_header_t_anonymous_union_encap_ext_t&);



template<>
class serializer_class<npl_og_em_lpm_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_em_lpm_result_t& m) {
        uint64_t m_no_hbm_access = m.no_hbm_access;
        uint64_t m_is_default_unused = m.is_default_unused;
            archive(::cereal::make_nvp("lpm_code_or_dest", m.lpm_code_or_dest));
            archive(::cereal::make_nvp("result_type", m.result_type));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_em_lpm_result_t& m) {
        uint64_t m_no_hbm_access;
        uint64_t m_is_default_unused;
            archive(::cereal::make_nvp("lpm_code_or_dest", m.lpm_code_or_dest));
            archive(::cereal::make_nvp("result_type", m.result_type));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
        m.no_hbm_access = m_no_hbm_access;
        m.is_default_unused = m_is_default_unused;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_em_lpm_result_t& m)
{
    serializer_class<npl_og_em_lpm_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_em_lpm_result_t&);

template <class Archive>
void
load(Archive& archive, npl_og_em_lpm_result_t& m)
{
    serializer_class<npl_og_em_lpm_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_em_lpm_result_t&);



template<>
class serializer_class<npl_og_em_result_t_anonymous_union_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_em_result_t_anonymous_union_result_t& m) {
            archive(::cereal::make_nvp("lpm_code_or_dest", m.lpm_code_or_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_em_result_t_anonymous_union_result_t& m) {
            archive(::cereal::make_nvp("lpm_code_or_dest", m.lpm_code_or_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_em_result_t_anonymous_union_result_t& m)
{
    serializer_class<npl_og_em_result_t_anonymous_union_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_em_result_t_anonymous_union_result_t&);

template <class Archive>
void
load(Archive& archive, npl_og_em_result_t_anonymous_union_result_t& m)
{
    serializer_class<npl_og_em_result_t_anonymous_union_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_em_result_t_anonymous_union_result_t&);



template<>
class serializer_class<npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t& m) {
            archive(::cereal::make_nvp("init_fields", m.init_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t& m) {
            archive(::cereal::make_nvp("init_fields", m.init_fields));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t& m)
{
    serializer_class<npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t&);

template <class Archive>
void
load(Archive& archive, npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t& m)
{
    serializer_class<npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t&);



template<>
class serializer_class<npl_punt_if_sa_or_npu_host_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_if_sa_or_npu_host_data_t& m) {
            archive(::cereal::make_nvp("punt_if_sa", m.punt_if_sa));
            archive(::cereal::make_nvp("punt_npu_host_data", m.punt_npu_host_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_if_sa_or_npu_host_data_t& m) {
            archive(::cereal::make_nvp("punt_if_sa", m.punt_if_sa));
            archive(::cereal::make_nvp("punt_npu_host_data", m.punt_npu_host_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_if_sa_or_npu_host_data_t& m)
{
    serializer_class<npl_punt_if_sa_or_npu_host_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_if_sa_or_npu_host_data_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_if_sa_or_npu_host_data_t& m)
{
    serializer_class<npl_punt_if_sa_or_npu_host_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_if_sa_or_npu_host_data_t&);



template<>
class serializer_class<npl_punt_lsb_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_lsb_encap_t& m) {
            archive(::cereal::make_nvp("packet_fwd_header_type", m.packet_fwd_header_type));
            archive(::cereal::make_nvp("punt_shared_lsb_encap", m.punt_shared_lsb_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_lsb_encap_t& m) {
            archive(::cereal::make_nvp("packet_fwd_header_type", m.packet_fwd_header_type));
            archive(::cereal::make_nvp("punt_shared_lsb_encap", m.punt_shared_lsb_encap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_lsb_encap_t& m)
{
    serializer_class<npl_punt_lsb_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_lsb_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_lsb_encap_t& m)
{
    serializer_class<npl_punt_lsb_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_lsb_encap_t&);



template<>
class serializer_class<npl_punt_padding_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_padding_id_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_padding_id_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_padding_id_t& m)
{
    serializer_class<npl_punt_padding_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_padding_id_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_padding_id_t& m)
{
    serializer_class<npl_punt_padding_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_padding_id_t&);



template<>
class serializer_class<npl_pwe_dlp_specific_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_dlp_specific_t& m) {
        uint64_t m_pwe_label = m.pwe_label;
        uint64_t m_lp_set = m.lp_set;
        uint64_t m_pwe_fat = m.pwe_fat;
        uint64_t m_pwe_cw = m.pwe_cw;
            archive(::cereal::make_nvp("eve", m.eve));
            archive(::cereal::make_nvp("pwe_label", m_pwe_label));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("pwe_fat", m_pwe_fat));
            archive(::cereal::make_nvp("pwe_cw", m_pwe_cw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_dlp_specific_t& m) {
        uint64_t m_pwe_label;
        uint64_t m_lp_set;
        uint64_t m_pwe_fat;
        uint64_t m_pwe_cw;
            archive(::cereal::make_nvp("eve", m.eve));
            archive(::cereal::make_nvp("pwe_label", m_pwe_label));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("pwe_fat", m_pwe_fat));
            archive(::cereal::make_nvp("pwe_cw", m_pwe_cw));
        m.pwe_label = m_pwe_label;
        m.lp_set = m_lp_set;
        m.pwe_fat = m_pwe_fat;
        m.pwe_cw = m_pwe_cw;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_dlp_specific_t& m)
{
    serializer_class<npl_pwe_dlp_specific_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_dlp_specific_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_dlp_specific_t& m)
{
    serializer_class<npl_pwe_dlp_specific_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_dlp_specific_t&);



template<>
class serializer_class<npl_qos_mapping_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_qos_mapping_key_t& m) {
            archive(::cereal::make_nvp("key_union", m.key_union));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_qos_mapping_key_t& m) {
            archive(::cereal::make_nvp("key_union", m.key_union));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_qos_mapping_key_t& m)
{
    serializer_class<npl_qos_mapping_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_qos_mapping_key_t&);

template <class Archive>
void
load(Archive& archive, npl_qos_mapping_key_t& m)
{
    serializer_class<npl_qos_mapping_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_qos_mapping_key_t&);



template<>
class serializer_class<npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t& m) {
        uint64_t m_rpf_id = m.rpf_id;
            archive(::cereal::make_nvp("rpf_id", m_rpf_id));
            archive(::cereal::make_nvp("lp", m.lp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t& m) {
        uint64_t m_rpf_id;
            archive(::cereal::make_nvp("rpf_id", m_rpf_id));
            archive(::cereal::make_nvp("lp", m.lp));
        m.rpf_id = m_rpf_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t& m)
{
    serializer_class<npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t& m)
{
    serializer_class<npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_compressed_destination_t_anonymous_union_rpf_id_or_lp_id_t&);



template<>
class serializer_class<npl_rtf_payload_t_anonymous_union_rtf_result_profile_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_payload_t_anonymous_union_rtf_result_profile_t& m) {
            archive(::cereal::make_nvp("rtf_result_profile_0", m.rtf_result_profile_0));
            archive(::cereal::make_nvp("rtf_result_profile_1", m.rtf_result_profile_1));
            archive(::cereal::make_nvp("rtf_result_profile_2", m.rtf_result_profile_2));
            archive(::cereal::make_nvp("rtf_result_profile_3", m.rtf_result_profile_3));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_payload_t_anonymous_union_rtf_result_profile_t& m) {
            archive(::cereal::make_nvp("rtf_result_profile_0", m.rtf_result_profile_0));
            archive(::cereal::make_nvp("rtf_result_profile_1", m.rtf_result_profile_1));
            archive(::cereal::make_nvp("rtf_result_profile_2", m.rtf_result_profile_2));
            archive(::cereal::make_nvp("rtf_result_profile_3", m.rtf_result_profile_3));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_payload_t_anonymous_union_rtf_result_profile_t& m)
{
    serializer_class<npl_rtf_payload_t_anonymous_union_rtf_result_profile_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_payload_t_anonymous_union_rtf_result_profile_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_payload_t_anonymous_union_rtf_result_profile_t& m)
{
    serializer_class<npl_rtf_payload_t_anonymous_union_rtf_result_profile_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_payload_t_anonymous_union_rtf_result_profile_t&);



template<>
class serializer_class<npl_single_label_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_single_label_encap_data_t& m) {
            archive(::cereal::make_nvp("udat", m.udat));
            archive(::cereal::make_nvp("v6_label_encap", m.v6_label_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_single_label_encap_data_t& m) {
            archive(::cereal::make_nvp("udat", m.udat));
            archive(::cereal::make_nvp("v6_label_encap", m.v6_label_encap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_single_label_encap_data_t& m)
{
    serializer_class<npl_single_label_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_single_label_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_single_label_encap_data_t& m)
{
    serializer_class<npl_single_label_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_single_label_encap_data_t&);



template<>
class serializer_class<npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t& m) {
        uint64_t m_snoop_code = m.snoop_code;
            archive(::cereal::make_nvp("snoop_code", m_snoop_code));
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t& m) {
        uint64_t m_snoop_code;
            archive(::cereal::make_nvp("snoop_code", m_snoop_code));
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
        m.snoop_code = m_snoop_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t& m)
{
    serializer_class<npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t& m)
{
    serializer_class<npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_or_rcy_data_t_anonymous_union_snoop_or_rcy_data_t&);



template<>
class serializer_class<npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t& m) {
        uint64_t m_vid2 = m.vid2;
            archive(::cereal::make_nvp("svi_eve_sub_type_plus_pad_plus_prf", m.svi_eve_sub_type_plus_pad_plus_prf));
            archive(::cereal::make_nvp("svi_eve_vid2_plus_prf_t", m.svi_eve_vid2_plus_prf_t));
            archive(::cereal::make_nvp("vid2", m_vid2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t& m) {
        uint64_t m_vid2;
            archive(::cereal::make_nvp("svi_eve_sub_type_plus_pad_plus_prf", m.svi_eve_sub_type_plus_pad_plus_prf));
            archive(::cereal::make_nvp("svi_eve_vid2_plus_prf_t", m.svi_eve_vid2_plus_prf_t));
            archive(::cereal::make_nvp("vid2", m_vid2));
        m.vid2 = m_vid2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t&);

template <class Archive>
void
load(Archive& archive, npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t& m)
{
    serializer_class<npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svi_eve_profile_and_data_t_anonymous_union_sub_type_or_vid_2_plus_prf_t&);



template<>
class serializer_class<npl_term_l2_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_l2_lp_attributes_t& m) {
        uint64_t m_enable_monitor = m.enable_monitor;
        uint64_t m_mip_exists = m.mip_exists;
        uint64_t m_mep_exists = m.mep_exists;
        uint64_t m_max_mep_level = m.max_mep_level;
            archive(::cereal::make_nvp("enable_monitor", m_enable_monitor));
            archive(::cereal::make_nvp("mip_exists", m_mip_exists));
            archive(::cereal::make_nvp("mep_exists", m_mep_exists));
            archive(::cereal::make_nvp("ive_profile_and_data", m.ive_profile_and_data));
            archive(::cereal::make_nvp("max_mep_level", m_max_mep_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_l2_lp_attributes_t& m) {
        uint64_t m_enable_monitor;
        uint64_t m_mip_exists;
        uint64_t m_mep_exists;
        uint64_t m_max_mep_level;
            archive(::cereal::make_nvp("enable_monitor", m_enable_monitor));
            archive(::cereal::make_nvp("mip_exists", m_mip_exists));
            archive(::cereal::make_nvp("mep_exists", m_mep_exists));
            archive(::cereal::make_nvp("ive_profile_and_data", m.ive_profile_and_data));
            archive(::cereal::make_nvp("max_mep_level", m_max_mep_level));
        m.enable_monitor = m_enable_monitor;
        m.mip_exists = m_mip_exists;
        m.mep_exists = m_mep_exists;
        m.max_mep_level = m_max_mep_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_l2_lp_attributes_t& m)
{
    serializer_class<npl_term_l2_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_l2_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_term_l2_lp_attributes_t& m)
{
    serializer_class<npl_term_l2_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_l2_lp_attributes_t&);



template<>
class serializer_class<npl_tm_headers_template_t_anonymous_union_u_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tm_headers_template_t_anonymous_union_u_t& m) {
            archive(::cereal::make_nvp("unicast_flb", m.unicast_flb));
            archive(::cereal::make_nvp("unicast_plb", m.unicast_plb));
            archive(::cereal::make_nvp("mmm", m.mmm));
            archive(::cereal::make_nvp("mum", m.mum));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tm_headers_template_t_anonymous_union_u_t& m) {
            archive(::cereal::make_nvp("unicast_flb", m.unicast_flb));
            archive(::cereal::make_nvp("unicast_plb", m.unicast_plb));
            archive(::cereal::make_nvp("mmm", m.mmm));
            archive(::cereal::make_nvp("mum", m.mum));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tm_headers_template_t_anonymous_union_u_t& m)
{
    serializer_class<npl_tm_headers_template_t_anonymous_union_u_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tm_headers_template_t_anonymous_union_u_t&);

template <class Archive>
void
load(Archive& archive, npl_tm_headers_template_t_anonymous_union_u_t& m)
{
    serializer_class<npl_tm_headers_template_t_anonymous_union_u_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tm_headers_template_t_anonymous_union_u_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t& m) {
            archive(::cereal::make_nvp("congestion_mark", m.congestion_mark));
            archive(::cereal::make_nvp("evict_to_dram", m.evict_to_dram));
            archive(::cereal::make_nvp("drop_y", m.drop_y));
            archive(::cereal::make_nvp("drop_g", m.drop_g));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t& m) {
            archive(::cereal::make_nvp("congestion_mark", m.congestion_mark));
            archive(::cereal::make_nvp("evict_to_dram", m.evict_to_dram));
            archive(::cereal::make_nvp("drop_y", m.drop_y));
            archive(::cereal::make_nvp("drop_g", m.drop_g));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t&);



template<>
class serializer_class<npl_vpn_label_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vpn_label_encap_data_t& m) {
            archive(::cereal::make_nvp("single_label_encap_data", m.single_label_encap_data));
            archive(::cereal::make_nvp("l2vpn_label_encap_data", m.l2vpn_label_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vpn_label_encap_data_t& m) {
            archive(::cereal::make_nvp("single_label_encap_data", m.single_label_encap_data));
            archive(::cereal::make_nvp("l2vpn_label_encap_data", m.l2vpn_label_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vpn_label_encap_data_t& m)
{
    serializer_class<npl_vpn_label_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vpn_label_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_vpn_label_encap_data_t& m)
{
    serializer_class<npl_vpn_label_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vpn_label_encap_data_t&);



template<>
class serializer_class<npl_bfd_aux_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_aux_payload_t& m) {
            archive(::cereal::make_nvp("transmit", m.transmit));
            archive(::cereal::make_nvp("shared", m.shared));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_aux_payload_t& m) {
            archive(::cereal::make_nvp("transmit", m.transmit));
            archive(::cereal::make_nvp("shared", m.shared));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_aux_payload_t& m)
{
    serializer_class<npl_bfd_aux_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_aux_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_aux_payload_t& m)
{
    serializer_class<npl_bfd_aux_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_aux_payload_t&);



template<>
class serializer_class<npl_bfd_em_compound_results_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_em_compound_results_t& m) {
            archive(::cereal::make_nvp("bfd_payload", m.bfd_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_em_compound_results_t& m) {
            archive(::cereal::make_nvp("bfd_payload", m.bfd_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_em_compound_results_t& m)
{
    serializer_class<npl_bfd_em_compound_results_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_em_compound_results_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_em_compound_results_t& m)
{
    serializer_class<npl_bfd_em_compound_results_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_em_compound_results_t&);



template<>
class serializer_class<npl_ene_punt_data_on_npuh_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_data_on_npuh_t& m) {
        uint64_t m_ene_current_nw_hdr_offset = m.ene_current_nw_hdr_offset;
            archive(::cereal::make_nvp("ene_punt_fwd_header_type", m.ene_punt_fwd_header_type));
            archive(::cereal::make_nvp("ene_punt_src", m.ene_punt_src));
            archive(::cereal::make_nvp("ene_current_nw_hdr_offset", m_ene_current_nw_hdr_offset));
            archive(::cereal::make_nvp("ene_punt_sub_code_and_padding_dsp_and_ssp", m.ene_punt_sub_code_and_padding_dsp_and_ssp));
            archive(::cereal::make_nvp("ene_punt_next_header_type", m.ene_punt_next_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_data_on_npuh_t& m) {
        uint64_t m_ene_current_nw_hdr_offset;
            archive(::cereal::make_nvp("ene_punt_fwd_header_type", m.ene_punt_fwd_header_type));
            archive(::cereal::make_nvp("ene_punt_src", m.ene_punt_src));
            archive(::cereal::make_nvp("ene_current_nw_hdr_offset", m_ene_current_nw_hdr_offset));
            archive(::cereal::make_nvp("ene_punt_sub_code_and_padding_dsp_and_ssp", m.ene_punt_sub_code_and_padding_dsp_and_ssp));
            archive(::cereal::make_nvp("ene_punt_next_header_type", m.ene_punt_next_header_type));
        m.ene_current_nw_hdr_offset = m_ene_current_nw_hdr_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_data_on_npuh_t& m)
{
    serializer_class<npl_ene_punt_data_on_npuh_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_data_on_npuh_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_data_on_npuh_t& m)
{
    serializer_class<npl_ene_punt_data_on_npuh_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_data_on_npuh_t&);



template<>
class serializer_class<npl_host_nh_mac_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_host_nh_mac_t& m) {
        uint64_t m_host_mac = m.host_mac;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("host_mac", m_host_mac));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_host_nh_mac_t& m) {
        uint64_t m_host_mac;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("host_mac", m_host_mac));
        m.host_mac = m_host_mac;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_host_nh_mac_t& m)
{
    serializer_class<npl_host_nh_mac_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_host_nh_mac_t&);

template <class Archive>
void
load(Archive& archive, npl_host_nh_mac_t& m)
{
    serializer_class<npl_host_nh_mac_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_host_nh_mac_t&);



template<>
class serializer_class<npl_host_nh_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_host_nh_ptr_t& m) {
        uint64_t m_host_ptr = m.host_ptr;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("host_ptr", m_host_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_host_nh_ptr_t& m) {
        uint64_t m_host_ptr;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("host_ptr", m_host_ptr));
        m.host_ptr = m_host_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_host_nh_ptr_t& m)
{
    serializer_class<npl_host_nh_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_host_nh_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_host_nh_ptr_t& m)
{
    serializer_class<npl_host_nh_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_host_nh_ptr_t&);



template<>
class serializer_class<npl_ingress_punt_mc_expand_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_punt_mc_expand_encap_t& m) {
        uint64_t m_current_nw_hdr_offset = m.current_nw_hdr_offset;
            archive(::cereal::make_nvp("npu_mirror_or_redirect_encapsulation_type", m.npu_mirror_or_redirect_encapsulation_type));
            archive(::cereal::make_nvp("lpts_tcam_first_result_encap_data_msb", m.lpts_tcam_first_result_encap_data_msb));
            archive(::cereal::make_nvp("current_nw_hdr_offset", m_current_nw_hdr_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_punt_mc_expand_encap_t& m) {
        uint64_t m_current_nw_hdr_offset;
            archive(::cereal::make_nvp("npu_mirror_or_redirect_encapsulation_type", m.npu_mirror_or_redirect_encapsulation_type));
            archive(::cereal::make_nvp("lpts_tcam_first_result_encap_data_msb", m.lpts_tcam_first_result_encap_data_msb));
            archive(::cereal::make_nvp("current_nw_hdr_offset", m_current_nw_hdr_offset));
        m.current_nw_hdr_offset = m_current_nw_hdr_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_punt_mc_expand_encap_t& m)
{
    serializer_class<npl_ingress_punt_mc_expand_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_punt_mc_expand_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_punt_mc_expand_encap_t& m)
{
    serializer_class<npl_ingress_punt_mc_expand_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_punt_mc_expand_encap_t&);



template<>
class serializer_class<npl_ingress_qos_acl_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_qos_acl_result_t& m) {
        uint64_t m_override_phb = m.override_phb;
        uint64_t m_override_qos = m.override_qos;
            archive(::cereal::make_nvp("override_phb", m_override_phb));
            archive(::cereal::make_nvp("override_qos", m_override_qos));
            archive(::cereal::make_nvp("meter", m.meter));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("ctr_offest_union", m.ctr_offest_union));
            archive(::cereal::make_nvp("ingress_qos_remark", m.ingress_qos_remark));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_qos_acl_result_t& m) {
        uint64_t m_override_phb;
        uint64_t m_override_qos;
            archive(::cereal::make_nvp("override_phb", m_override_phb));
            archive(::cereal::make_nvp("override_qos", m_override_qos));
            archive(::cereal::make_nvp("meter", m.meter));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("ctr_offest_union", m.ctr_offest_union));
            archive(::cereal::make_nvp("ingress_qos_remark", m.ingress_qos_remark));
        m.override_phb = m_override_phb;
        m.override_qos = m_override_qos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_qos_acl_result_t& m)
{
    serializer_class<npl_ingress_qos_acl_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_qos_acl_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_qos_acl_result_t& m)
{
    serializer_class<npl_ingress_qos_acl_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_qos_acl_result_t&);



template<>
class serializer_class<npl_ingress_qos_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_qos_result_t& m) {
        uint64_t m_override_qos = m.override_qos;
        uint64_t m_enable_ingress_remark = m.enable_ingress_remark;
        uint64_t m_meter = m.meter;
        uint64_t m_fwd_qos_tag = m.fwd_qos_tag;
            archive(::cereal::make_nvp("override_qos", m_override_qos));
            archive(::cereal::make_nvp("enable_ingress_remark", m_enable_ingress_remark));
            archive(::cereal::make_nvp("ctr_offest_union", m.ctr_offest_union));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("encap_mpls_exp", m.encap_mpls_exp));
            archive(::cereal::make_nvp("fwd_class_qos_group_u", m.fwd_class_qos_group_u));
            archive(::cereal::make_nvp("meter", m_meter));
            archive(::cereal::make_nvp("fwd_qos_tag", m_fwd_qos_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_qos_result_t& m) {
        uint64_t m_override_qos;
        uint64_t m_enable_ingress_remark;
        uint64_t m_meter;
        uint64_t m_fwd_qos_tag;
            archive(::cereal::make_nvp("override_qos", m_override_qos));
            archive(::cereal::make_nvp("enable_ingress_remark", m_enable_ingress_remark));
            archive(::cereal::make_nvp("ctr_offest_union", m.ctr_offest_union));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("encap_mpls_exp", m.encap_mpls_exp));
            archive(::cereal::make_nvp("fwd_class_qos_group_u", m.fwd_class_qos_group_u));
            archive(::cereal::make_nvp("meter", m_meter));
            archive(::cereal::make_nvp("fwd_qos_tag", m_fwd_qos_tag));
        m.override_qos = m_override_qos;
        m.enable_ingress_remark = m_enable_ingress_remark;
        m.meter = m_meter;
        m.fwd_qos_tag = m_fwd_qos_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_qos_result_t& m)
{
    serializer_class<npl_ingress_qos_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_qos_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_qos_result_t& m)
{
    serializer_class<npl_ingress_qos_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_qos_result_t&);



template<>
class serializer_class<npl_inject_down_encap_dlp_and_nh_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_encap_dlp_and_nh_t& m) {
        uint64_t m_down_nh = m.down_nh;
            archive(::cereal::make_nvp("down_l3_dlp", m.down_l3_dlp));
            archive(::cereal::make_nvp("down_nh", m_down_nh));
            archive(::cereal::make_nvp("down_pcp_dei", m.down_pcp_dei));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_encap_dlp_and_nh_t& m) {
        uint64_t m_down_nh;
            archive(::cereal::make_nvp("down_l3_dlp", m.down_l3_dlp));
            archive(::cereal::make_nvp("down_nh", m_down_nh));
            archive(::cereal::make_nvp("down_pcp_dei", m.down_pcp_dei));
        m.down_nh = m_down_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_encap_dlp_and_nh_t& m)
{
    serializer_class<npl_inject_down_encap_dlp_and_nh_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_encap_dlp_and_nh_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_encap_dlp_and_nh_t& m)
{
    serializer_class<npl_inject_down_encap_dlp_and_nh_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_encap_dlp_and_nh_t&);



template<>
class serializer_class<npl_inject_down_encap_ptr_or_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_encap_ptr_or_dlp_t& m) {
        uint64_t m_inject_down_encap_ptr = m.inject_down_encap_ptr;
            archive(::cereal::make_nvp("inject_down_encap_ptr", m_inject_down_encap_ptr));
            archive(::cereal::make_nvp("inject_down_encap_nh", m.inject_down_encap_nh));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_encap_ptr_or_dlp_t& m) {
        uint64_t m_inject_down_encap_ptr;
            archive(::cereal::make_nvp("inject_down_encap_ptr", m_inject_down_encap_ptr));
            archive(::cereal::make_nvp("inject_down_encap_nh", m.inject_down_encap_nh));
        m.inject_down_encap_ptr = m_inject_down_encap_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_encap_ptr_or_dlp_t& m)
{
    serializer_class<npl_inject_down_encap_ptr_or_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_encap_ptr_or_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_encap_ptr_or_dlp_t& m)
{
    serializer_class<npl_inject_down_encap_ptr_or_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_encap_ptr_or_dlp_t&);



template<>
class serializer_class<npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t& m) {
            archive(::cereal::make_nvp("inject_down_encap_ptr_or_dlp", m.inject_down_encap_ptr_or_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t& m) {
            archive(::cereal::make_nvp("inject_down_encap_ptr_or_dlp", m.inject_down_encap_ptr_or_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t& m)
{
    serializer_class<npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t& m)
{
    serializer_class<npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t&);



template<>
class serializer_class<npl_inject_up_eth_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_eth_header_t& m) {
            archive(::cereal::make_nvp("qos_or_dest", m.qos_or_dest));
            archive(::cereal::make_nvp("from_port", m.from_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_eth_header_t& m) {
            archive(::cereal::make_nvp("qos_or_dest", m.qos_or_dest));
            archive(::cereal::make_nvp("from_port", m.from_port));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_eth_header_t& m)
{
    serializer_class<npl_inject_up_eth_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_eth_header_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_eth_header_t& m)
{
    serializer_class<npl_inject_up_eth_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_eth_header_t&);



template<>
class serializer_class<npl_ip_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_encap_data_t& m) {
            archive(::cereal::make_nvp("ip", m.ip));
            archive(::cereal::make_nvp("upper_layer", m.upper_layer));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_encap_data_t& m) {
            archive(::cereal::make_nvp("ip", m.ip));
            archive(::cereal::make_nvp("upper_layer", m.upper_layer));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_encap_data_t& m)
{
    serializer_class<npl_ip_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_encap_data_t& m)
{
    serializer_class<npl_ip_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_encap_data_t&);



template<>
class serializer_class<npl_l2_adj_sid_nhlfe_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_adj_sid_nhlfe_t& m) {
        uint64_t m_prefix = m.prefix;
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("l3_dlp_nh_encap", m.l3_dlp_nh_encap));
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("dsp", m_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_adj_sid_nhlfe_t& m) {
        uint64_t m_prefix;
        uint64_t m_dsp;
            archive(::cereal::make_nvp("l3_dlp_nh_encap", m.l3_dlp_nh_encap));
            archive(::cereal::make_nvp("prefix", m_prefix));
            archive(::cereal::make_nvp("dsp", m_dsp));
        m.prefix = m_prefix;
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_adj_sid_nhlfe_t& m)
{
    serializer_class<npl_l2_adj_sid_nhlfe_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_adj_sid_nhlfe_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_adj_sid_nhlfe_t& m)
{
    serializer_class<npl_l2_adj_sid_nhlfe_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_adj_sid_nhlfe_t&);



template<>
class serializer_class<npl_l2_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lp_attributes_t& m) {
            archive(::cereal::make_nvp("learn_type", m.learn_type));
            archive(::cereal::make_nvp("learn_prob", m.learn_prob));
            archive(::cereal::make_nvp("term", m.term));
            archive(::cereal::make_nvp("shared", m.shared));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lp_attributes_t& m) {
            archive(::cereal::make_nvp("learn_type", m.learn_type));
            archive(::cereal::make_nvp("learn_prob", m.learn_prob));
            archive(::cereal::make_nvp("term", m.term));
            archive(::cereal::make_nvp("shared", m.shared));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lp_attributes_t& m)
{
    serializer_class<npl_l2_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lp_attributes_t& m)
{
    serializer_class<npl_l2_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lp_attributes_t&);



template<>
class serializer_class<npl_l2_pwe_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_pwe_encap_t& m) {
        uint64_t m_nh = m.nh;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("nh", m_nh));
            archive(::cereal::make_nvp("lsp_destination", m.lsp_destination));
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_pwe_encap_t& m) {
        uint64_t m_nh;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("nh", m_nh));
            archive(::cereal::make_nvp("lsp_destination", m.lsp_destination));
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
        m.nh = m_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_pwe_encap_t& m)
{
    serializer_class<npl_l2_pwe_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_pwe_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_pwe_encap_t& m)
{
    serializer_class<npl_l2_pwe_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_pwe_encap_t&);



template<>
class serializer_class<npl_l2_relay_and_l3_lp_attributes_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_relay_and_l3_lp_attributes_payload_t& m) {
            archive(::cereal::make_nvp("relay_att_inf_payload", m.relay_att_inf_payload));
            archive(::cereal::make_nvp("mac_relay_attributes", m.mac_relay_attributes));
            archive(::cereal::make_nvp("relay_att_table_payload", m.relay_att_table_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_relay_and_l3_lp_attributes_payload_t& m) {
            archive(::cereal::make_nvp("relay_att_inf_payload", m.relay_att_inf_payload));
            archive(::cereal::make_nvp("mac_relay_attributes", m.mac_relay_attributes));
            archive(::cereal::make_nvp("relay_att_table_payload", m.relay_att_table_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_relay_and_l3_lp_attributes_payload_t& m)
{
    serializer_class<npl_l2_relay_and_l3_lp_attributes_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_relay_and_l3_lp_attributes_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_relay_and_l3_lp_attributes_payload_t& m)
{
    serializer_class<npl_l2_relay_and_l3_lp_attributes_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_relay_and_l3_lp_attributes_payload_t&);



template<>
class serializer_class<npl_l2_vxlan_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_vxlan_encap_t& m) {
        uint64_t m_nh = m.nh;
        uint64_t m_overlay_nh = m.overlay_nh;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("nh", m_nh));
            archive(::cereal::make_nvp("tunnel_dlp", m.tunnel_dlp));
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_vxlan_encap_t& m) {
        uint64_t m_nh;
        uint64_t m_overlay_nh;
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
            archive(::cereal::make_nvp("nh", m_nh));
            archive(::cereal::make_nvp("tunnel_dlp", m.tunnel_dlp));
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
        m.nh = m_nh;
        m.overlay_nh = m_overlay_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_vxlan_encap_t& m)
{
    serializer_class<npl_l2_vxlan_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_vxlan_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_vxlan_encap_t& m)
{
    serializer_class<npl_l2_vxlan_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_vxlan_encap_t&);



template<>
class serializer_class<npl_l3_dlp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_dlp_attributes_t& m) {
        uint64_t m_svi_dhcp_snooping = m.svi_dhcp_snooping;
        uint64_t m_disabled = m.disabled;
            archive(::cereal::make_nvp("svi_dhcp_snooping", m_svi_dhcp_snooping));
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("l3_dlp_encap_or_te_labels", m.l3_dlp_encap_or_te_labels));
            archive(::cereal::make_nvp("nh_ene_macro_code", m.nh_ene_macro_code));
            archive(::cereal::make_nvp("l3_dlp_qos_and_attributes", m.l3_dlp_qos_and_attributes));
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_dlp_attributes_t& m) {
        uint64_t m_svi_dhcp_snooping;
        uint64_t m_disabled;
            archive(::cereal::make_nvp("svi_dhcp_snooping", m_svi_dhcp_snooping));
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("l3_dlp_encap_or_te_labels", m.l3_dlp_encap_or_te_labels));
            archive(::cereal::make_nvp("nh_ene_macro_code", m.nh_ene_macro_code));
            archive(::cereal::make_nvp("l3_dlp_qos_and_attributes", m.l3_dlp_qos_and_attributes));
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
        m.svi_dhcp_snooping = m_svi_dhcp_snooping;
        m.disabled = m_disabled;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_dlp_attributes_t& m)
{
    serializer_class<npl_l3_dlp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_dlp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_dlp_attributes_t& m)
{
    serializer_class<npl_l3_dlp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_dlp_attributes_t&);



template<>
class serializer_class<npl_l3_global_slp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_global_slp_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_global_slp_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_global_slp_t& m)
{
    serializer_class<npl_l3_global_slp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_global_slp_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_global_slp_t& m)
{
    serializer_class<npl_l3_global_slp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_global_slp_t&);



template<>
class serializer_class<npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t& m) {
            archive(::cereal::make_nvp("opt3", m.opt3));
            archive(::cereal::make_nvp("opt2", m.opt2));
            archive(::cereal::make_nvp("opt1", m.opt1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t& m) {
            archive(::cereal::make_nvp("opt3", m.opt3));
            archive(::cereal::make_nvp("opt2", m.opt2));
            archive(::cereal::make_nvp("opt1", m.opt1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t& m)
{
    serializer_class<npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t& m)
{
    serializer_class<npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t&);



template<>
class serializer_class<npl_mac_qos_macro_pack_table_fields_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_qos_macro_pack_table_fields_t& m) {
        uint64_t m_pd_qos_mapping_7b = m.pd_qos_mapping_7b;
            archive(::cereal::make_nvp("pd_qos_mapping_7b", m_pd_qos_mapping_7b));
            archive(::cereal::make_nvp("l3_qos_mapping_key", m.l3_qos_mapping_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_qos_macro_pack_table_fields_t& m) {
        uint64_t m_pd_qos_mapping_7b;
            archive(::cereal::make_nvp("pd_qos_mapping_7b", m_pd_qos_mapping_7b));
            archive(::cereal::make_nvp("l3_qos_mapping_key", m.l3_qos_mapping_key));
        m.pd_qos_mapping_7b = m_pd_qos_mapping_7b;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_qos_macro_pack_table_fields_t& m)
{
    serializer_class<npl_mac_qos_macro_pack_table_fields_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_qos_macro_pack_table_fields_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_qos_macro_pack_table_fields_t& m)
{
    serializer_class<npl_mac_qos_macro_pack_table_fields_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_qos_macro_pack_table_fields_t&);



template<>
class serializer_class<npl_mc_em_db_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_result_t& m) {
            archive(::cereal::make_nvp("rx", m.rx));
            archive(::cereal::make_nvp("tx", m.tx));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_result_t& m) {
            archive(::cereal::make_nvp("rx", m.rx));
            archive(::cereal::make_nvp("tx", m.tx));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_result_t& m)
{
    serializer_class<npl_mc_em_db_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_result_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_result_t& m)
{
    serializer_class<npl_mc_em_db_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_result_t&);



template<>
class serializer_class<npl_minimal_l3_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_minimal_l3_lp_attributes_t& m) {
        uint64_t m_disable_ipv6_mc = m.disable_ipv6_mc;
        uint64_t m_lp_set = m.lp_set;
        uint64_t m_per_protocol_count = m.per_protocol_count;
        uint64_t m_disable_ipv4_uc = m.disable_ipv4_uc;
        uint64_t m_disable_ipv4_mc = m.disable_ipv4_mc;
        uint64_t m_disable_mpls = m.disable_mpls;
        uint64_t m_disable_ipv6_uc = m.disable_ipv6_uc;
            archive(::cereal::make_nvp("disable_ipv6_mc", m_disable_ipv6_mc));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("ttl_mode", m.ttl_mode));
            archive(::cereal::make_nvp("per_protocol_count", m_per_protocol_count));
            archive(::cereal::make_nvp("disable_ipv4_uc", m_disable_ipv4_uc));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("global_slp_id", m.global_slp_id));
            archive(::cereal::make_nvp("disable_ipv4_mc", m_disable_ipv4_mc));
            archive(::cereal::make_nvp("disable_mpls", m_disable_mpls));
            archive(::cereal::make_nvp("disable_ipv6_uc", m_disable_ipv6_uc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_minimal_l3_lp_attributes_t& m) {
        uint64_t m_disable_ipv6_mc;
        uint64_t m_lp_set;
        uint64_t m_per_protocol_count;
        uint64_t m_disable_ipv4_uc;
        uint64_t m_disable_ipv4_mc;
        uint64_t m_disable_mpls;
        uint64_t m_disable_ipv6_uc;
            archive(::cereal::make_nvp("disable_ipv6_mc", m_disable_ipv6_mc));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("ttl_mode", m.ttl_mode));
            archive(::cereal::make_nvp("per_protocol_count", m_per_protocol_count));
            archive(::cereal::make_nvp("disable_ipv4_uc", m_disable_ipv4_uc));
            archive(::cereal::make_nvp("p_counter", m.p_counter));
            archive(::cereal::make_nvp("global_slp_id", m.global_slp_id));
            archive(::cereal::make_nvp("disable_ipv4_mc", m_disable_ipv4_mc));
            archive(::cereal::make_nvp("disable_mpls", m_disable_mpls));
            archive(::cereal::make_nvp("disable_ipv6_uc", m_disable_ipv6_uc));
        m.disable_ipv6_mc = m_disable_ipv6_mc;
        m.lp_set = m_lp_set;
        m.per_protocol_count = m_per_protocol_count;
        m.disable_ipv4_uc = m_disable_ipv4_uc;
        m.disable_ipv4_mc = m_disable_ipv4_mc;
        m.disable_mpls = m_disable_mpls;
        m.disable_ipv6_uc = m_disable_ipv6_uc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_minimal_l3_lp_attributes_t& m)
{
    serializer_class<npl_minimal_l3_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_minimal_l3_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_minimal_l3_lp_attributes_t& m)
{
    serializer_class<npl_minimal_l3_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_minimal_l3_lp_attributes_t&);



template<>
class serializer_class<npl_mpls_termination_l3vpn_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_l3vpn_t& m) {
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("vpn_mldp_info", m.vpn_mldp_info));
            archive(::cereal::make_nvp("vpn_p_counter", m.vpn_p_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_l3vpn_t& m) {
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("vpn_mldp_info", m.vpn_mldp_info));
            archive(::cereal::make_nvp("vpn_p_counter", m.vpn_p_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_l3vpn_t& m)
{
    serializer_class<npl_mpls_termination_l3vpn_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_l3vpn_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_l3vpn_t& m)
{
    serializer_class<npl_mpls_termination_l3vpn_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_l3vpn_t&);



template<>
class serializer_class<npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t& m) {
            archive(::cereal::make_nvp("l3vpn_info", m.l3vpn_info));
            archive(::cereal::make_nvp("pwe_info", m.pwe_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t& m) {
            archive(::cereal::make_nvp("l3vpn_info", m.l3vpn_info));
            archive(::cereal::make_nvp("pwe_info", m.pwe_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t& m)
{
    serializer_class<npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t& m)
{
    serializer_class<npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t&);



template<>
class serializer_class<npl_nh_and_svi_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nh_and_svi_payload_t& m) {
        uint64_t m_nh_da = m.nh_da;
            archive(::cereal::make_nvp("nh_payload", m.nh_payload));
            archive(::cereal::make_nvp("nh_da", m_nh_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nh_and_svi_payload_t& m) {
        uint64_t m_nh_da;
            archive(::cereal::make_nvp("nh_payload", m.nh_payload));
            archive(::cereal::make_nvp("nh_da", m_nh_da));
        m.nh_da = m_nh_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nh_and_svi_payload_t& m)
{
    serializer_class<npl_nh_and_svi_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nh_and_svi_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_nh_and_svi_payload_t& m)
{
    serializer_class<npl_nh_and_svi_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nh_and_svi_payload_t&);



template<>
class serializer_class<npl_nhlfe_t_anonymous_union_nhlfe_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nhlfe_t_anonymous_union_nhlfe_payload_t& m) {
            archive(::cereal::make_nvp("te_headend", m.te_headend));
            archive(::cereal::make_nvp("te_midpoint", m.te_midpoint));
            archive(::cereal::make_nvp("l2_adj_sid", m.l2_adj_sid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nhlfe_t_anonymous_union_nhlfe_payload_t& m) {
            archive(::cereal::make_nvp("te_headend", m.te_headend));
            archive(::cereal::make_nvp("te_midpoint", m.te_midpoint));
            archive(::cereal::make_nvp("l2_adj_sid", m.l2_adj_sid));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nhlfe_t_anonymous_union_nhlfe_payload_t& m)
{
    serializer_class<npl_nhlfe_t_anonymous_union_nhlfe_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nhlfe_t_anonymous_union_nhlfe_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_nhlfe_t_anonymous_union_nhlfe_payload_t& m)
{
    serializer_class<npl_nhlfe_t_anonymous_union_nhlfe_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nhlfe_t_anonymous_union_nhlfe_payload_t&);



template<>
class serializer_class<npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t& m) {
            archive(::cereal::make_nvp("host_nh_mac", m.host_nh_mac));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t& m) {
            archive(::cereal::make_nvp("host_nh_mac", m.host_nh_mac));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t& m)
{
    serializer_class<npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t& m)
{
    serializer_class<npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t&);



template<>
class serializer_class<npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t& m) {
            archive(::cereal::make_nvp("ac", m.ac));
            archive(::cereal::make_nvp("pwe", m.pwe));
            archive(::cereal::make_nvp("vxlan", m.vxlan));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t& m) {
            archive(::cereal::make_nvp("ac", m.ac));
            archive(::cereal::make_nvp("pwe", m.pwe));
            archive(::cereal::make_nvp("vxlan", m.vxlan));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t& m)
{
    serializer_class<npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t& m)
{
    serializer_class<npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t&);



template<>
class serializer_class<npl_npu_l3_common_encap_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l3_common_encap_header_t& m) {
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
            archive(::cereal::make_nvp("l3_dlp_nh_encap", m.l3_dlp_nh_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l3_common_encap_header_t& m) {
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
            archive(::cereal::make_nvp("l3_dlp_nh_encap", m.l3_dlp_nh_encap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l3_common_encap_header_t& m)
{
    serializer_class<npl_npu_l3_common_encap_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l3_common_encap_header_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l3_common_encap_header_t& m)
{
    serializer_class<npl_npu_l3_common_encap_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l3_common_encap_header_t&);



template<>
class serializer_class<npl_npu_l3_encap_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l3_encap_header_t& m) {
            archive(::cereal::make_nvp("l3_common_encap", m.l3_common_encap));
            archive(::cereal::make_nvp("encap_ext", m.encap_ext));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l3_encap_header_t& m) {
            archive(::cereal::make_nvp("l3_common_encap", m.l3_common_encap));
            archive(::cereal::make_nvp("encap_ext", m.encap_ext));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l3_encap_header_t& m)
{
    serializer_class<npl_npu_l3_encap_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l3_encap_header_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l3_encap_header_t& m)
{
    serializer_class<npl_npu_l3_encap_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l3_encap_header_t&);



template<>
class serializer_class<npl_og_em_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_em_result_t& m) {
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("result_type", m.result_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_em_result_t& m) {
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("result_type", m.result_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_em_result_t& m)
{
    serializer_class<npl_og_em_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_em_result_t&);

template <class Archive>
void
load(Archive& archive, npl_og_em_result_t& m)
{
    serializer_class<npl_og_em_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_em_result_t&);



template<>
class serializer_class<npl_punt_eth_nw_common_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_eth_nw_common_encap_data_t& m) {
            archive(::cereal::make_nvp("punt_host_da", m.punt_host_da));
            archive(::cereal::make_nvp("sa_or_npuh", m.sa_or_npuh));
            archive(::cereal::make_nvp("punt_eth_vid", m.punt_eth_vid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_eth_nw_common_encap_data_t& m) {
            archive(::cereal::make_nvp("punt_host_da", m.punt_host_da));
            archive(::cereal::make_nvp("sa_or_npuh", m.sa_or_npuh));
            archive(::cereal::make_nvp("punt_eth_vid", m.punt_eth_vid));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_eth_nw_common_encap_data_t& m)
{
    serializer_class<npl_punt_eth_nw_common_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_eth_nw_common_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_eth_nw_common_encap_data_t& m)
{
    serializer_class<npl_punt_eth_nw_common_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_eth_nw_common_encap_data_t&);



template<>
class serializer_class<npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t& m) {
            archive(::cereal::make_nvp("punt_padding_id", m.punt_padding_id));
            archive(::cereal::make_nvp("sw_pfc", m.sw_pfc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t& m) {
            archive(::cereal::make_nvp("punt_padding_id", m.punt_padding_id));
            archive(::cereal::make_nvp("sw_pfc", m.sw_pfc));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t& m)
{
    serializer_class<npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t& m)
{
    serializer_class<npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t&);



template<>
class serializer_class<npl_punt_msb_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_msb_encap_t& m) {
            archive(::cereal::make_nvp("punt_encap_msb", m.punt_encap_msb));
            archive(::cereal::make_nvp("punt_lm_cmd", m.punt_lm_cmd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_msb_encap_t& m) {
            archive(::cereal::make_nvp("punt_encap_msb", m.punt_encap_msb));
            archive(::cereal::make_nvp("punt_lm_cmd", m.punt_lm_cmd));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_msb_encap_t& m)
{
    serializer_class<npl_punt_msb_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_msb_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_msb_encap_t& m)
{
    serializer_class<npl_punt_msb_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_msb_encap_t&);



template<>
class serializer_class<npl_rpf_compressed_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_compressed_destination_t& m) {
        uint64_t m_enable_mc_rpf = m.enable_mc_rpf;
            archive(::cereal::make_nvp("enable_mc_rpf", m_enable_mc_rpf));
            archive(::cereal::make_nvp("rpf_id_or_lp_id", m.rpf_id_or_lp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_compressed_destination_t& m) {
        uint64_t m_enable_mc_rpf;
            archive(::cereal::make_nvp("enable_mc_rpf", m_enable_mc_rpf));
            archive(::cereal::make_nvp("rpf_id_or_lp_id", m.rpf_id_or_lp_id));
        m.enable_mc_rpf = m_enable_mc_rpf;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_compressed_destination_t& m)
{
    serializer_class<npl_rpf_compressed_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_compressed_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_compressed_destination_t& m)
{
    serializer_class<npl_rpf_compressed_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_compressed_destination_t&);



template<>
class serializer_class<npl_rtf_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_payload_t& m) {
            archive(::cereal::make_nvp("rtf_profile_index", m.rtf_profile_index));
            archive(::cereal::make_nvp("rtf_result_profile", m.rtf_result_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_payload_t& m) {
            archive(::cereal::make_nvp("rtf_profile_index", m.rtf_profile_index));
            archive(::cereal::make_nvp("rtf_result_profile", m.rtf_result_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_payload_t& m)
{
    serializer_class<npl_rtf_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_payload_t& m)
{
    serializer_class<npl_rtf_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_payload_t&);



template<>
class serializer_class<npl_slp_info_t_anonymous_union_global_slp_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slp_info_t_anonymous_union_global_slp_id_t& m) {
        uint64_t m_is_l2 = m.is_l2;
            archive(::cereal::make_nvp("l2_slp", m.l2_slp));
            archive(::cereal::make_nvp("l3_slp", m.l3_slp));
            archive(::cereal::make_nvp("is_l2", m_is_l2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slp_info_t_anonymous_union_global_slp_id_t& m) {
        uint64_t m_is_l2;
            archive(::cereal::make_nvp("l2_slp", m.l2_slp));
            archive(::cereal::make_nvp("l3_slp", m.l3_slp));
            archive(::cereal::make_nvp("is_l2", m_is_l2));
        m.is_l2 = m_is_l2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slp_info_t_anonymous_union_global_slp_id_t& m)
{
    serializer_class<npl_slp_info_t_anonymous_union_global_slp_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slp_info_t_anonymous_union_global_slp_id_t&);

template <class Archive>
void
load(Archive& archive, npl_slp_info_t_anonymous_union_global_slp_id_t& m)
{
    serializer_class<npl_slp_info_t_anonymous_union_global_slp_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slp_info_t_anonymous_union_global_slp_id_t&);



template<>
class serializer_class<npl_snoop_or_rcy_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_or_rcy_data_t& m) {
            archive(::cereal::make_nvp("snoop_or_rcy_data", m.snoop_or_rcy_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_or_rcy_data_t& m) {
            archive(::cereal::make_nvp("snoop_or_rcy_data", m.snoop_or_rcy_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_or_rcy_data_t& m)
{
    serializer_class<npl_snoop_or_rcy_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_or_rcy_data_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_or_rcy_data_t& m)
{
    serializer_class<npl_snoop_or_rcy_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_or_rcy_data_t&);



template<>
class serializer_class<npl_std_ip_em_lpm_result_host_and_l3_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_std_ip_em_lpm_result_host_and_l3_dlp_t& m) {
            archive(::cereal::make_nvp("host_nh_mac", m.host_nh_mac));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_std_ip_em_lpm_result_host_and_l3_dlp_t& m) {
            archive(::cereal::make_nvp("host_nh_mac", m.host_nh_mac));
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_std_ip_em_lpm_result_host_and_l3_dlp_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_host_and_l3_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_std_ip_em_lpm_result_host_and_l3_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_std_ip_em_lpm_result_host_and_l3_dlp_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_host_and_l3_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_std_ip_em_lpm_result_host_and_l3_dlp_t&);



template<>
class serializer_class<npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t& m) {
            archive(::cereal::make_nvp("host_ptr", m.host_ptr));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t& m) {
            archive(::cereal::make_nvp("host_ptr", m.host_ptr));
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t&);



template<>
class serializer_class<npl_svi_eve_profile_and_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svi_eve_profile_and_data_t& m) {
        uint64_t m_vid1 = m.vid1;
            archive(::cereal::make_nvp("main_type", m.main_type));
            archive(::cereal::make_nvp("sub_type_or_vid_2_plus_prf", m.sub_type_or_vid_2_plus_prf));
            archive(::cereal::make_nvp("vid1", m_vid1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svi_eve_profile_and_data_t& m) {
        uint64_t m_vid1;
            archive(::cereal::make_nvp("main_type", m.main_type));
            archive(::cereal::make_nvp("sub_type_or_vid_2_plus_prf", m.sub_type_or_vid_2_plus_prf));
            archive(::cereal::make_nvp("vid1", m_vid1));
        m.vid1 = m_vid1;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svi_eve_profile_and_data_t& m)
{
    serializer_class<npl_svi_eve_profile_and_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svi_eve_profile_and_data_t&);

template <class Archive>
void
load(Archive& archive, npl_svi_eve_profile_and_data_t& m)
{
    serializer_class<npl_svi_eve_profile_and_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svi_eve_profile_and_data_t&);



template<>
class serializer_class<npl_tm_headers_template_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tm_headers_template_t& m) {
            archive(::cereal::make_nvp("u", m.u));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tm_headers_template_t& m) {
            archive(::cereal::make_nvp("u", m.u));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tm_headers_template_t& m)
{
    serializer_class<npl_tm_headers_template_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tm_headers_template_t&);

template <class Archive>
void
load(Archive& archive, npl_tm_headers_template_t& m)
{
    serializer_class<npl_tm_headers_template_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tm_headers_template_t&);



template<>
class serializer_class<npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t& m) {
            archive(::cereal::make_nvp("punt_eth_nw_encap_data", m.punt_eth_nw_encap_data));
            archive(::cereal::make_nvp("punt_eth_transport_update", m.punt_eth_transport_update));
            archive(::cereal::make_nvp("punt_npu_host_data", m.punt_npu_host_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t& m) {
            archive(::cereal::make_nvp("punt_eth_nw_encap_data", m.punt_eth_nw_encap_data));
            archive(::cereal::make_nvp("punt_eth_transport_update", m.punt_eth_transport_update));
            archive(::cereal::make_nvp("punt_npu_host_data", m.punt_npu_host_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t& m)
{
    serializer_class<npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t& m)
{
    serializer_class<npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t&);



template<>
class serializer_class<npl_ac_dlp_specific_t_anonymous_union_eve_types_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ac_dlp_specific_t_anonymous_union_eve_types_t& m) {
            archive(::cereal::make_nvp("eve", m.eve));
            archive(::cereal::make_nvp("eve_svi", m.eve_svi));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ac_dlp_specific_t_anonymous_union_eve_types_t& m) {
            archive(::cereal::make_nvp("eve", m.eve));
            archive(::cereal::make_nvp("eve_svi", m.eve_svi));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ac_dlp_specific_t_anonymous_union_eve_types_t& m)
{
    serializer_class<npl_ac_dlp_specific_t_anonymous_union_eve_types_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ac_dlp_specific_t_anonymous_union_eve_types_t&);

template <class Archive>
void
load(Archive& archive, npl_ac_dlp_specific_t_anonymous_union_eve_types_t& m)
{
    serializer_class<npl_ac_dlp_specific_t_anonymous_union_eve_types_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ac_dlp_specific_t_anonymous_union_eve_types_t&);



template<>
class serializer_class<npl_base_l3_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_base_l3_lp_attributes_t& m) {
        uint64_t m_mirror_cmd = m.mirror_cmd;
            archive(::cereal::make_nvp("rtf_conf_set_and_stages_or_post_fwd_stage", m.rtf_conf_set_and_stages_or_post_fwd_stage));
            archive(::cereal::make_nvp("uc_rpf_mode", m.uc_rpf_mode));
            archive(::cereal::make_nvp("mirror_cmd", m_mirror_cmd));
            archive(::cereal::make_nvp("minimal_l3_lp_attributes", m.minimal_l3_lp_attributes));
            archive(::cereal::make_nvp("l3_lp_mirror_type", m.l3_lp_mirror_type));
            archive(::cereal::make_nvp("acl_drop_offset", m.acl_drop_offset));
            archive(::cereal::make_nvp("q_counter", m.q_counter));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_base_l3_lp_attributes_t& m) {
        uint64_t m_mirror_cmd;
            archive(::cereal::make_nvp("rtf_conf_set_and_stages_or_post_fwd_stage", m.rtf_conf_set_and_stages_or_post_fwd_stage));
            archive(::cereal::make_nvp("uc_rpf_mode", m.uc_rpf_mode));
            archive(::cereal::make_nvp("mirror_cmd", m_mirror_cmd));
            archive(::cereal::make_nvp("minimal_l3_lp_attributes", m.minimal_l3_lp_attributes));
            archive(::cereal::make_nvp("l3_lp_mirror_type", m.l3_lp_mirror_type));
            archive(::cereal::make_nvp("acl_drop_offset", m.acl_drop_offset));
            archive(::cereal::make_nvp("q_counter", m.q_counter));
            archive(::cereal::make_nvp("m_counter", m.m_counter));
        m.mirror_cmd = m_mirror_cmd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_base_l3_lp_attributes_t& m)
{
    serializer_class<npl_base_l3_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_base_l3_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_base_l3_lp_attributes_t& m)
{
    serializer_class<npl_base_l3_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_base_l3_lp_attributes_t&);



template<>
class serializer_class<npl_em_result_ptr_and_l3_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_result_ptr_and_l3_dlp_t& m) {
            archive(::cereal::make_nvp("host_ptr", m.host_ptr));
            archive(::cereal::make_nvp("destination", m.destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_result_ptr_and_l3_dlp_t& m) {
            archive(::cereal::make_nvp("host_ptr", m.host_ptr));
            archive(::cereal::make_nvp("destination", m.destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_result_ptr_and_l3_dlp_t& m)
{
    serializer_class<npl_em_result_ptr_and_l3_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_result_ptr_and_l3_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_em_result_ptr_and_l3_dlp_t& m)
{
    serializer_class<npl_em_result_ptr_and_l3_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_result_ptr_and_l3_dlp_t&);



template<>
class serializer_class<npl_inject_down_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_data_t& m) {
            archive(::cereal::make_nvp("bfd_ih_down", m.bfd_ih_down));
            archive(::cereal::make_nvp("inject_down", m.inject_down));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_data_t& m) {
            archive(::cereal::make_nvp("bfd_ih_down", m.bfd_ih_down));
            archive(::cereal::make_nvp("inject_down", m.inject_down));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_data_t& m)
{
    serializer_class<npl_inject_down_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_data_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_data_t& m)
{
    serializer_class<npl_inject_down_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_data_t&);



}

