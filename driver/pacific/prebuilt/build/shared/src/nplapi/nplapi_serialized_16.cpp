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

template <class Archive> void save(Archive&, const npl_ac_dlp_specific_t_anonymous_union_eve_types_t&);
template <class Archive> void load(Archive&, npl_ac_dlp_specific_t_anonymous_union_eve_types_t&);

template <class Archive> void save(Archive&, const npl_app_relay_id_t&);
template <class Archive> void load(Archive&, npl_app_relay_id_t&);

template <class Archive> void save(Archive&, const npl_base_l3_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_base_l3_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_bfd_mp_table_extra_payload_t&);
template <class Archive> void load(Archive&, npl_bfd_mp_table_extra_payload_t&);

template <class Archive> void save(Archive&, const npl_bfd_mp_table_shared_msb_t&);
template <class Archive> void load(Archive&, npl_bfd_mp_table_shared_msb_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_dlp_attributes_t&);
template <class Archive> void load(Archive&, npl_dlp_attributes_t&);

template <class Archive> void save(Archive&, const npl_em_destination_t&);
template <class Archive> void load(Archive&, npl_em_destination_t&);

template <class Archive> void save(Archive&, const npl_em_result_dsp_host_t&);
template <class Archive> void load(Archive&, npl_em_result_dsp_host_t&);

template <class Archive> void save(Archive&, const npl_em_result_ptr_and_l3_dlp_t&);
template <class Archive> void load(Archive&, npl_em_result_ptr_and_l3_dlp_t&);

template <class Archive> void save(Archive&, const npl_eth_mp_table_transmit_a_payload_t&);
template <class Archive> void load(Archive&, npl_eth_mp_table_transmit_a_payload_t&);

template <class Archive> void save(Archive&, const npl_fabric_mc_ibm_cmd_t&);
template <class Archive> void load(Archive&, npl_fabric_mc_ibm_cmd_t&);

template <class Archive> void save(Archive&, const npl_inject_down_data_t&);
template <class Archive> void load(Archive&, npl_inject_down_data_t&);

template <class Archive> void save(Archive&, const npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t&);
template <class Archive> void load(Archive&, npl_inject_header_specific_data_t_anonymous_union_inject_header_encap_hdr_ptr_t&);

template <class Archive> void save(Archive&, const npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t&);
template <class Archive> void load(Archive&, npl_inject_header_t_anonymous_union_ts_and_cntr_stamp_cmd_t&);

template <class Archive> void save(Archive&, const npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t&);
template <class Archive> void load(Archive&, npl_inject_specific_data_t_anonymous_union_inject_data_t_anonymous_union_inject_down_u_t&);

template <class Archive> void save(Archive&, const npl_inject_up_eth_header_t&);
template <class Archive> void load(Archive&, npl_inject_up_eth_header_t&);

template <class Archive> void save(Archive&, const npl_inject_up_none_routable_mc_lpts_t&);
template <class Archive> void load(Archive&, npl_inject_up_none_routable_mc_lpts_t&);

template <class Archive> void save(Archive&, const npl_inject_up_vxlan_mc_t&);
template <class Archive> void load(Archive&, npl_inject_up_vxlan_mc_t&);

template <class Archive> void save(Archive&, const npl_l2_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_l2_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l2_lp_with_padding_t&);
template <class Archive> void load(Archive&, npl_l2_lp_with_padding_t&);

template <class Archive> void save(Archive&, const npl_l3_lp_additional_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_lp_additional_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_pfc_data_t&);
template <class Archive> void load(Archive&, npl_l3_pfc_data_t&);

template <class Archive> void save(Archive&, const npl_lp_attr_update_raw_bits_t&);
template <class Archive> void load(Archive&, npl_lp_attr_update_raw_bits_t&);

template <class Archive> void save(Archive&, const npl_lp_id_t&);
template <class Archive> void load(Archive&, npl_lp_id_t&);

template <class Archive> void save(Archive&, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t&);
template <class Archive> void load(Archive&, npl_lsp_encap_mapping_data_payload_t_anonymous_union_counter_and_flag_t&);

template <class Archive> void save(Archive&, const npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t&);
template <class Archive> void load(Archive&, npl_lsp_encap_mapping_data_payload_t_anonymous_union_label_stack_t&);

template <class Archive> void save(Archive&, const npl_mcid_t&);
template <class Archive> void load(Archive&, npl_mcid_t&);

template <class Archive> void save(Archive&, const npl_mp_table_app_t_anonymous_union_mp2_data_union_t&);
template <class Archive> void load(Archive&, npl_mp_table_app_t_anonymous_union_mp2_data_union_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_result_t_anonymous_union_pwe_vpn_mldp_info_t&);

template <class Archive> void save(Archive&, const npl_nhlfe_t_anonymous_union_nhlfe_payload_t&);
template <class Archive> void load(Archive&, npl_nhlfe_t_anonymous_union_nhlfe_payload_t&);

template <class Archive> void save(Archive&, const npl_npl_internal_info_t&);
template <class Archive> void load(Archive&, npl_npl_internal_info_t&);

template <class Archive> void save(Archive&, const npl_npu_dsp_pif_ifg_t&);
template <class Archive> void load(Archive&, npl_npu_dsp_pif_ifg_t&);

template <class Archive> void save(Archive&, const npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t&);
template <class Archive> void load(Archive&, npl_npu_encap_header_ip_host_t_anonymous_union_next_hop_t&);

template <class Archive> void save(Archive&, const npl_npu_host_data_result_count_phase_t&);
template <class Archive> void load(Archive&, npl_npu_host_data_result_count_phase_t&);

template <class Archive> void save(Archive&, const npl_npu_ip_collapsed_mc_encap_header_t&);
template <class Archive> void load(Archive&, npl_npu_ip_collapsed_mc_encap_header_t&);

template <class Archive> void save(Archive&, const npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t&);
template <class Archive> void load(Archive&, npl_npu_l2_encap_header_t_anonymous_union_l2_dlp_type_t&);

template <class Archive> void save(Archive&, const npl_npu_l3_encap_header_t&);
template <class Archive> void load(Archive&, npl_npu_l3_encap_header_t&);

template <class Archive> void save(Archive&, const npl_pd_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_pd_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_punt_code_t&);
template <class Archive> void load(Archive&, npl_punt_code_t&);

template <class Archive> void save(Archive&, const npl_punt_header_t_anonymous_union_pl_header_offset_t&);
template <class Archive> void load(Archive&, npl_punt_header_t_anonymous_union_pl_header_offset_t&);

template <class Archive> void save(Archive&, const npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t&);
template <class Archive> void load(Archive&, npl_punt_l3_lp_t_anonymous_union_id_or_pfc_t&);

template <class Archive> void save(Archive&, const npl_punt_lsb_encap_t&);
template <class Archive> void load(Archive&, npl_punt_lsb_encap_t&);

template <class Archive> void save(Archive&, const npl_punt_msb_encap_t&);
template <class Archive> void load(Archive&, npl_punt_msb_encap_t&);

template <class Archive> void save(Archive&, const npl_punt_src_and_code_t&);
template <class Archive> void load(Archive&, npl_punt_src_and_code_t&);

template <class Archive> void save(Archive&, const npl_punt_sub_code_with_padding_t&);
template <class Archive> void load(Archive&, npl_punt_sub_code_with_padding_t&);

template <class Archive> void save(Archive&, const npl_pwe_dlp_specific_t&);
template <class Archive> void load(Archive&, npl_pwe_dlp_specific_t&);

template <class Archive> void save(Archive&, const npl_qos_attributes_t&);
template <class Archive> void load(Archive&, npl_qos_attributes_t&);

template <class Archive> void save(Archive&, const npl_resolution_dlp_attributes_t&);
template <class Archive> void load(Archive&, npl_resolution_dlp_attributes_t&);

template <class Archive> void save(Archive&, const npl_rpf_compressed_destination_t&);
template <class Archive> void load(Archive&, npl_rpf_compressed_destination_t&);

template <class Archive> void save(Archive&, const npl_slp_info_t_anonymous_union_global_slp_id_t&);
template <class Archive> void load(Archive&, npl_slp_info_t_anonymous_union_global_slp_id_t&);

template <class Archive> void save(Archive&, const npl_std_ip_em_lpm_result_destination_t&);
template <class Archive> void load(Archive&, npl_std_ip_em_lpm_result_destination_t&);

template <class Archive> void save(Archive&, const npl_std_ip_em_lpm_result_destination_with_default_t&);
template <class Archive> void load(Archive&, npl_std_ip_em_lpm_result_destination_with_default_t&);

template <class Archive> void save(Archive&, const npl_std_ip_em_lpm_result_host_and_l3_dlp_t&);
template <class Archive> void load(Archive&, npl_std_ip_em_lpm_result_host_and_l3_dlp_t&);

template <class Archive> void save(Archive&, const npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t&);
template <class Archive> void load(Archive&, npl_std_ip_em_lpm_result_ptr_and_l3_dlp_t&);

template <class Archive> void save(Archive&, const npl_system_mcid_t&);
template <class Archive> void load(Archive&, npl_system_mcid_t&);

template <class Archive> void save(Archive&, const npl_tx_to_rx_rcy_data_t&);
template <class Archive> void load(Archive&, npl_tx_to_rx_rcy_data_t&);

template<>
class serializer_class<npl_inject_specific_data_t_anonymous_union_inject_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_specific_data_t_anonymous_union_inject_data_t& m) {
            archive(::cereal::make_nvp("inject_down_u", m.inject_down_u));
            archive(::cereal::make_nvp("inject_up_eth", m.inject_up_eth));
            archive(::cereal::make_nvp("inject_up_none_routable_mc_lpts", m.inject_up_none_routable_mc_lpts));
            archive(::cereal::make_nvp("inject_vxlan_mc_up", m.inject_vxlan_mc_up));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_specific_data_t_anonymous_union_inject_data_t& m) {
            archive(::cereal::make_nvp("inject_down_u", m.inject_down_u));
            archive(::cereal::make_nvp("inject_up_eth", m.inject_up_eth));
            archive(::cereal::make_nvp("inject_up_none_routable_mc_lpts", m.inject_up_none_routable_mc_lpts));
            archive(::cereal::make_nvp("inject_vxlan_mc_up", m.inject_vxlan_mc_up));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_specific_data_t_anonymous_union_inject_data_t& m)
{
    serializer_class<npl_inject_specific_data_t_anonymous_union_inject_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_specific_data_t_anonymous_union_inject_data_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_specific_data_t_anonymous_union_inject_data_t& m)
{
    serializer_class<npl_inject_specific_data_t_anonymous_union_inject_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_specific_data_t_anonymous_union_inject_data_t&);



template<>
class serializer_class<npl_ip_mc_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_result_payload_t& m) {
        uint64_t m_punt_on_rpf_fail = m.punt_on_rpf_fail;
        uint64_t m_punt_and_fwd = m.punt_and_fwd;
            archive(::cereal::make_nvp("global_mcid", m.global_mcid));
            archive(::cereal::make_nvp("rpf_destination", m.rpf_destination));
            archive(::cereal::make_nvp("local_mcid", m.local_mcid));
            archive(::cereal::make_nvp("punt_on_rpf_fail", m_punt_on_rpf_fail));
            archive(::cereal::make_nvp("punt_and_fwd", m_punt_and_fwd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_result_payload_t& m) {
        uint64_t m_punt_on_rpf_fail;
        uint64_t m_punt_and_fwd;
            archive(::cereal::make_nvp("global_mcid", m.global_mcid));
            archive(::cereal::make_nvp("rpf_destination", m.rpf_destination));
            archive(::cereal::make_nvp("local_mcid", m.local_mcid));
            archive(::cereal::make_nvp("punt_on_rpf_fail", m_punt_on_rpf_fail));
            archive(::cereal::make_nvp("punt_and_fwd", m_punt_and_fwd));
        m.punt_on_rpf_fail = m_punt_on_rpf_fail;
        m.punt_and_fwd = m_punt_and_fwd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_result_payload_t& m)
{
    serializer_class<npl_ip_mc_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_result_payload_t& m)
{
    serializer_class<npl_ip_mc_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_result_payload_t&);



template<>
class serializer_class<npl_ip_mc_result_payload_with_format_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_result_payload_with_format_t& m) {
        uint64_t m_format = m.format;
            archive(::cereal::make_nvp("mc_result_payload", m.mc_result_payload));
            archive(::cereal::make_nvp("format", m_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_result_payload_with_format_t& m) {
        uint64_t m_format;
            archive(::cereal::make_nvp("mc_result_payload", m.mc_result_payload));
            archive(::cereal::make_nvp("format", m_format));
        m.format = m_format;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_result_payload_with_format_t& m)
{
    serializer_class<npl_ip_mc_result_payload_with_format_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_result_payload_with_format_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_result_payload_with_format_t& m)
{
    serializer_class<npl_ip_mc_result_payload_with_format_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_result_payload_with_format_t&);



template<>
class serializer_class<npl_l3_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_attributes_t& m) {
            archive(::cereal::make_nvp("additional", m.additional));
            archive(::cereal::make_nvp("base", m.base));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_attributes_t& m) {
            archive(::cereal::make_nvp("additional", m.additional));
            archive(::cereal::make_nvp("base", m.base));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_lp_attributes_t& m)
{
    serializer_class<npl_l3_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_attributes_t& m)
{
    serializer_class<npl_l3_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_attributes_t&);



template<>
class serializer_class<npl_lsp_encap_mapping_data_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_lsp_encap_mapping_data_payload_t& m) {
            archive(::cereal::make_nvp("label_stack", m.label_stack));
            archive(::cereal::make_nvp("counter_and_flag", m.counter_and_flag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_lsp_encap_mapping_data_payload_t& m) {
            archive(::cereal::make_nvp("label_stack", m.label_stack));
            archive(::cereal::make_nvp("counter_and_flag", m.counter_and_flag));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_lsp_encap_mapping_data_payload_t& m)
{
    serializer_class<npl_lsp_encap_mapping_data_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_lsp_encap_mapping_data_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_lsp_encap_mapping_data_payload_t& m)
{
    serializer_class<npl_lsp_encap_mapping_data_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_lsp_encap_mapping_data_payload_t&);



template<>
class serializer_class<npl_mac_l3_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_l3_lp_attributes_t& m) {
        uint64_t m_l3_lp_mymac_da_prefix = m.l3_lp_mymac_da_prefix;
        uint64_t m_mldp_budnode_terminate = m.mldp_budnode_terminate;
        uint64_t m_l3_lp_mymac_da_lsb = m.l3_lp_mymac_da_lsb;
            archive(::cereal::make_nvp("l3_lp_mymac_da_prefix", m_l3_lp_mymac_da_prefix));
            archive(::cereal::make_nvp("mldp_budnode_terminate", m_mldp_budnode_terminate));
            archive(::cereal::make_nvp("l3_lp_mymac_da_lsb", m_l3_lp_mymac_da_lsb));
            archive(::cereal::make_nvp("base", m.base));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_l3_lp_attributes_t& m) {
        uint64_t m_l3_lp_mymac_da_prefix;
        uint64_t m_mldp_budnode_terminate;
        uint64_t m_l3_lp_mymac_da_lsb;
            archive(::cereal::make_nvp("l3_lp_mymac_da_prefix", m_l3_lp_mymac_da_prefix));
            archive(::cereal::make_nvp("mldp_budnode_terminate", m_mldp_budnode_terminate));
            archive(::cereal::make_nvp("l3_lp_mymac_da_lsb", m_l3_lp_mymac_da_lsb));
            archive(::cereal::make_nvp("base", m.base));
        m.l3_lp_mymac_da_prefix = m_l3_lp_mymac_da_prefix;
        m.mldp_budnode_terminate = m_mldp_budnode_terminate;
        m.l3_lp_mymac_da_lsb = m_l3_lp_mymac_da_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_l3_lp_attributes_t& m)
{
    serializer_class<npl_mac_l3_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_l3_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_l3_lp_attributes_t& m)
{
    serializer_class<npl_mac_l3_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_l3_lp_attributes_t&);



template<>
class serializer_class<npl_mac_lp_attributes_payload_t_anonymous_union_layer_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_lp_attributes_payload_t_anonymous_union_layer_t& m) {
            archive(::cereal::make_nvp("two", m.two));
            archive(::cereal::make_nvp("three", m.three));
            archive(::cereal::make_nvp("pd", m.pd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_lp_attributes_payload_t_anonymous_union_layer_t& m) {
            archive(::cereal::make_nvp("two", m.two));
            archive(::cereal::make_nvp("three", m.three));
            archive(::cereal::make_nvp("pd", m.pd));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_lp_attributes_payload_t_anonymous_union_layer_t& m)
{
    serializer_class<npl_mac_lp_attributes_payload_t_anonymous_union_layer_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_lp_attributes_payload_t_anonymous_union_layer_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_lp_attributes_payload_t_anonymous_union_layer_t& m)
{
    serializer_class<npl_mac_lp_attributes_payload_t_anonymous_union_layer_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_lp_attributes_payload_t_anonymous_union_layer_t&);



template<>
class serializer_class<npl_mpls_termination_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_result_t& m) {
            archive(::cereal::make_nvp("service", m.service));
            archive(::cereal::make_nvp("pwe_vpn_mldp_info", m.pwe_vpn_mldp_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_result_t& m) {
            archive(::cereal::make_nvp("service", m.service));
            archive(::cereal::make_nvp("pwe_vpn_mldp_info", m.pwe_vpn_mldp_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_result_t& m)
{
    serializer_class<npl_mpls_termination_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_result_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_result_t& m)
{
    serializer_class<npl_mpls_termination_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_result_t&);



template<>
class serializer_class<npl_nhlfe_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nhlfe_t& m) {
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("nhlfe_payload", m.nhlfe_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nhlfe_t& m) {
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("nhlfe_payload", m.nhlfe_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nhlfe_t& m)
{
    serializer_class<npl_nhlfe_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nhlfe_t&);

template <class Archive>
void
load(Archive& archive, npl_nhlfe_t& m)
{
    serializer_class<npl_nhlfe_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nhlfe_t&);



template<>
class serializer_class<npl_npu_encap_header_ip_host_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_encap_header_ip_host_t& m) {
            archive(::cereal::make_nvp("l3_encapsulation_type", m.l3_encapsulation_type));
            archive(::cereal::make_nvp("next_hop", m.next_hop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_encap_header_ip_host_t& m) {
            archive(::cereal::make_nvp("l3_encapsulation_type", m.l3_encapsulation_type));
            archive(::cereal::make_nvp("next_hop", m.next_hop));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_encap_header_ip_host_t& m)
{
    serializer_class<npl_npu_encap_header_ip_host_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_encap_header_ip_host_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_encap_header_ip_host_t& m)
{
    serializer_class<npl_npu_encap_header_ip_host_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_encap_header_ip_host_t&);



template<>
class serializer_class<npl_npu_l2_encap_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_l2_encap_header_t& m) {
            archive(::cereal::make_nvp("l2_encapsulation_type", m.l2_encapsulation_type));
            archive(::cereal::make_nvp("l2_dlp_type", m.l2_dlp_type));
            archive(::cereal::make_nvp("npu_pif_ifg", m.npu_pif_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_l2_encap_header_t& m) {
            archive(::cereal::make_nvp("l2_encapsulation_type", m.l2_encapsulation_type));
            archive(::cereal::make_nvp("l2_dlp_type", m.l2_dlp_type));
            archive(::cereal::make_nvp("npu_pif_ifg", m.npu_pif_ifg));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_l2_encap_header_t& m)
{
    serializer_class<npl_npu_l2_encap_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_l2_encap_header_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_l2_encap_header_t& m)
{
    serializer_class<npl_npu_l2_encap_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_l2_encap_header_t&);



template<>
class serializer_class<npl_punt_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_encap_data_t& m) {
            archive(::cereal::make_nvp("punt_msb_encap", m.punt_msb_encap));
            archive(::cereal::make_nvp("punt_lsb_encap", m.punt_lsb_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_encap_data_t& m) {
            archive(::cereal::make_nvp("punt_msb_encap", m.punt_msb_encap));
            archive(::cereal::make_nvp("punt_lsb_encap", m.punt_lsb_encap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_encap_data_t& m)
{
    serializer_class<npl_punt_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_encap_data_t& m)
{
    serializer_class<npl_punt_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_encap_data_t&);



template<>
class serializer_class<npl_punt_l3_lp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_l3_lp_t& m) {
            archive(::cereal::make_nvp("id_or_pfc", m.id_or_pfc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_l3_lp_t& m) {
            archive(::cereal::make_nvp("id_or_pfc", m.id_or_pfc));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_l3_lp_t& m)
{
    serializer_class<npl_punt_l3_lp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_l3_lp_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_l3_lp_t& m)
{
    serializer_class<npl_punt_l3_lp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_l3_lp_t&);



template<>
class serializer_class<npl_resolution_result_enc_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_result_enc_data_t& m) {
            archive(::cereal::make_nvp("l2", m.l2));
            archive(::cereal::make_nvp("l3", m.l3));
            archive(::cereal::make_nvp("ip_collapsed_mc_encap_header", m.ip_collapsed_mc_encap_header));
            archive(::cereal::make_nvp("mpls_mc_host_encap_header", m.mpls_mc_host_encap_header));
            archive(::cereal::make_nvp("dlp_attributes", m.dlp_attributes));
            archive(::cereal::make_nvp("pif_ifg_data", m.pif_ifg_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_result_enc_data_t& m) {
            archive(::cereal::make_nvp("l2", m.l2));
            archive(::cereal::make_nvp("l3", m.l3));
            archive(::cereal::make_nvp("ip_collapsed_mc_encap_header", m.ip_collapsed_mc_encap_header));
            archive(::cereal::make_nvp("mpls_mc_host_encap_header", m.mpls_mc_host_encap_header));
            archive(::cereal::make_nvp("dlp_attributes", m.dlp_attributes));
            archive(::cereal::make_nvp("pif_ifg_data", m.pif_ifg_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_result_enc_data_t& m)
{
    serializer_class<npl_resolution_result_enc_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_result_enc_data_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_result_enc_data_t& m)
{
    serializer_class<npl_resolution_result_enc_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_result_enc_data_t&);



template<>
class serializer_class<npl_slp_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slp_info_t& m) {
        uint64_t m_slp_profile = m.slp_profile;
            archive(::cereal::make_nvp("slp_profile", m_slp_profile));
            archive(::cereal::make_nvp("global_slp_id", m.global_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slp_info_t& m) {
        uint64_t m_slp_profile;
            archive(::cereal::make_nvp("slp_profile", m_slp_profile));
            archive(::cereal::make_nvp("global_slp_id", m.global_slp_id));
        m.slp_profile = m_slp_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slp_info_t& m)
{
    serializer_class<npl_slp_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slp_info_t&);

template <class Archive>
void
load(Archive& archive, npl_slp_info_t& m)
{
    serializer_class<npl_slp_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slp_info_t&);



template<>
class serializer_class<npl_std_ip_em_lpm_result_mc_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_std_ip_em_lpm_result_mc_t& m) {
            archive(::cereal::make_nvp("mc_result", m.mc_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_std_ip_em_lpm_result_mc_t& m) {
            archive(::cereal::make_nvp("mc_result", m.mc_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_std_ip_em_lpm_result_mc_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_mc_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_std_ip_em_lpm_result_mc_t&);

template <class Archive>
void
load(Archive& archive, npl_std_ip_em_lpm_result_mc_t& m)
{
    serializer_class<npl_std_ip_em_lpm_result_mc_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_std_ip_em_lpm_result_mc_t&);



template<>
class serializer_class<npl_wrap_nhlfe_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_wrap_nhlfe_t& m) {
            archive(::cereal::make_nvp("nhlfe", m.nhlfe));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_wrap_nhlfe_t& m) {
            archive(::cereal::make_nvp("nhlfe", m.nhlfe));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_wrap_nhlfe_t& m)
{
    serializer_class<npl_wrap_nhlfe_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_wrap_nhlfe_t&);

template <class Archive>
void
load(Archive& archive, npl_wrap_nhlfe_t& m)
{
    serializer_class<npl_wrap_nhlfe_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_wrap_nhlfe_t&);



template<>
class serializer_class<npl_ac_dlp_specific_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ac_dlp_specific_t& m) {
        uint64_t m_vlan_after_eve_format = m.vlan_after_eve_format;
        uint64_t m_mep_exists = m.mep_exists;
        uint64_t m_max_mep_level = m.max_mep_level;
            archive(::cereal::make_nvp("vlan_after_eve_format", m_vlan_after_eve_format));
            archive(::cereal::make_nvp("eve_types", m.eve_types));
            archive(::cereal::make_nvp("mep_exists", m_mep_exists));
            archive(::cereal::make_nvp("max_mep_level", m_max_mep_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ac_dlp_specific_t& m) {
        uint64_t m_vlan_after_eve_format;
        uint64_t m_mep_exists;
        uint64_t m_max_mep_level;
            archive(::cereal::make_nvp("vlan_after_eve_format", m_vlan_after_eve_format));
            archive(::cereal::make_nvp("eve_types", m.eve_types));
            archive(::cereal::make_nvp("mep_exists", m_mep_exists));
            archive(::cereal::make_nvp("max_mep_level", m_max_mep_level));
        m.vlan_after_eve_format = m_vlan_after_eve_format;
        m.mep_exists = m_mep_exists;
        m.max_mep_level = m_max_mep_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ac_dlp_specific_t& m)
{
    serializer_class<npl_ac_dlp_specific_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ac_dlp_specific_t&);

template <class Archive>
void
load(Archive& archive, npl_ac_dlp_specific_t& m)
{
    serializer_class<npl_ac_dlp_specific_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ac_dlp_specific_t&);



template<>
class serializer_class<npl_app_mc_cud_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_app_mc_cud_t& m) {
            archive(::cereal::make_nvp("npu_encap_data", m.npu_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_app_mc_cud_t& m) {
            archive(::cereal::make_nvp("npu_encap_data", m.npu_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_app_mc_cud_t& m)
{
    serializer_class<npl_app_mc_cud_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_app_mc_cud_t&);

template <class Archive>
void
load(Archive& archive, npl_app_mc_cud_t& m)
{
    serializer_class<npl_app_mc_cud_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_app_mc_cud_t&);



template<>
class serializer_class<npl_base_l3_lp_attr_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_base_l3_lp_attr_union_t& m) {
            archive(::cereal::make_nvp("update", m.update));
            archive(::cereal::make_nvp("base", m.base));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_base_l3_lp_attr_union_t& m) {
            archive(::cereal::make_nvp("update", m.update));
            archive(::cereal::make_nvp("base", m.base));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_base_l3_lp_attr_union_t& m)
{
    serializer_class<npl_base_l3_lp_attr_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_base_l3_lp_attr_union_t&);

template <class Archive>
void
load(Archive& archive, npl_base_l3_lp_attr_union_t& m)
{
    serializer_class<npl_base_l3_lp_attr_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_base_l3_lp_attr_union_t&);



template<>
class serializer_class<npl_inject_specific_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_specific_data_t& m) {
            archive(::cereal::make_nvp("inject_data", m.inject_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_specific_data_t& m) {
            archive(::cereal::make_nvp("inject_data", m.inject_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_specific_data_t& m)
{
    serializer_class<npl_inject_specific_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_specific_data_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_specific_data_t& m)
{
    serializer_class<npl_inject_specific_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_specific_data_t&);



template<>
class serializer_class<npl_ip_em_lpm_result_t_anonymous_union_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_em_lpm_result_t_anonymous_union_result_t& m) {
            archive(::cereal::make_nvp("destination_from_em", m.destination_from_em));
            archive(::cereal::make_nvp("ptr_and_l3_dlp", m.ptr_and_l3_dlp));
            archive(::cereal::make_nvp("host_and_l3_dlp", m.host_and_l3_dlp));
            archive(::cereal::make_nvp("destination_from_lpm", m.destination_from_lpm));
            archive(::cereal::make_nvp("destination_with_default", m.destination_with_default));
            archive(::cereal::make_nvp("mc_std_result", m.mc_std_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_em_lpm_result_t_anonymous_union_result_t& m) {
            archive(::cereal::make_nvp("destination_from_em", m.destination_from_em));
            archive(::cereal::make_nvp("ptr_and_l3_dlp", m.ptr_and_l3_dlp));
            archive(::cereal::make_nvp("host_and_l3_dlp", m.host_and_l3_dlp));
            archive(::cereal::make_nvp("destination_from_lpm", m.destination_from_lpm));
            archive(::cereal::make_nvp("destination_with_default", m.destination_with_default));
            archive(::cereal::make_nvp("mc_std_result", m.mc_std_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_em_lpm_result_t_anonymous_union_result_t& m)
{
    serializer_class<npl_ip_em_lpm_result_t_anonymous_union_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_em_lpm_result_t_anonymous_union_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_em_lpm_result_t_anonymous_union_result_t& m)
{
    serializer_class<npl_ip_em_lpm_result_t_anonymous_union_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_em_lpm_result_t_anonymous_union_result_t&);



template<>
class serializer_class<npl_ip_em_result_t_anonymous_union_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_em_result_t_anonymous_union_result_t& m) {
            archive(::cereal::make_nvp("em_dest", m.em_dest));
            archive(::cereal::make_nvp("ptr_and_l3_dlp", m.ptr_and_l3_dlp));
            archive(::cereal::make_nvp("dsp_host", m.dsp_host));
            archive(::cereal::make_nvp("mc_result", m.mc_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_em_result_t_anonymous_union_result_t& m) {
            archive(::cereal::make_nvp("em_dest", m.em_dest));
            archive(::cereal::make_nvp("ptr_and_l3_dlp", m.ptr_and_l3_dlp));
            archive(::cereal::make_nvp("dsp_host", m.dsp_host));
            archive(::cereal::make_nvp("mc_result", m.mc_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_em_result_t_anonymous_union_result_t& m)
{
    serializer_class<npl_ip_em_result_t_anonymous_union_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_em_result_t_anonymous_union_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_em_result_t_anonymous_union_result_t& m)
{
    serializer_class<npl_ip_em_result_t_anonymous_union_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_em_result_t_anonymous_union_result_t&);



template<>
class serializer_class<npl_ip_mc_result_em_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_result_em_payload_t& m) {
            archive(::cereal::make_nvp("raw_payload", m.raw_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_result_em_payload_t& m) {
            archive(::cereal::make_nvp("raw_payload", m.raw_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_result_em_payload_t& m)
{
    serializer_class<npl_ip_mc_result_em_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_result_em_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_result_em_payload_t& m)
{
    serializer_class<npl_ip_mc_result_em_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_result_em_payload_t&);



template<>
class serializer_class<npl_l2_dlp_specific_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_dlp_specific_t& m) {
            archive(::cereal::make_nvp("ac", m.ac));
            archive(::cereal::make_nvp("pwe", m.pwe));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_dlp_specific_t& m) {
            archive(::cereal::make_nvp("ac", m.ac));
            archive(::cereal::make_nvp("pwe", m.pwe));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_dlp_specific_t& m)
{
    serializer_class<npl_l2_dlp_specific_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_dlp_specific_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_dlp_specific_t& m)
{
    serializer_class<npl_l2_dlp_specific_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_dlp_specific_t&);



template<>
class serializer_class<npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t& m) {
            archive(::cereal::make_nvp("l3_lp", m.l3_lp));
            archive(::cereal::make_nvp("pfc", m.pfc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t& m) {
            archive(::cereal::make_nvp("l3_lp", m.l3_lp));
            archive(::cereal::make_nvp("pfc", m.pfc));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t& m)
{
    serializer_class<npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t& m)
{
    serializer_class<npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_extra_data_with_padding_t_anonymous_union_l3_punt_info_t&);



template<>
class serializer_class<npl_l3_lp_with_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_with_padding_t& m) {
            archive(::cereal::make_nvp("l3_lp", m.l3_lp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_with_padding_t& m) {
            archive(::cereal::make_nvp("l3_lp", m.l3_lp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_lp_with_padding_t& m)
{
    serializer_class<npl_l3_lp_with_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_with_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_with_padding_t& m)
{
    serializer_class<npl_l3_lp_with_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_with_padding_t&);



template<>
class serializer_class<npl_mac_lp_attributes_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_lp_attributes_payload_t& m) {
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("layer", m.layer));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_lp_attributes_payload_t& m) {
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("layer", m.layer));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_lp_attributes_payload_t& m)
{
    serializer_class<npl_mac_lp_attributes_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_lp_attributes_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_lp_attributes_payload_t& m)
{
    serializer_class<npl_mac_lp_attributes_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_lp_attributes_payload_t&);



template<>
class serializer_class<npl_mac_lp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_lp_attributes_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_lp_attributes_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_lp_attributes_t& m)
{
    serializer_class<npl_mac_lp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_lp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_lp_attributes_t& m)
{
    serializer_class<npl_mac_lp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_lp_attributes_t&);



template<>
class serializer_class<npl_mac_lp_attributes_table_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_lp_attributes_table_payload_t& m) {
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_lp_attributes_table_payload_t& m) {
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_lp_attributes_table_payload_t& m)
{
    serializer_class<npl_mac_lp_attributes_table_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_lp_attributes_table_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_lp_attributes_table_payload_t& m)
{
    serializer_class<npl_mac_lp_attributes_table_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_lp_attributes_table_payload_t&);



template<>
class serializer_class<npl_mac_relay_pack_table_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mac_relay_pack_table_payload_t& m) {
        uint64_t m_local_mapped_qos_group = m.local_mapped_qos_group;
            archive(::cereal::make_nvp("local_mapped_qos_group", m_local_mapped_qos_group));
            archive(::cereal::make_nvp("muxed_slp_info", m.muxed_slp_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mac_relay_pack_table_payload_t& m) {
        uint64_t m_local_mapped_qos_group;
            archive(::cereal::make_nvp("local_mapped_qos_group", m_local_mapped_qos_group));
            archive(::cereal::make_nvp("muxed_slp_info", m.muxed_slp_info));
        m.local_mapped_qos_group = m_local_mapped_qos_group;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mac_relay_pack_table_payload_t& m)
{
    serializer_class<npl_mac_relay_pack_table_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mac_relay_pack_table_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mac_relay_pack_table_payload_t& m)
{
    serializer_class<npl_mac_relay_pack_table_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mac_relay_pack_table_payload_t&);



template<>
class serializer_class<npl_mpls_termination_res_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_res_t& m) {
            archive(::cereal::make_nvp("result", m.result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_res_t& m) {
            archive(::cereal::make_nvp("result", m.result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_res_t& m)
{
    serializer_class<npl_mpls_termination_res_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_res_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_res_t& m)
{
    serializer_class<npl_mpls_termination_res_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_res_t&);



template<>
class serializer_class<npl_punt_app_encap_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_app_encap_t& m) {
        uint64_t m_dcf_data = m.dcf_data;
            archive(::cereal::make_nvp("punt_encap_data", m.punt_encap_data));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd", m.fabric_mc_ibm_cmd));
            archive(::cereal::make_nvp("dcf_data", m_dcf_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_app_encap_t& m) {
        uint64_t m_dcf_data;
            archive(::cereal::make_nvp("punt_encap_data", m.punt_encap_data));
            archive(::cereal::make_nvp("fabric_mc_ibm_cmd", m.fabric_mc_ibm_cmd));
            archive(::cereal::make_nvp("dcf_data", m_dcf_data));
        m.dcf_data = m_dcf_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_app_encap_t& m)
{
    serializer_class<npl_punt_app_encap_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_app_encap_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_app_encap_t& m)
{
    serializer_class<npl_punt_app_encap_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_app_encap_t&);



template<>
class serializer_class<npl_punt_header_t_anonymous_union_slp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_header_t_anonymous_union_slp_t& m) {
            archive(::cereal::make_nvp("l2_slp", m.l2_slp));
            archive(::cereal::make_nvp("l3_slp", m.l3_slp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_header_t_anonymous_union_slp_t& m) {
            archive(::cereal::make_nvp("l2_slp", m.l2_slp));
            archive(::cereal::make_nvp("l3_slp", m.l3_slp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_header_t_anonymous_union_slp_t& m)
{
    serializer_class<npl_punt_header_t_anonymous_union_slp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_header_t_anonymous_union_slp_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_header_t_anonymous_union_slp_t& m)
{
    serializer_class<npl_punt_header_t_anonymous_union_slp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_header_t_anonymous_union_slp_t&);



template<>
class serializer_class<npl_raw_ip_mc_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_raw_ip_mc_result_t& m) {
            archive(::cereal::make_nvp("result_payload", m.result_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_raw_ip_mc_result_t& m) {
            archive(::cereal::make_nvp("result_payload", m.result_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_raw_ip_mc_result_t& m)
{
    serializer_class<npl_raw_ip_mc_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_raw_ip_mc_result_t&);

template <class Archive>
void
load(Archive& archive, npl_raw_ip_mc_result_t& m)
{
    serializer_class<npl_raw_ip_mc_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_raw_ip_mc_result_t&);



template<>
class serializer_class<npl_app_mirror_cud_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_app_mirror_cud_t& m) {
            archive(::cereal::make_nvp("mirror_cud_encap", m.mirror_cud_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_app_mirror_cud_t& m) {
            archive(::cereal::make_nvp("mirror_cud_encap", m.mirror_cud_encap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_app_mirror_cud_t& m)
{
    serializer_class<npl_app_mirror_cud_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_app_mirror_cud_t&);

template <class Archive>
void
load(Archive& archive, npl_app_mirror_cud_t& m)
{
    serializer_class<npl_app_mirror_cud_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_app_mirror_cud_t&);



template<>
class serializer_class<npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t& m) {
            archive(::cereal::make_nvp("app_mc_cud", m.app_mc_cud));
            archive(::cereal::make_nvp("mirror", m.mirror));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t& m) {
            archive(::cereal::make_nvp("app_mc_cud", m.app_mc_cud));
            archive(::cereal::make_nvp("mirror", m.mirror));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t& m)
{
    serializer_class<npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t& m)
{
    serializer_class<npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t&);



template<>
class serializer_class<npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t& m) {
            archive(::cereal::make_nvp("l2_slp", m.l2_slp));
            archive(::cereal::make_nvp("l3_slp", m.l3_slp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t& m) {
            archive(::cereal::make_nvp("l2_slp", m.l2_slp));
            archive(::cereal::make_nvp("l3_slp", m.l3_slp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t& m)
{
    serializer_class<npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t& m)
{
    serializer_class<npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_slp_t&);



template<>
class serializer_class<npl_ibm_encap_header_on_direct_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_encap_header_on_direct_t& m) {
        uint64_t m_wide_bit = m.wide_bit;
            archive(::cereal::make_nvp("wide_bit", m_wide_bit));
            archive(::cereal::make_nvp("ibm_encap_header", m.ibm_encap_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_encap_header_on_direct_t& m) {
        uint64_t m_wide_bit;
            archive(::cereal::make_nvp("wide_bit", m_wide_bit));
            archive(::cereal::make_nvp("ibm_encap_header", m.ibm_encap_header));
        m.wide_bit = m_wide_bit;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_encap_header_on_direct_t& m)
{
    serializer_class<npl_ibm_encap_header_on_direct_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_encap_header_on_direct_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_encap_header_on_direct_t& m)
{
    serializer_class<npl_ibm_encap_header_on_direct_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_encap_header_on_direct_t&);



template<>
class serializer_class<npl_inject_header_app_specific_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_header_app_specific_data_t& m) {
            archive(::cereal::make_nvp("inject_specific_data", m.inject_specific_data));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_header_app_specific_data_t& m) {
            archive(::cereal::make_nvp("inject_specific_data", m.inject_specific_data));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_header_app_specific_data_t& m)
{
    serializer_class<npl_inject_header_app_specific_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_header_app_specific_data_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_header_app_specific_data_t& m)
{
    serializer_class<npl_inject_header_app_specific_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_header_app_specific_data_t&);



template<>
class serializer_class<npl_inject_header_specific_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_header_specific_data_t& m) {
            archive(::cereal::make_nvp("inject_header_app_specific_data", m.inject_header_app_specific_data));
            archive(::cereal::make_nvp("inject_header_encap_hdr_ptr", m.inject_header_encap_hdr_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_header_specific_data_t& m) {
            archive(::cereal::make_nvp("inject_header_app_specific_data", m.inject_header_app_specific_data));
            archive(::cereal::make_nvp("inject_header_encap_hdr_ptr", m.inject_header_encap_hdr_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_header_specific_data_t& m)
{
    serializer_class<npl_inject_header_specific_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_header_specific_data_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_header_specific_data_t& m)
{
    serializer_class<npl_inject_header_specific_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_header_specific_data_t&);



template<>
class serializer_class<npl_inject_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_header_t& m) {
            archive(::cereal::make_nvp("inject_header_type", m.inject_header_type));
            archive(::cereal::make_nvp("inject_header_specific_data", m.inject_header_specific_data));
            archive(::cereal::make_nvp("ts_and_cntr_stamp_cmd", m.ts_and_cntr_stamp_cmd));
            archive(::cereal::make_nvp("npl_internal_info", m.npl_internal_info));
            archive(::cereal::make_nvp("inject_header_trailer_type", m.inject_header_trailer_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_header_t& m) {
            archive(::cereal::make_nvp("inject_header_type", m.inject_header_type));
            archive(::cereal::make_nvp("inject_header_specific_data", m.inject_header_specific_data));
            archive(::cereal::make_nvp("ts_and_cntr_stamp_cmd", m.ts_and_cntr_stamp_cmd));
            archive(::cereal::make_nvp("npl_internal_info", m.npl_internal_info));
            archive(::cereal::make_nvp("inject_header_trailer_type", m.inject_header_trailer_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_header_t& m)
{
    serializer_class<npl_inject_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_header_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_header_t& m)
{
    serializer_class<npl_inject_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_header_t&);



template<>
class serializer_class<npl_inject_header_with_time_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_header_with_time_t& m) {
        uint64_t m_time_extension = m.time_extension;
            archive(::cereal::make_nvp("base_inject_header", m.base_inject_header));
            archive(::cereal::make_nvp("time_extension", m_time_extension));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_header_with_time_t& m) {
        uint64_t m_time_extension;
            archive(::cereal::make_nvp("base_inject_header", m.base_inject_header));
            archive(::cereal::make_nvp("time_extension", m_time_extension));
        m.time_extension = m_time_extension;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_header_with_time_t& m)
{
    serializer_class<npl_inject_header_with_time_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_header_with_time_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_header_with_time_t& m)
{
    serializer_class<npl_inject_header_with_time_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_header_with_time_t&);



template<>
class serializer_class<npl_inject_up_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_data_t& m) {
        uint64_t m_inject_vlan_id = m.inject_vlan_id;
            archive(::cereal::make_nvp("bfd_ih_app", m.bfd_ih_app));
            archive(::cereal::make_nvp("inject_vlan_id", m_inject_vlan_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_data_t& m) {
        uint64_t m_inject_vlan_id;
            archive(::cereal::make_nvp("bfd_ih_app", m.bfd_ih_app));
            archive(::cereal::make_nvp("inject_vlan_id", m_inject_vlan_id));
        m.inject_vlan_id = m_inject_vlan_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_data_t& m)
{
    serializer_class<npl_inject_up_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_data_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_data_t& m)
{
    serializer_class<npl_inject_up_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_data_t&);



template<>
class serializer_class<npl_ip_em_lpm_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_em_lpm_result_t& m) {
        uint64_t m_result_type = m.result_type;
        uint64_t m_no_hbm_access = m.no_hbm_access;
        uint64_t m_is_default_unused = m.is_default_unused;
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("result_type", m_result_type));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_em_lpm_result_t& m) {
        uint64_t m_result_type;
        uint64_t m_no_hbm_access;
        uint64_t m_is_default_unused;
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("result_type", m_result_type));
            archive(::cereal::make_nvp("no_hbm_access", m_no_hbm_access));
            archive(::cereal::make_nvp("is_default_unused", m_is_default_unused));
        m.result_type = m_result_type;
        m.no_hbm_access = m_no_hbm_access;
        m.is_default_unused = m_is_default_unused;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_em_lpm_result_t& m)
{
    serializer_class<npl_ip_em_lpm_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_em_lpm_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_em_lpm_result_t& m)
{
    serializer_class<npl_ip_em_lpm_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_em_lpm_result_t&);



template<>
class serializer_class<npl_ip_em_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_em_result_t& m) {
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("result_type", m.result_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_em_result_t& m) {
            archive(::cereal::make_nvp("result", m.result));
            archive(::cereal::make_nvp("result_type", m.result_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_em_result_t& m)
{
    serializer_class<npl_ip_em_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_em_result_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_em_result_t& m)
{
    serializer_class<npl_ip_em_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_em_result_t&);



template<>
class serializer_class<npl_l2_dlp_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_dlp_attributes_t& m) {
        uint64_t m_disabled = m.disabled;
        uint64_t m_stp_state_is_block = m.stp_state_is_block;
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("stp_state_is_block", m_stp_state_is_block));
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
            archive(::cereal::make_nvp("l2_dlp_specific", m.l2_dlp_specific));
            archive(::cereal::make_nvp("dlp_attributes", m.dlp_attributes));
            archive(::cereal::make_nvp("qos_attributes", m.qos_attributes));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_dlp_attributes_t& m) {
        uint64_t m_disabled;
        uint64_t m_stp_state_is_block;
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("stp_state_is_block", m_stp_state_is_block));
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
            archive(::cereal::make_nvp("l2_dlp_specific", m.l2_dlp_specific));
            archive(::cereal::make_nvp("dlp_attributes", m.dlp_attributes));
            archive(::cereal::make_nvp("qos_attributes", m.qos_attributes));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.disabled = m_disabled;
        m.stp_state_is_block = m_stp_state_is_block;
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_dlp_attributes_t& m)
{
    serializer_class<npl_l2_dlp_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_dlp_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_dlp_attributes_t& m)
{
    serializer_class<npl_l2_dlp_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_dlp_attributes_t&);



template<>
class serializer_class<npl_l3_lp_extra_data_with_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l3_lp_extra_data_with_padding_t& m) {
            archive(::cereal::make_nvp("l3_punt_info", m.l3_punt_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l3_lp_extra_data_with_padding_t& m) {
            archive(::cereal::make_nvp("l3_punt_info", m.l3_punt_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l3_lp_extra_data_with_padding_t& m)
{
    serializer_class<npl_l3_lp_extra_data_with_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l3_lp_extra_data_with_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_l3_lp_extra_data_with_padding_t& m)
{
    serializer_class<npl_l3_lp_extra_data_with_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l3_lp_extra_data_with_padding_t&);



template<>
class serializer_class<npl_pfc_mp_table_shared_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_mp_table_shared_payload_t& m) {
        uint64_t m_inject_ifg_id = m.inject_ifg_id;
        uint64_t m_profile = m.profile;
            archive(::cereal::make_nvp("inj_header", m.inj_header));
            archive(::cereal::make_nvp("inject_ifg_id", m_inject_ifg_id));
            archive(::cereal::make_nvp("profile", m_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_mp_table_shared_payload_t& m) {
        uint64_t m_inject_ifg_id;
        uint64_t m_profile;
            archive(::cereal::make_nvp("inj_header", m.inj_header));
            archive(::cereal::make_nvp("inject_ifg_id", m_inject_ifg_id));
            archive(::cereal::make_nvp("profile", m_profile));
        m.inject_ifg_id = m_inject_ifg_id;
        m.profile = m_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_mp_table_shared_payload_t& m)
{
    serializer_class<npl_pfc_mp_table_shared_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_mp_table_shared_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_mp_table_shared_payload_t& m)
{
    serializer_class<npl_pfc_mp_table_shared_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_mp_table_shared_payload_t&);



template<>
class serializer_class<npl_punt_header_t_anonymous_union_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_header_t_anonymous_union_dlp_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_header_t_anonymous_union_dlp_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_header_t_anonymous_union_dlp_t& m)
{
    serializer_class<npl_punt_header_t_anonymous_union_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_header_t_anonymous_union_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_header_t_anonymous_union_dlp_t& m)
{
    serializer_class<npl_punt_header_t_anonymous_union_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_header_t_anonymous_union_dlp_t&);



template<>
class serializer_class<npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t& m) {
            archive(::cereal::make_nvp("inject_down_data", m.inject_down_data));
            archive(::cereal::make_nvp("inject_up_data", m.inject_up_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t& m) {
            archive(::cereal::make_nvp("inject_down_data", m.inject_down_data));
            archive(::cereal::make_nvp("inject_up_data", m.inject_up_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_shared_lsb_t_anonymous_union_inject_data_t&);



template<>
class serializer_class<npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t& m) {
            archive(::cereal::make_nvp("l2_dlp", m.l2_dlp));
            archive(::cereal::make_nvp("l3_dlp", m.l3_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t& m)
{
    serializer_class<npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t& m)
{
    serializer_class<npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_dlp_and_slp_t_anonymous_union_ene_dlp_t&);



template<>
class serializer_class<npl_eth_mp_table_shared_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_mp_table_shared_payload_t& m) {
        uint64_t m_md_level = m.md_level;
        uint64_t m_ccm_period = m.ccm_period;
        uint64_t m_mep_address_lsb = m.mep_address_lsb;
        uint64_t m_per_tc_count = m.per_tc_count;
        uint64_t m_mep_address_prefix_index = m.mep_address_prefix_index;
            archive(::cereal::make_nvp("punt_code", m.punt_code));
            archive(::cereal::make_nvp("meg_id_format", m.meg_id_format));
            archive(::cereal::make_nvp("dmr_lmr_da", m.dmr_lmr_da));
            archive(::cereal::make_nvp("md_level", m_md_level));
            archive(::cereal::make_nvp("ccm_period", m_ccm_period));
            archive(::cereal::make_nvp("mep_address_lsb", m_mep_address_lsb));
            archive(::cereal::make_nvp("per_tc_count", m_per_tc_count));
            archive(::cereal::make_nvp("mep_address_prefix_index", m_mep_address_prefix_index));
            archive(::cereal::make_nvp("inject_header_data", m.inject_header_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_mp_table_shared_payload_t& m) {
        uint64_t m_md_level;
        uint64_t m_ccm_period;
        uint64_t m_mep_address_lsb;
        uint64_t m_per_tc_count;
        uint64_t m_mep_address_prefix_index;
            archive(::cereal::make_nvp("punt_code", m.punt_code));
            archive(::cereal::make_nvp("meg_id_format", m.meg_id_format));
            archive(::cereal::make_nvp("dmr_lmr_da", m.dmr_lmr_da));
            archive(::cereal::make_nvp("md_level", m_md_level));
            archive(::cereal::make_nvp("ccm_period", m_ccm_period));
            archive(::cereal::make_nvp("mep_address_lsb", m_mep_address_lsb));
            archive(::cereal::make_nvp("per_tc_count", m_per_tc_count));
            archive(::cereal::make_nvp("mep_address_prefix_index", m_mep_address_prefix_index));
            archive(::cereal::make_nvp("inject_header_data", m.inject_header_data));
        m.md_level = m_md_level;
        m.ccm_period = m_ccm_period;
        m.mep_address_lsb = m_mep_address_lsb;
        m.per_tc_count = m_per_tc_count;
        m.mep_address_prefix_index = m_mep_address_prefix_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_mp_table_shared_payload_t& m)
{
    serializer_class<npl_eth_mp_table_shared_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_mp_table_shared_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_mp_table_shared_payload_t& m)
{
    serializer_class<npl_eth_mp_table_shared_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_mp_table_shared_payload_t&);



template<>
class serializer_class<npl_punt_header_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_header_t& m) {
        uint64_t m_reserved = m.reserved;
        uint64_t m_ssp = m.ssp;
        uint64_t m_dsp = m.dsp;
        uint64_t m_time_stamp_val = m.time_stamp_val;
        uint64_t m_receive_time = m.receive_time;
            archive(::cereal::make_nvp("punt_next_header", m.punt_next_header));
            archive(::cereal::make_nvp("punt_fwd_header_type", m.punt_fwd_header_type));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("pl_header_offset", m.pl_header_offset));
            archive(::cereal::make_nvp("punt_src_and_code", m.punt_src_and_code));
            archive(::cereal::make_nvp("punt_sub_code", m.punt_sub_code));
            archive(::cereal::make_nvp("ssp", m_ssp));
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("slp", m.slp));
            archive(::cereal::make_nvp("dlp", m.dlp));
            archive(::cereal::make_nvp("punt_relay_id", m.punt_relay_id));
            archive(::cereal::make_nvp("time_stamp_val", m_time_stamp_val));
            archive(::cereal::make_nvp("receive_time", m_receive_time));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_header_t& m) {
        uint64_t m_reserved;
        uint64_t m_ssp;
        uint64_t m_dsp;
        uint64_t m_time_stamp_val;
        uint64_t m_receive_time;
            archive(::cereal::make_nvp("punt_next_header", m.punt_next_header));
            archive(::cereal::make_nvp("punt_fwd_header_type", m.punt_fwd_header_type));
            archive(::cereal::make_nvp("reserved", m_reserved));
            archive(::cereal::make_nvp("pl_header_offset", m.pl_header_offset));
            archive(::cereal::make_nvp("punt_src_and_code", m.punt_src_and_code));
            archive(::cereal::make_nvp("punt_sub_code", m.punt_sub_code));
            archive(::cereal::make_nvp("ssp", m_ssp));
            archive(::cereal::make_nvp("dsp", m_dsp));
            archive(::cereal::make_nvp("slp", m.slp));
            archive(::cereal::make_nvp("dlp", m.dlp));
            archive(::cereal::make_nvp("punt_relay_id", m.punt_relay_id));
            archive(::cereal::make_nvp("time_stamp_val", m_time_stamp_val));
            archive(::cereal::make_nvp("receive_time", m_receive_time));
        m.reserved = m_reserved;
        m.ssp = m_ssp;
        m.dsp = m_dsp;
        m.time_stamp_val = m_time_stamp_val;
        m.receive_time = m_receive_time;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_header_t& m)
{
    serializer_class<npl_punt_header_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_header_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_header_t& m)
{
    serializer_class<npl_punt_header_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_header_t&);



template<>
class serializer_class<npl_bfd_mp_table_shared_lsb_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_shared_lsb_t& m) {
        uint64_t m_inject_ifg_id = m.inject_ifg_id;
        uint64_t m_udp_checksum = m.udp_checksum;
            archive(::cereal::make_nvp("inject_ifg_id", m_inject_ifg_id));
            archive(::cereal::make_nvp("udp_checksum", m_udp_checksum));
            archive(::cereal::make_nvp("inject_data", m.inject_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_shared_lsb_t& m) {
        uint64_t m_inject_ifg_id;
        uint64_t m_udp_checksum;
            archive(::cereal::make_nvp("inject_ifg_id", m_inject_ifg_id));
            archive(::cereal::make_nvp("udp_checksum", m_udp_checksum));
            archive(::cereal::make_nvp("inject_data", m.inject_data));
        m.inject_ifg_id = m_inject_ifg_id;
        m.udp_checksum = m_udp_checksum;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_shared_lsb_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_lsb_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_shared_lsb_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_shared_lsb_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_lsb_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_shared_lsb_t&);



template<>
class serializer_class<npl_bfd_mp_table_shared_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_shared_payload_t& m) {
            archive(::cereal::make_nvp("shared_msb", m.shared_msb));
            archive(::cereal::make_nvp("shared_lsb", m.shared_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_shared_payload_t& m) {
            archive(::cereal::make_nvp("shared_msb", m.shared_msb));
            archive(::cereal::make_nvp("shared_lsb", m.shared_lsb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_shared_payload_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_shared_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_shared_payload_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_shared_payload_t&);



template<>
class serializer_class<npl_ene_punt_dlp_and_slp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_dlp_and_slp_t& m) {
            archive(::cereal::make_nvp("ene_slp", m.ene_slp));
            archive(::cereal::make_nvp("ene_dlp", m.ene_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_dlp_and_slp_t& m) {
            archive(::cereal::make_nvp("ene_slp", m.ene_slp));
            archive(::cereal::make_nvp("ene_dlp", m.ene_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_dlp_and_slp_t& m)
{
    serializer_class<npl_ene_punt_dlp_and_slp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_dlp_and_slp_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_dlp_and_slp_t& m)
{
    serializer_class<npl_ene_punt_dlp_and_slp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_dlp_and_slp_t&);



template<>
class serializer_class<npl_ene_punt_encap_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_encap_data_t& m) {
            archive(::cereal::make_nvp("ene_punt_dlp_and_slp", m.ene_punt_dlp_and_slp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_encap_data_t& m) {
            archive(::cereal::make_nvp("ene_punt_dlp_and_slp", m.ene_punt_dlp_and_slp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_encap_data_t& m)
{
    serializer_class<npl_ene_punt_encap_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_encap_data_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_encap_data_t& m)
{
    serializer_class<npl_ene_punt_encap_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_encap_data_t&);



template<>
class serializer_class<npl_eth_mp_table_app_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_mp_table_app_t& m) {
            archive(::cereal::make_nvp("transmit_a", m.transmit_a));
            archive(::cereal::make_nvp("shared", m.shared));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_mp_table_app_t& m) {
            archive(::cereal::make_nvp("transmit_a", m.transmit_a));
            archive(::cereal::make_nvp("shared", m.shared));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_mp_table_app_t& m)
{
    serializer_class<npl_eth_mp_table_app_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_mp_table_app_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_mp_table_app_t& m)
{
    serializer_class<npl_eth_mp_table_app_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_mp_table_app_t&);



template<>
class serializer_class<npl_bfd_mp_table_app_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_app_t& m) {
            archive(::cereal::make_nvp("shared", m.shared));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_app_t& m) {
            archive(::cereal::make_nvp("shared", m.shared));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_app_t& m)
{
    serializer_class<npl_bfd_mp_table_app_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_app_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_app_t& m)
{
    serializer_class<npl_bfd_mp_table_app_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_app_t&);



template<>
class serializer_class<npl_ene_punt_encap_data_and_misc_pack_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_punt_encap_data_and_misc_pack_payload_t& m) {
        uint64_t m_ene_bytes_to_remove = m.ene_bytes_to_remove;
            archive(::cereal::make_nvp("ene_bytes_to_remove", m_ene_bytes_to_remove));
            archive(::cereal::make_nvp("ene_punt_encap_data", m.ene_punt_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_punt_encap_data_and_misc_pack_payload_t& m) {
        uint64_t m_ene_bytes_to_remove;
            archive(::cereal::make_nvp("ene_bytes_to_remove", m_ene_bytes_to_remove));
            archive(::cereal::make_nvp("ene_punt_encap_data", m.ene_punt_encap_data));
        m.ene_bytes_to_remove = m_ene_bytes_to_remove;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_punt_encap_data_and_misc_pack_payload_t& m)
{
    serializer_class<npl_ene_punt_encap_data_and_misc_pack_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_punt_encap_data_and_misc_pack_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_punt_encap_data_and_misc_pack_payload_t& m)
{
    serializer_class<npl_ene_punt_encap_data_and_misc_pack_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_punt_encap_data_and_misc_pack_payload_t&);



template<>
class serializer_class<npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t& m) {
            archive(::cereal::make_nvp("eth", m.eth));
            archive(::cereal::make_nvp("bfd", m.bfd));
            archive(::cereal::make_nvp("bfd_extra", m.bfd_extra));
            archive(::cereal::make_nvp("pfc", m.pfc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t& m) {
            archive(::cereal::make_nvp("eth", m.eth));
            archive(::cereal::make_nvp("bfd", m.bfd));
            archive(::cereal::make_nvp("bfd_extra", m.bfd_extra));
            archive(::cereal::make_nvp("pfc", m.pfc));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t& m)
{
    serializer_class<npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t& m)
{
    serializer_class<npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_table_rd_app_t_anonymous_union_mp_data_union_t&);



template<>
class serializer_class<npl_mp_table_rd_app_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_table_rd_app_t& m) {
            archive(::cereal::make_nvp("mp_data_union", m.mp_data_union));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_table_rd_app_t& m) {
            archive(::cereal::make_nvp("mp_data_union", m.mp_data_union));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_table_rd_app_t& m)
{
    serializer_class<npl_mp_table_rd_app_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_table_rd_app_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_table_rd_app_t& m)
{
    serializer_class<npl_mp_table_rd_app_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_table_rd_app_t&);



template<>
class serializer_class<npl_mp_table_app_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_table_app_t& m) {
            archive(::cereal::make_nvp("mp_rd_data", m.mp_rd_data));
            archive(::cereal::make_nvp("mp_type", m.mp_type));
            archive(::cereal::make_nvp("mp2_data_union", m.mp2_data_union));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_table_app_t& m) {
            archive(::cereal::make_nvp("mp_rd_data", m.mp_rd_data));
            archive(::cereal::make_nvp("mp_type", m.mp_type));
            archive(::cereal::make_nvp("mp2_data_union", m.mp2_data_union));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_table_app_t& m)
{
    serializer_class<npl_mp_table_app_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_table_app_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_table_app_t& m)
{
    serializer_class<npl_mp_table_app_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_table_app_t&);



template<>
class serializer_class<npl_overload_union_npu_host_mp_data_t_app_defined_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_overload_union_npu_host_mp_data_t_app_defined_t& m) {
            archive(::cereal::make_nvp("app", m.app));
            archive(::cereal::make_nvp("app_defined", m.app_defined));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_overload_union_npu_host_mp_data_t_app_defined_t& m) {
            archive(::cereal::make_nvp("app", m.app));
            archive(::cereal::make_nvp("app_defined", m.app_defined));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_overload_union_npu_host_mp_data_t_app_defined_t& m)
{
    serializer_class<npl_overload_union_npu_host_mp_data_t_app_defined_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_overload_union_npu_host_mp_data_t_app_defined_t&);

template <class Archive>
void
load(Archive& archive, npl_overload_union_npu_host_mp_data_t_app_defined_t& m)
{
    serializer_class<npl_overload_union_npu_host_mp_data_t_app_defined_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_overload_union_npu_host_mp_data_t_app_defined_t&);



template<>
class serializer_class<npl_npu_host_mp_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_host_mp_data_t& m) {
            archive(::cereal::make_nvp("overload_union_app_defined", m.overload_union_app_defined));
            archive(::cereal::make_nvp("raw", m.raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_host_mp_data_t& m) {
            archive(::cereal::make_nvp("overload_union_app_defined", m.overload_union_app_defined));
            archive(::cereal::make_nvp("raw", m.raw));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_host_mp_data_t& m)
{
    serializer_class<npl_npu_host_mp_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_host_mp_data_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_host_mp_data_t& m)
{
    serializer_class<npl_npu_host_mp_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_host_mp_data_t&);



template<>
class serializer_class<npl_npu_host_mp_data_with_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npu_host_mp_data_with_padding_t& m) {
            archive(::cereal::make_nvp("host_data", m.host_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npu_host_mp_data_with_padding_t& m) {
            archive(::cereal::make_nvp("host_data", m.host_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npu_host_mp_data_with_padding_t& m)
{
    serializer_class<npl_npu_host_mp_data_with_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npu_host_mp_data_with_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_npu_host_mp_data_with_padding_t& m)
{
    serializer_class<npl_npu_host_mp_data_with_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npu_host_mp_data_with_padding_t&);



template<>
class serializer_class<npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t& m) {
            archive(::cereal::make_nvp("npu_host_mp_data", m.npu_host_mp_data));
            archive(::cereal::make_nvp("npu_host_data_res_count_phase", m.npu_host_data_res_count_phase));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t& m) {
            archive(::cereal::make_nvp("npu_host_mp_data", m.npu_host_mp_data));
            archive(::cereal::make_nvp("npu_host_data_res_count_phase", m.npu_host_data_res_count_phase));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t& m)
{
    serializer_class<npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t& m)
{
    serializer_class<npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_data_result_t_anonymous_union_npu_host_mp_data_t&);



template<>
class serializer_class<npl_mp_data_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_data_result_t& m) {
        uint64_t m_ccm_period = m.ccm_period;
        uint64_t m_dm_valid = m.dm_valid;
        uint64_t m_lm_valid = m.lm_valid;
        uint64_t m_ccm_valid = m.ccm_valid;
        uint64_t m_aux_ptr = m.aux_ptr;
        uint64_t m_mp_valid = m.mp_valid;
            archive(::cereal::make_nvp("npu_host_mp_data", m.npu_host_mp_data));
            archive(::cereal::make_nvp("ccm_period", m_ccm_period));
            archive(::cereal::make_nvp("dm_valid", m_dm_valid));
            archive(::cereal::make_nvp("lm_valid", m_lm_valid));
            archive(::cereal::make_nvp("ccm_valid", m_ccm_valid));
            archive(::cereal::make_nvp("aux_ptr", m_aux_ptr));
            archive(::cereal::make_nvp("mp_valid", m_mp_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_data_result_t& m) {
        uint64_t m_ccm_period;
        uint64_t m_dm_valid;
        uint64_t m_lm_valid;
        uint64_t m_ccm_valid;
        uint64_t m_aux_ptr;
        uint64_t m_mp_valid;
            archive(::cereal::make_nvp("npu_host_mp_data", m.npu_host_mp_data));
            archive(::cereal::make_nvp("ccm_period", m_ccm_period));
            archive(::cereal::make_nvp("dm_valid", m_dm_valid));
            archive(::cereal::make_nvp("lm_valid", m_lm_valid));
            archive(::cereal::make_nvp("ccm_valid", m_ccm_valid));
            archive(::cereal::make_nvp("aux_ptr", m_aux_ptr));
            archive(::cereal::make_nvp("mp_valid", m_mp_valid));
        m.ccm_period = m_ccm_period;
        m.dm_valid = m_dm_valid;
        m.lm_valid = m_lm_valid;
        m.ccm_valid = m_ccm_valid;
        m.aux_ptr = m_aux_ptr;
        m.mp_valid = m_mp_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_data_result_t& m)
{
    serializer_class<npl_mp_data_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_data_result_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_data_result_t& m)
{
    serializer_class<npl_mp_data_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_data_result_t&);



template<>
class serializer_class<silicon_one::table_generic_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::table_generic_entry_t& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::table_generic_entry_t& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::table_generic_entry_t& m)
{
    serializer_class<silicon_one::table_generic_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::table_generic_entry_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::table_generic_entry_t& m)
{
    serializer_class<silicon_one::table_generic_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::table_generic_entry_t&);



template<>
class serializer_class<silicon_one::ternary_table_generic_entry_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::ternary_table_generic_entry_t& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mask", m.mask));
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::ternary_table_generic_entry_t& m) {
            archive(::cereal::make_nvp("key", m.key));
            archive(::cereal::make_nvp("mask", m.mask));
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::ternary_table_generic_entry_t& m)
{
    serializer_class<silicon_one::ternary_table_generic_entry_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::ternary_table_generic_entry_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::ternary_table_generic_entry_t& m)
{
    serializer_class<silicon_one::ternary_table_generic_entry_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::ternary_table_generic_entry_t&);



template<>
class serializer_class<silicon_one::npu_features_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::npu_features_t& m) {
        uint64_t m_alternate_next_engine_bits = m.alternate_next_engine_bits;
            archive(::cereal::make_nvp("alternate_next_engine_bits", m_alternate_next_engine_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::npu_features_t& m) {
        uint64_t m_alternate_next_engine_bits;
            archive(::cereal::make_nvp("alternate_next_engine_bits", m_alternate_next_engine_bits));
        m.alternate_next_engine_bits = m_alternate_next_engine_bits;
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::npu_features_t& m)
{
    serializer_class<silicon_one::npu_features_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::npu_features_t&);

template <class Archive>
void
load(Archive& archive, silicon_one::npu_features_t& m)
{
    serializer_class<silicon_one::npu_features_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::npu_features_t&);



template<>
class serializer_class<silicon_one::nplapi_table_entry_translation> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::nplapi_table_entry_translation& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::nplapi_table_entry_translation& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::nplapi_table_entry_translation& m)
{
    serializer_class<silicon_one::nplapi_table_entry_translation>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::nplapi_table_entry_translation&);

template <class Archive>
void
load(Archive& archive, silicon_one::nplapi_table_entry_translation& m)
{
    serializer_class<silicon_one::nplapi_table_entry_translation>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::nplapi_table_entry_translation&);



template<>
class serializer_class<silicon_one::device_tables> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::device_tables& m) {
            archive(::cereal::make_nvp("acl_map_fi_header_type_to_protocol_number_table", m.acl_map_fi_header_type_to_protocol_number_table));
            archive(::cereal::make_nvp("additional_labels_table", m.additional_labels_table));
            archive(::cereal::make_nvp("all_reachable_vector", m.all_reachable_vector));
            archive(::cereal::make_nvp("bfd_desired_tx_interval_table", m.bfd_desired_tx_interval_table));
            archive(::cereal::make_nvp("bfd_detection_multiple_table", m.bfd_detection_multiple_table));
            archive(::cereal::make_nvp("bfd_event_queue_table", m.bfd_event_queue_table));
            archive(::cereal::make_nvp("bfd_inject_inner_da_high_table", m.bfd_inject_inner_da_high_table));
            archive(::cereal::make_nvp("bfd_inject_inner_da_low_table", m.bfd_inject_inner_da_low_table));
            archive(::cereal::make_nvp("bfd_inject_inner_ethernet_header_static_table", m.bfd_inject_inner_ethernet_header_static_table));
            archive(::cereal::make_nvp("bfd_inject_ttl_static_table", m.bfd_inject_ttl_static_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_A_table", m.bfd_ipv6_sip_A_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_B_table", m.bfd_ipv6_sip_B_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_C_table", m.bfd_ipv6_sip_C_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_D_table", m.bfd_ipv6_sip_D_table));
            archive(::cereal::make_nvp("bfd_punt_encap_static_table", m.bfd_punt_encap_static_table));
            archive(::cereal::make_nvp("bfd_required_tx_interval_table", m.bfd_required_tx_interval_table));
            archive(::cereal::make_nvp("bfd_rx_table", m.bfd_rx_table));
            archive(::cereal::make_nvp("bfd_set_inject_type_static_table", m.bfd_set_inject_type_static_table));
            archive(::cereal::make_nvp("bfd_udp_port_map_static_table", m.bfd_udp_port_map_static_table));
            archive(::cereal::make_nvp("bfd_udp_port_static_table", m.bfd_udp_port_static_table));
            archive(::cereal::make_nvp("bitmap_oqg_map_table", m.bitmap_oqg_map_table));
            archive(::cereal::make_nvp("bvn_tc_map_table", m.bvn_tc_map_table));
            archive(::cereal::make_nvp("calc_checksum_enable_table", m.calc_checksum_enable_table));
            archive(::cereal::make_nvp("ccm_flags_table", m.ccm_flags_table));
            archive(::cereal::make_nvp("cif2npa_c_lri_macro", m.cif2npa_c_lri_macro));
            archive(::cereal::make_nvp("cif2npa_c_mps_macro", m.cif2npa_c_mps_macro));
            archive(::cereal::make_nvp("counters_block_config_table", m.counters_block_config_table));
            archive(::cereal::make_nvp("counters_voq_block_map_table", m.counters_voq_block_map_table));
            archive(::cereal::make_nvp("cud_is_multicast_bitmap", m.cud_is_multicast_bitmap));
            archive(::cereal::make_nvp("cud_narrow_hw_table", m.cud_narrow_hw_table));
            archive(::cereal::make_nvp("cud_wide_hw_table", m.cud_wide_hw_table));
            archive(::cereal::make_nvp("default_egress_ipv4_sec_acl_table", m.default_egress_ipv4_sec_acl_table));
            archive(::cereal::make_nvp("default_egress_ipv6_acl_sec_table", m.default_egress_ipv6_acl_sec_table));
            archive(::cereal::make_nvp("destination_decoding_table", m.destination_decoding_table));
            archive(::cereal::make_nvp("device_mode_table", m.device_mode_table));
            archive(::cereal::make_nvp("dsp_l2_attributes_table", m.dsp_l2_attributes_table));
            archive(::cereal::make_nvp("dsp_l3_attributes_table", m.dsp_l3_attributes_table));
            archive(::cereal::make_nvp("dummy_dip_index_table", m.dummy_dip_index_table));
            archive(::cereal::make_nvp("ecn_remark_static_table", m.ecn_remark_static_table));
            archive(::cereal::make_nvp("egress_mac_ipv4_sec_acl_table", m.egress_mac_ipv4_sec_acl_table));
            archive(::cereal::make_nvp("egress_nh_and_svi_direct0_table", m.egress_nh_and_svi_direct0_table));
            archive(::cereal::make_nvp("egress_nh_and_svi_direct1_table", m.egress_nh_and_svi_direct1_table));
            archive(::cereal::make_nvp("em_mp_table", m.em_mp_table));
            archive(::cereal::make_nvp("em_pfc_cong_table", m.em_pfc_cong_table));
            archive(::cereal::make_nvp("ene_byte_addition_static_table", m.ene_byte_addition_static_table));
            archive(::cereal::make_nvp("ene_macro_code_tpid_profile_static_table", m.ene_macro_code_tpid_profile_static_table));
            archive(::cereal::make_nvp("erpp_fabric_counters_offset_table", m.erpp_fabric_counters_offset_table));
            archive(::cereal::make_nvp("erpp_fabric_counters_table", m.erpp_fabric_counters_table));
            archive(::cereal::make_nvp("eth_meter_profile_mapping_table", m.eth_meter_profile_mapping_table));
            archive(::cereal::make_nvp("eth_oam_set_da_mc2_static_table", m.eth_oam_set_da_mc2_static_table));
            archive(::cereal::make_nvp("eth_oam_set_da_mc_static_table", m.eth_oam_set_da_mc_static_table));
            archive(::cereal::make_nvp("eth_rtf_conf_set_mapping_table", m.eth_rtf_conf_set_mapping_table));
            archive(::cereal::make_nvp("eve_byte_addition_static_table", m.eve_byte_addition_static_table));
            archive(::cereal::make_nvp("eve_to_ethernet_ene_static_table", m.eve_to_ethernet_ene_static_table));
            archive(::cereal::make_nvp("event_queue_table", m.event_queue_table));
            archive(::cereal::make_nvp("external_aux_table", m.external_aux_table));
            archive(::cereal::make_nvp("fabric_and_tm_header_size_static_table", m.fabric_and_tm_header_size_static_table));
            archive(::cereal::make_nvp("fabric_header_ene_macro_table", m.fabric_header_ene_macro_table));
            archive(::cereal::make_nvp("fabric_header_types_static_table", m.fabric_header_types_static_table));
            archive(::cereal::make_nvp("fabric_headers_type_table", m.fabric_headers_type_table));
            archive(::cereal::make_nvp("fabric_init_cfg", m.fabric_init_cfg));
            archive(::cereal::make_nvp("fabric_npuh_size_calculation_static_table", m.fabric_npuh_size_calculation_static_table));
            archive(::cereal::make_nvp("fabric_out_color_map_table", m.fabric_out_color_map_table));
            archive(::cereal::make_nvp("fabric_rx_fwd_error_handling_counter_table", m.fabric_rx_fwd_error_handling_counter_table));
            archive(::cereal::make_nvp("fabric_rx_fwd_error_handling_destination_table", m.fabric_rx_fwd_error_handling_destination_table));
            archive(::cereal::make_nvp("fabric_rx_term_error_handling_counter_table", m.fabric_rx_term_error_handling_counter_table));
            archive(::cereal::make_nvp("fabric_rx_term_error_handling_destination_table", m.fabric_rx_term_error_handling_destination_table));
            archive(::cereal::make_nvp("fabric_scaled_mc_map_to_netork_slice_static_table", m.fabric_scaled_mc_map_to_netork_slice_static_table));
            archive(::cereal::make_nvp("fabric_smcid_threshold_table", m.fabric_smcid_threshold_table));
            archive(::cereal::make_nvp("fabric_term_error_checker_static_table", m.fabric_term_error_checker_static_table));
            archive(::cereal::make_nvp("fabric_tm_headers_table", m.fabric_tm_headers_table));
            archive(::cereal::make_nvp("fabric_transmit_error_checker_static_table", m.fabric_transmit_error_checker_static_table));
            archive(::cereal::make_nvp("fe_broadcast_bmp_table", m.fe_broadcast_bmp_table));
            archive(::cereal::make_nvp("fe_smcid_threshold_table", m.fe_smcid_threshold_table));
            archive(::cereal::make_nvp("fe_smcid_to_mcid_table", m.fe_smcid_to_mcid_table));
            archive(::cereal::make_nvp("fi_core_tcam_table", m.fi_core_tcam_table));
            archive(::cereal::make_nvp("fi_macro_config_table", m.fi_macro_config_table));
            archive(::cereal::make_nvp("filb_voq_mapping", m.filb_voq_mapping));
            archive(::cereal::make_nvp("first_ene_static_table", m.first_ene_static_table));
            archive(::cereal::make_nvp("frm_db_fabric_routing_table", m.frm_db_fabric_routing_table));
            archive(::cereal::make_nvp("fwd_destination_to_tm_result_data", m.fwd_destination_to_tm_result_data));
            archive(::cereal::make_nvp("fwd_type_to_ive_enable_table", m.fwd_type_to_ive_enable_table));
            archive(::cereal::make_nvp("get_ecm_meter_ptr_table", m.get_ecm_meter_ptr_table));
            archive(::cereal::make_nvp("get_ingress_ptp_info_and_is_slp_dm_static_table", m.get_ingress_ptp_info_and_is_slp_dm_static_table));
            archive(::cereal::make_nvp("get_l2_rtf_conf_set_and_init_stages", m.get_l2_rtf_conf_set_and_init_stages));
            archive(::cereal::make_nvp("get_non_comp_mc_value_static_table", m.get_non_comp_mc_value_static_table));
            archive(::cereal::make_nvp("gre_proto_static_table", m.gre_proto_static_table));
            archive(::cereal::make_nvp("hmc_cgm_cgm_lut_table", m.hmc_cgm_cgm_lut_table));
            archive(::cereal::make_nvp("hmc_cgm_profile_global_table", m.hmc_cgm_profile_global_table));
            archive(::cereal::make_nvp("ibm_cmd_table", m.ibm_cmd_table));
            archive(::cereal::make_nvp("ibm_mc_cmd_to_encap_data_table", m.ibm_mc_cmd_to_encap_data_table));
            archive(::cereal::make_nvp("ibm_uc_cmd_to_encap_data_table", m.ibm_uc_cmd_to_encap_data_table));
            archive(::cereal::make_nvp("ifgb_tc_lut_table", m.ifgb_tc_lut_table));
            archive(::cereal::make_nvp("ingress_ip_qos_mapping_table", m.ingress_ip_qos_mapping_table));
            archive(::cereal::make_nvp("ingress_rtf_eth_db1_160_f0_table", m.ingress_rtf_eth_db1_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_eth_db2_160_f0_table", m.ingress_rtf_eth_db2_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db1_160_f0_table", m.ingress_rtf_ipv4_db1_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db1_160_f1_table", m.ingress_rtf_ipv4_db1_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db1_320_f0_table", m.ingress_rtf_ipv4_db1_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db2_160_f0_table", m.ingress_rtf_ipv4_db2_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db2_160_f1_table", m.ingress_rtf_ipv4_db2_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db2_320_f0_table", m.ingress_rtf_ipv4_db2_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db3_160_f0_table", m.ingress_rtf_ipv4_db3_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db3_160_f1_table", m.ingress_rtf_ipv4_db3_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db3_320_f0_table", m.ingress_rtf_ipv4_db3_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db4_160_f0_table", m.ingress_rtf_ipv4_db4_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db4_160_f1_table", m.ingress_rtf_ipv4_db4_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db4_320_f0_table", m.ingress_rtf_ipv4_db4_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db1_160_f0_table", m.ingress_rtf_ipv6_db1_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db1_160_f1_table", m.ingress_rtf_ipv6_db1_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db1_320_f0_table", m.ingress_rtf_ipv6_db1_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db2_160_f0_table", m.ingress_rtf_ipv6_db2_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db2_160_f1_table", m.ingress_rtf_ipv6_db2_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db2_320_f0_table", m.ingress_rtf_ipv6_db2_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db3_160_f0_table", m.ingress_rtf_ipv6_db3_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db3_160_f1_table", m.ingress_rtf_ipv6_db3_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db3_320_f0_table", m.ingress_rtf_ipv6_db3_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db4_160_f0_table", m.ingress_rtf_ipv6_db4_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db4_160_f1_table", m.ingress_rtf_ipv6_db4_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db4_320_f0_table", m.ingress_rtf_ipv6_db4_320_f0_table));
            archive(::cereal::make_nvp("inject_down_select_ene_static_table", m.inject_down_select_ene_static_table));
            archive(::cereal::make_nvp("inject_down_tx_redirect_counter_table", m.inject_down_tx_redirect_counter_table));
            archive(::cereal::make_nvp("inject_up_pif_ifg_init_data_table", m.inject_up_pif_ifg_init_data_table));
            archive(::cereal::make_nvp("inject_up_ssp_init_data_table", m.inject_up_ssp_init_data_table));
            archive(::cereal::make_nvp("inner_tpid_table", m.inner_tpid_table));
            archive(::cereal::make_nvp("ip_fwd_header_mapping_to_ethtype_static_table", m.ip_fwd_header_mapping_to_ethtype_static_table));
            archive(::cereal::make_nvp("ip_ingress_cmp_mcid_static_table", m.ip_ingress_cmp_mcid_static_table));
            archive(::cereal::make_nvp("ip_mc_local_inject_type_static_table", m.ip_mc_local_inject_type_static_table));
            archive(::cereal::make_nvp("ip_mc_next_macro_static_table", m.ip_mc_next_macro_static_table));
            archive(::cereal::make_nvp("ip_meter_profile_mapping_table", m.ip_meter_profile_mapping_table));
            archive(::cereal::make_nvp("ip_prefix_destination_table", m.ip_prefix_destination_table));
            archive(::cereal::make_nvp("ip_relay_to_vni_table", m.ip_relay_to_vni_table));
            archive(::cereal::make_nvp("ip_rx_global_counter_table", m.ip_rx_global_counter_table));
            archive(::cereal::make_nvp("ip_ver_mc_static_table", m.ip_ver_mc_static_table));
            archive(::cereal::make_nvp("ipv4_acl_map_protocol_type_to_protocol_number_table", m.ipv4_acl_map_protocol_type_to_protocol_number_table));
            archive(::cereal::make_nvp("ipv4_acl_sport_static_table", m.ipv4_acl_sport_static_table));
            archive(::cereal::make_nvp("ipv4_ip_tunnel_termination_dip_index_tt0_table", m.ipv4_ip_tunnel_termination_dip_index_tt0_table));
            archive(::cereal::make_nvp("ipv4_ip_tunnel_termination_sip_dip_index_tt0_table", m.ipv4_ip_tunnel_termination_sip_dip_index_tt0_table));
            archive(::cereal::make_nvp("ipv4_ip_tunnel_termination_sip_dip_index_tt1_table", m.ipv4_ip_tunnel_termination_sip_dip_index_tt1_table));
            archive(::cereal::make_nvp("ipv4_lpm_table", m.ipv4_lpm_table));
            archive(::cereal::make_nvp("ipv4_lpts_table", m.ipv4_lpts_table));
            archive(::cereal::make_nvp("ipv4_og_pcl_em_table", m.ipv4_og_pcl_em_table));
            archive(::cereal::make_nvp("ipv4_og_pcl_lpm_table", m.ipv4_og_pcl_lpm_table));
            archive(::cereal::make_nvp("ipv4_rtf_conf_set_mapping_table", m.ipv4_rtf_conf_set_mapping_table));
            archive(::cereal::make_nvp("ipv4_vrf_dip_em_table", m.ipv4_vrf_dip_em_table));
            archive(::cereal::make_nvp("ipv4_vrf_s_g_table", m.ipv4_vrf_s_g_table));
            archive(::cereal::make_nvp("ipv6_acl_sport_static_table", m.ipv6_acl_sport_static_table));
            archive(::cereal::make_nvp("ipv6_first_fragment_static_table", m.ipv6_first_fragment_static_table));
            archive(::cereal::make_nvp("ipv6_lpm_table", m.ipv6_lpm_table));
            archive(::cereal::make_nvp("ipv6_lpts_table", m.ipv6_lpts_table));
            archive(::cereal::make_nvp("ipv6_mc_select_qos_id", m.ipv6_mc_select_qos_id));
            archive(::cereal::make_nvp("ipv6_og_pcl_em_table", m.ipv6_og_pcl_em_table));
            archive(::cereal::make_nvp("ipv6_og_pcl_lpm_table", m.ipv6_og_pcl_lpm_table));
            archive(::cereal::make_nvp("ipv6_rtf_conf_set_mapping_table", m.ipv6_rtf_conf_set_mapping_table));
            archive(::cereal::make_nvp("ipv6_sip_compression_table", m.ipv6_sip_compression_table));
            archive(::cereal::make_nvp("ipv6_vrf_dip_em_table", m.ipv6_vrf_dip_em_table));
            archive(::cereal::make_nvp("ipv6_vrf_s_g_table", m.ipv6_vrf_s_g_table));
            archive(::cereal::make_nvp("is_pacific_b1_static_table", m.is_pacific_b1_static_table));
            archive(::cereal::make_nvp("l2_dlp_table", m.l2_dlp_table));
            archive(::cereal::make_nvp("l2_lp_profile_filter_table", m.l2_lp_profile_filter_table));
            archive(::cereal::make_nvp("l2_lpts_ctrl_fields_static_table", m.l2_lpts_ctrl_fields_static_table));
            archive(::cereal::make_nvp("l2_lpts_ip_fragment_static_table", m.l2_lpts_ip_fragment_static_table));
            archive(::cereal::make_nvp("l2_lpts_ipv4_table", m.l2_lpts_ipv4_table));
            archive(::cereal::make_nvp("l2_lpts_ipv6_table", m.l2_lpts_ipv6_table));
            archive(::cereal::make_nvp("l2_lpts_mac_table", m.l2_lpts_mac_table));
            archive(::cereal::make_nvp("l2_lpts_next_macro_static_table", m.l2_lpts_next_macro_static_table));
            archive(::cereal::make_nvp("l2_lpts_protocol_table", m.l2_lpts_protocol_table));
            archive(::cereal::make_nvp("l2_lpts_skip_p2p_static_table", m.l2_lpts_skip_p2p_static_table));
            archive(::cereal::make_nvp("l2_termination_next_macro_static_table", m.l2_termination_next_macro_static_table));
            archive(::cereal::make_nvp("l2_tunnel_term_next_macro_static_table", m.l2_tunnel_term_next_macro_static_table));
            archive(::cereal::make_nvp("l3_dlp_p_counter_offset_table", m.l3_dlp_p_counter_offset_table));
            archive(::cereal::make_nvp("l3_dlp_table", m.l3_dlp_table));
            archive(::cereal::make_nvp("l3_termination_classify_ip_tunnels_table", m.l3_termination_classify_ip_tunnels_table));
            archive(::cereal::make_nvp("l3_termination_next_macro_static_table", m.l3_termination_next_macro_static_table));
            archive(::cereal::make_nvp("l3_tunnel_termination_next_macro_static_table", m.l3_tunnel_termination_next_macro_static_table));
            archive(::cereal::make_nvp("l3_vxlan_overlay_sa_table", m.l3_vxlan_overlay_sa_table));
            archive(::cereal::make_nvp("large_encap_global_lsp_prefix_table", m.large_encap_global_lsp_prefix_table));
            archive(::cereal::make_nvp("large_encap_ip_tunnel_table", m.large_encap_ip_tunnel_table));
            archive(::cereal::make_nvp("large_encap_mpls_he_no_ldp_table", m.large_encap_mpls_he_no_ldp_table));
            archive(::cereal::make_nvp("large_encap_mpls_ldp_over_te_table", m.large_encap_mpls_ldp_over_te_table));
            archive(::cereal::make_nvp("large_encap_te_he_tunnel_id_table", m.large_encap_te_he_tunnel_id_table));
            archive(::cereal::make_nvp("learn_manager_cfg_max_learn_type_reg", m.learn_manager_cfg_max_learn_type_reg));
            archive(::cereal::make_nvp("light_fi_fabric_table", m.light_fi_fabric_table));
            archive(::cereal::make_nvp("light_fi_npu_base_table", m.light_fi_npu_base_table));
            archive(::cereal::make_nvp("light_fi_npu_encap_table", m.light_fi_npu_encap_table));
            archive(::cereal::make_nvp("light_fi_nw_0_table", m.light_fi_nw_0_table));
            archive(::cereal::make_nvp("light_fi_nw_1_table", m.light_fi_nw_1_table));
            archive(::cereal::make_nvp("light_fi_nw_2_table", m.light_fi_nw_2_table));
            archive(::cereal::make_nvp("light_fi_nw_3_table", m.light_fi_nw_3_table));
            archive(::cereal::make_nvp("light_fi_stages_cfg_table", m.light_fi_stages_cfg_table));
            archive(::cereal::make_nvp("light_fi_tm_table", m.light_fi_tm_table));
            archive(::cereal::make_nvp("link_relay_attributes_table", m.link_relay_attributes_table));
            archive(::cereal::make_nvp("link_up_vector", m.link_up_vector));
            archive(::cereal::make_nvp("lp_over_lag_table", m.lp_over_lag_table));
            archive(::cereal::make_nvp("lpm_destination_prefix_map_table", m.lpm_destination_prefix_map_table));
            archive(::cereal::make_nvp("lpts_2nd_lookup_table", m.lpts_2nd_lookup_table));
            archive(::cereal::make_nvp("lpts_meter_table", m.lpts_meter_table));
            archive(::cereal::make_nvp("lpts_og_application_table", m.lpts_og_application_table));
            archive(::cereal::make_nvp("mac_af_npp_attributes_table", m.mac_af_npp_attributes_table));
            archive(::cereal::make_nvp("mac_da_table", m.mac_da_table));
            archive(::cereal::make_nvp("mac_ethernet_rate_limit_type_static_table", m.mac_ethernet_rate_limit_type_static_table));
            archive(::cereal::make_nvp("mac_forwarding_table", m.mac_forwarding_table));
            archive(::cereal::make_nvp("mac_mc_em_termination_attributes_table", m.mac_mc_em_termination_attributes_table));
            archive(::cereal::make_nvp("mac_mc_tcam_termination_attributes_table", m.mac_mc_tcam_termination_attributes_table));
            archive(::cereal::make_nvp("mac_qos_mapping_table", m.mac_qos_mapping_table));
            archive(::cereal::make_nvp("mac_relay_g_ipv4_table", m.mac_relay_g_ipv4_table));
            archive(::cereal::make_nvp("mac_relay_g_ipv6_table", m.mac_relay_g_ipv6_table));
            archive(::cereal::make_nvp("mac_relay_to_vni_table", m.mac_relay_to_vni_table));
            archive(::cereal::make_nvp("mac_termination_em_table", m.mac_termination_em_table));
            archive(::cereal::make_nvp("mac_termination_next_macro_static_table", m.mac_termination_next_macro_static_table));
            archive(::cereal::make_nvp("mac_termination_no_da_em_table", m.mac_termination_no_da_em_table));
            archive(::cereal::make_nvp("mac_termination_tcam_table", m.mac_termination_tcam_table));
            archive(::cereal::make_nvp("map_ene_subcode_to8bit_static_table", m.map_ene_subcode_to8bit_static_table));
            archive(::cereal::make_nvp("map_inject_ccm_macro_static_table", m.map_inject_ccm_macro_static_table));
            archive(::cereal::make_nvp("map_more_labels_static_table", m.map_more_labels_static_table));
            archive(::cereal::make_nvp("map_recyle_tx_to_rx_data_on_pd_static_table", m.map_recyle_tx_to_rx_data_on_pd_static_table));
            archive(::cereal::make_nvp("map_tm_dp_ecn_to_wa_ecn_dp_static_table", m.map_tm_dp_ecn_to_wa_ecn_dp_static_table));
            archive(::cereal::make_nvp("map_tx_punt_next_macro_static_table", m.map_tx_punt_next_macro_static_table));
            archive(::cereal::make_nvp("map_tx_punt_rcy_next_macro_static_table", m.map_tx_punt_rcy_next_macro_static_table));
            archive(::cereal::make_nvp("mc_bitmap_base_voq_lookup_table", m.mc_bitmap_base_voq_lookup_table));
            archive(::cereal::make_nvp("mc_bitmap_tc_map_table", m.mc_bitmap_tc_map_table));
            archive(::cereal::make_nvp("mc_copy_id_map", m.mc_copy_id_map));
            archive(::cereal::make_nvp("mc_cud_is_wide_table", m.mc_cud_is_wide_table));
            archive(::cereal::make_nvp("mc_em_db", m.mc_em_db));
            archive(::cereal::make_nvp("mc_emdb_tc_map_table", m.mc_emdb_tc_map_table));
            archive(::cereal::make_nvp("mc_fe_links_bmp", m.mc_fe_links_bmp));
            archive(::cereal::make_nvp("mc_ibm_cud_mapping_table", m.mc_ibm_cud_mapping_table));
            archive(::cereal::make_nvp("mc_slice_bitmap_table", m.mc_slice_bitmap_table));
            archive(::cereal::make_nvp("meg_id_format_table", m.meg_id_format_table));
            archive(::cereal::make_nvp("mep_address_prefix_table", m.mep_address_prefix_table));
            archive(::cereal::make_nvp("mii_loopback_table", m.mii_loopback_table));
            archive(::cereal::make_nvp("mirror_code_hw_table", m.mirror_code_hw_table));
            archive(::cereal::make_nvp("mirror_egress_attributes_table", m.mirror_egress_attributes_table));
            archive(::cereal::make_nvp("mirror_to_dsp_in_npu_soft_header_table", m.mirror_to_dsp_in_npu_soft_header_table));
            archive(::cereal::make_nvp("mldp_protection_enabled_static_table", m.mldp_protection_enabled_static_table));
            archive(::cereal::make_nvp("mldp_protection_table", m.mldp_protection_table));
            archive(::cereal::make_nvp("mp_aux_data_table", m.mp_aux_data_table));
            archive(::cereal::make_nvp("mp_data_table", m.mp_data_table));
            archive(::cereal::make_nvp("mpls_encap_control_static_table", m.mpls_encap_control_static_table));
            archive(::cereal::make_nvp("mpls_forwarding_table", m.mpls_forwarding_table));
            archive(::cereal::make_nvp("mpls_header_offset_in_bytes_static_table", m.mpls_header_offset_in_bytes_static_table));
            archive(::cereal::make_nvp("mpls_l3_lsp_static_table", m.mpls_l3_lsp_static_table));
            archive(::cereal::make_nvp("mpls_labels_1_to_4_jump_offset_static_table", m.mpls_labels_1_to_4_jump_offset_static_table));
            archive(::cereal::make_nvp("mpls_lsp_labels_config_static_table", m.mpls_lsp_labels_config_static_table));
            archive(::cereal::make_nvp("mpls_qos_mapping_table", m.mpls_qos_mapping_table));
            archive(::cereal::make_nvp("mpls_resolve_service_labels_static_table", m.mpls_resolve_service_labels_static_table));
            archive(::cereal::make_nvp("mpls_termination_em0_table", m.mpls_termination_em0_table));
            archive(::cereal::make_nvp("mpls_termination_em1_table", m.mpls_termination_em1_table));
            archive(::cereal::make_nvp("mpls_vpn_enabled_static_table", m.mpls_vpn_enabled_static_table));
            archive(::cereal::make_nvp("my_ipv4_table", m.my_ipv4_table));
            archive(::cereal::make_nvp("native_ce_ptr_table", m.native_ce_ptr_table));
            archive(::cereal::make_nvp("native_fec_table", m.native_fec_table));
            archive(::cereal::make_nvp("native_fec_type_decoding_table", m.native_fec_type_decoding_table));
            archive(::cereal::make_nvp("native_frr_table", m.native_frr_table));
            archive(::cereal::make_nvp("native_frr_type_decoding_table", m.native_frr_type_decoding_table));
            archive(::cereal::make_nvp("native_l2_lp_table", m.native_l2_lp_table));
            archive(::cereal::make_nvp("native_l2_lp_type_decoding_table", m.native_l2_lp_type_decoding_table));
            archive(::cereal::make_nvp("native_lb_group_size_table", m.native_lb_group_size_table));
            archive(::cereal::make_nvp("native_lb_table", m.native_lb_table));
            archive(::cereal::make_nvp("native_lb_type_decoding_table", m.native_lb_type_decoding_table));
            archive(::cereal::make_nvp("native_lp_is_pbts_prefix_table", m.native_lp_is_pbts_prefix_table));
            archive(::cereal::make_nvp("native_lp_pbts_map_table", m.native_lp_pbts_map_table));
            archive(::cereal::make_nvp("native_protection_table", m.native_protection_table));
            archive(::cereal::make_nvp("next_header_1_is_l4_over_ipv4_static_table", m.next_header_1_is_l4_over_ipv4_static_table));
            archive(::cereal::make_nvp("nh_macro_code_to_id_l6_static_table", m.nh_macro_code_to_id_l6_static_table));
            archive(::cereal::make_nvp("nhlfe_type_mapping_static_table", m.nhlfe_type_mapping_static_table));
            archive(::cereal::make_nvp("null_rtf_next_macro_static_table", m.null_rtf_next_macro_static_table));
            archive(::cereal::make_nvp("nw_smcid_threshold_table", m.nw_smcid_threshold_table));
            archive(::cereal::make_nvp("oamp_drop_destination_static_table", m.oamp_drop_destination_static_table));
            archive(::cereal::make_nvp("oamp_event_queue_table", m.oamp_event_queue_table));
            archive(::cereal::make_nvp("oamp_redirect_get_counter_table", m.oamp_redirect_get_counter_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_1_table", m.oamp_redirect_punt_eth_hdr_1_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_2_table", m.oamp_redirect_punt_eth_hdr_2_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_3_table", m.oamp_redirect_punt_eth_hdr_3_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_4_table", m.oamp_redirect_punt_eth_hdr_4_table));
            archive(::cereal::make_nvp("oamp_redirect_table", m.oamp_redirect_table));
            archive(::cereal::make_nvp("obm_next_macro_static_table", m.obm_next_macro_static_table));
            archive(::cereal::make_nvp("og_next_macro_static_table", m.og_next_macro_static_table));
            archive(::cereal::make_nvp("outer_tpid_table", m.outer_tpid_table));
            archive(::cereal::make_nvp("overlay_ipv4_sip_table", m.overlay_ipv4_sip_table));
            archive(::cereal::make_nvp("pad_mtu_inj_check_static_table", m.pad_mtu_inj_check_static_table));
            archive(::cereal::make_nvp("path_lb_type_decoding_table", m.path_lb_type_decoding_table));
            archive(::cereal::make_nvp("path_lp_is_pbts_prefix_table", m.path_lp_is_pbts_prefix_table));
            archive(::cereal::make_nvp("path_lp_pbts_map_table", m.path_lp_pbts_map_table));
            archive(::cereal::make_nvp("path_lp_table", m.path_lp_table));
            archive(::cereal::make_nvp("path_lp_type_decoding_table", m.path_lp_type_decoding_table));
            archive(::cereal::make_nvp("path_protection_table", m.path_protection_table));
            archive(::cereal::make_nvp("pdoq_oq_ifc_mapping", m.pdoq_oq_ifc_mapping));
            archive(::cereal::make_nvp("pdvoq_slice_voq_properties_table", m.pdvoq_slice_voq_properties_table));
            archive(::cereal::make_nvp("per_asbr_and_dpe_table", m.per_asbr_and_dpe_table));
            archive(::cereal::make_nvp("per_pe_and_prefix_vpn_key_large_table", m.per_pe_and_prefix_vpn_key_large_table));
            archive(::cereal::make_nvp("per_pe_and_vrf_vpn_key_large_table", m.per_pe_and_vrf_vpn_key_large_table));
            archive(::cereal::make_nvp("per_port_destination_table", m.per_port_destination_table));
            archive(::cereal::make_nvp("per_vrf_mpls_forwarding_table", m.per_vrf_mpls_forwarding_table));
            archive(::cereal::make_nvp("pfc_destination_table", m.pfc_destination_table));
            archive(::cereal::make_nvp("pfc_event_queue_table", m.pfc_event_queue_table));
            archive(::cereal::make_nvp("pfc_filter_wd_table", m.pfc_filter_wd_table));
            archive(::cereal::make_nvp("pfc_offset_from_vector_static_table", m.pfc_offset_from_vector_static_table));
            archive(::cereal::make_nvp("pfc_ssp_slice_map_table", m.pfc_ssp_slice_map_table));
            archive(::cereal::make_nvp("pfc_tc_latency_table", m.pfc_tc_latency_table));
            archive(::cereal::make_nvp("pfc_tc_table", m.pfc_tc_table));
            archive(::cereal::make_nvp("pfc_tc_wrap_latency_table", m.pfc_tc_wrap_latency_table));
            archive(::cereal::make_nvp("pfc_vector_static_table", m.pfc_vector_static_table));
            archive(::cereal::make_nvp("pin_start_offset_macros", m.pin_start_offset_macros));
            archive(::cereal::make_nvp("pma_loopback_table", m.pma_loopback_table));
            archive(::cereal::make_nvp("port_dspa_group_size_table", m.port_dspa_group_size_table));
            archive(::cereal::make_nvp("port_dspa_table", m.port_dspa_table));
            archive(::cereal::make_nvp("port_dspa_type_decoding_table", m.port_dspa_type_decoding_table));
            archive(::cereal::make_nvp("port_npp_protection_table", m.port_npp_protection_table));
            archive(::cereal::make_nvp("port_npp_protection_type_decoding_table", m.port_npp_protection_type_decoding_table));
            archive(::cereal::make_nvp("port_protection_table", m.port_protection_table));
            archive(::cereal::make_nvp("punt_ethertype_static_table", m.punt_ethertype_static_table));
            archive(::cereal::make_nvp("punt_rcy_inject_header_ene_encap_table", m.punt_rcy_inject_header_ene_encap_table));
            archive(::cereal::make_nvp("punt_select_nw_ene_static_table", m.punt_select_nw_ene_static_table));
            archive(::cereal::make_nvp("punt_tunnel_transport_encap_table", m.punt_tunnel_transport_encap_table));
            archive(::cereal::make_nvp("punt_tunnel_transport_extended_encap_table", m.punt_tunnel_transport_extended_encap_table));
            archive(::cereal::make_nvp("punt_tunnel_transport_extended_encap_table2", m.punt_tunnel_transport_extended_encap_table2));
            archive(::cereal::make_nvp("pwe_label_table", m.pwe_label_table));
            archive(::cereal::make_nvp("pwe_to_l3_dest_table", m.pwe_to_l3_dest_table));
            archive(::cereal::make_nvp("pwe_vpls_label_table", m.pwe_vpls_label_table));
            archive(::cereal::make_nvp("pwe_vpls_tunnel_label_table", m.pwe_vpls_tunnel_label_table));
            archive(::cereal::make_nvp("reassembly_source_port_map_table", m.reassembly_source_port_map_table));
            archive(::cereal::make_nvp("recycle_override_table", m.recycle_override_table));
            archive(::cereal::make_nvp("recycled_inject_up_info_table", m.recycled_inject_up_info_table));
            archive(::cereal::make_nvp("redirect_destination_table", m.redirect_destination_table));
            archive(::cereal::make_nvp("redirect_table", m.redirect_table));
            archive(::cereal::make_nvp("resolution_pfc_select_table", m.resolution_pfc_select_table));
            archive(::cereal::make_nvp("resolution_set_next_macro_table", m.resolution_set_next_macro_table));
            archive(::cereal::make_nvp("rewrite_sa_prefix_index_table", m.rewrite_sa_prefix_index_table));
            archive(::cereal::make_nvp("rmep_last_time_table", m.rmep_last_time_table));
            archive(::cereal::make_nvp("rmep_state_table", m.rmep_state_table));
            archive(::cereal::make_nvp("rpf_fec_access_map_table", m.rpf_fec_access_map_table));
            archive(::cereal::make_nvp("rpf_fec_table", m.rpf_fec_table));
            archive(::cereal::make_nvp("rtf_conf_set_to_og_pcl_compress_bits_mapping_table", m.rtf_conf_set_to_og_pcl_compress_bits_mapping_table));
            archive(::cereal::make_nvp("rtf_conf_set_to_og_pcl_ids_mapping_table", m.rtf_conf_set_to_og_pcl_ids_mapping_table));
            archive(::cereal::make_nvp("rtf_conf_set_to_post_fwd_stage_mapping_table", m.rtf_conf_set_to_post_fwd_stage_mapping_table));
            archive(::cereal::make_nvp("rtf_next_macro_static_table", m.rtf_next_macro_static_table));
            archive(::cereal::make_nvp("rx_counters_block_config_table", m.rx_counters_block_config_table));
            archive(::cereal::make_nvp("rx_fwd_error_handling_counter_table", m.rx_fwd_error_handling_counter_table));
            archive(::cereal::make_nvp("rx_fwd_error_handling_destination_table", m.rx_fwd_error_handling_destination_table));
            archive(::cereal::make_nvp("rx_ip_p_counter_offset_static_table", m.rx_ip_p_counter_offset_static_table));
            archive(::cereal::make_nvp("rx_map_npp_to_ssp_table", m.rx_map_npp_to_ssp_table));
            archive(::cereal::make_nvp("rx_meter_block_meter_attribute_table", m.rx_meter_block_meter_attribute_table));
            archive(::cereal::make_nvp("rx_meter_block_meter_profile_table", m.rx_meter_block_meter_profile_table));
            archive(::cereal::make_nvp("rx_meter_block_meter_shaper_configuration_table", m.rx_meter_block_meter_shaper_configuration_table));
            archive(::cereal::make_nvp("rx_meter_distributed_meter_profile_table", m.rx_meter_distributed_meter_profile_table));
            archive(::cereal::make_nvp("rx_meter_exact_meter_decision_mapping_table", m.rx_meter_exact_meter_decision_mapping_table));
            archive(::cereal::make_nvp("rx_meter_meter_profile_table", m.rx_meter_meter_profile_table));
            archive(::cereal::make_nvp("rx_meter_meter_shaper_configuration_table", m.rx_meter_meter_shaper_configuration_table));
            archive(::cereal::make_nvp("rx_meter_meters_attribute_table", m.rx_meter_meters_attribute_table));
            archive(::cereal::make_nvp("rx_meter_rate_limiter_shaper_configuration_table", m.rx_meter_rate_limiter_shaper_configuration_table));
            archive(::cereal::make_nvp("rx_meter_stat_meter_decision_mapping_table", m.rx_meter_stat_meter_decision_mapping_table));
            archive(::cereal::make_nvp("rx_npu_to_tm_dest_table", m.rx_npu_to_tm_dest_table));
            archive(::cereal::make_nvp("rx_obm_code_table", m.rx_obm_code_table));
            archive(::cereal::make_nvp("rx_obm_punt_src_and_code_table", m.rx_obm_punt_src_and_code_table));
            archive(::cereal::make_nvp("rx_redirect_code_ext_table", m.rx_redirect_code_ext_table));
            archive(::cereal::make_nvp("rx_redirect_code_table", m.rx_redirect_code_table));
            archive(::cereal::make_nvp("rx_redirect_next_macro_static_table", m.rx_redirect_next_macro_static_table));
            archive(::cereal::make_nvp("rx_term_error_handling_counter_table", m.rx_term_error_handling_counter_table));
            archive(::cereal::make_nvp("rx_term_error_handling_destination_table", m.rx_term_error_handling_destination_table));
            archive(::cereal::make_nvp("rxpdr_dsp_lookup_table", m.rxpdr_dsp_lookup_table));
            archive(::cereal::make_nvp("rxpdr_dsp_tc_map", m.rxpdr_dsp_tc_map));
            archive(::cereal::make_nvp("sch_oqse_cfg", m.sch_oqse_cfg));
            archive(::cereal::make_nvp("second_ene_static_table", m.second_ene_static_table));
            archive(::cereal::make_nvp("select_inject_next_macro_static_table", m.select_inject_next_macro_static_table));
            archive(::cereal::make_nvp("service_lp_attributes_table", m.service_lp_attributes_table));
            archive(::cereal::make_nvp("service_mapping_em0_ac_port_table", m.service_mapping_em0_ac_port_table));
            archive(::cereal::make_nvp("service_mapping_em0_ac_port_tag_table", m.service_mapping_em0_ac_port_tag_table));
            archive(::cereal::make_nvp("service_mapping_em0_ac_port_tag_tag_table", m.service_mapping_em0_ac_port_tag_tag_table));
            archive(::cereal::make_nvp("service_mapping_em0_pwe_tag_table", m.service_mapping_em0_pwe_tag_table));
            archive(::cereal::make_nvp("service_mapping_em1_ac_port_tag_table", m.service_mapping_em1_ac_port_tag_table));
            archive(::cereal::make_nvp("service_mapping_tcam_ac_port_table", m.service_mapping_tcam_ac_port_table));
            archive(::cereal::make_nvp("service_mapping_tcam_ac_port_tag_table", m.service_mapping_tcam_ac_port_tag_table));
            archive(::cereal::make_nvp("service_mapping_tcam_ac_port_tag_tag_table", m.service_mapping_tcam_ac_port_tag_tag_table));
            archive(::cereal::make_nvp("service_mapping_tcam_pwe_tag_table", m.service_mapping_tcam_pwe_tag_table));
            archive(::cereal::make_nvp("service_relay_attributes_table", m.service_relay_attributes_table));
            archive(::cereal::make_nvp("set_ene_macro_and_bytes_to_remove_table", m.set_ene_macro_and_bytes_to_remove_table));
            archive(::cereal::make_nvp("sgacl_table", m.sgacl_table));
            archive(::cereal::make_nvp("sip_index_table", m.sip_index_table));
            archive(::cereal::make_nvp("slice_modes_table", m.slice_modes_table));
            archive(::cereal::make_nvp("slp_based_forwarding_table", m.slp_based_forwarding_table));
            archive(::cereal::make_nvp("small_encap_mpls_he_asbr_table", m.small_encap_mpls_he_asbr_table));
            archive(::cereal::make_nvp("small_encap_mpls_he_te_table", m.small_encap_mpls_he_te_table));
            archive(::cereal::make_nvp("snoop_code_hw_table", m.snoop_code_hw_table));
            archive(::cereal::make_nvp("snoop_table", m.snoop_table));
            archive(::cereal::make_nvp("snoop_to_dsp_in_npu_soft_header_table", m.snoop_to_dsp_in_npu_soft_header_table));
            archive(::cereal::make_nvp("source_pif_hw_table", m.source_pif_hw_table));
            archive(::cereal::make_nvp("stage2_lb_group_size_table", m.stage2_lb_group_size_table));
            archive(::cereal::make_nvp("stage2_lb_table", m.stage2_lb_table));
            archive(::cereal::make_nvp("stage3_lb_group_size_table", m.stage3_lb_group_size_table));
            archive(::cereal::make_nvp("stage3_lb_table", m.stage3_lb_table));
            archive(::cereal::make_nvp("stage3_lb_type_decoding_table", m.stage3_lb_type_decoding_table));
            archive(::cereal::make_nvp("svl_next_macro_static_table", m.svl_next_macro_static_table));
            archive(::cereal::make_nvp("te_headend_lsp_counter_offset_table", m.te_headend_lsp_counter_offset_table));
            archive(::cereal::make_nvp("termination_to_forwarding_fi_hardwired_table", m.termination_to_forwarding_fi_hardwired_table));
            archive(::cereal::make_nvp("tm_ibm_cmd_to_destination", m.tm_ibm_cmd_to_destination));
            archive(::cereal::make_nvp("ts_cmd_hw_static_table", m.ts_cmd_hw_static_table));
            archive(::cereal::make_nvp("tunnel_dlp_p_counter_offset_table", m.tunnel_dlp_p_counter_offset_table));
            archive(::cereal::make_nvp("tunnel_qos_static_table", m.tunnel_qos_static_table));
            archive(::cereal::make_nvp("tx_counters_block_config_table", m.tx_counters_block_config_table));
            archive(::cereal::make_nvp("tx_error_handling_counter_table", m.tx_error_handling_counter_table));
            archive(::cereal::make_nvp("tx_punt_eth_encap_table", m.tx_punt_eth_encap_table));
            archive(::cereal::make_nvp("tx_redirect_code_table", m.tx_redirect_code_table));
            archive(::cereal::make_nvp("txpdr_mc_list_size_table", m.txpdr_mc_list_size_table));
            archive(::cereal::make_nvp("txpdr_tc_map_table", m.txpdr_tc_map_table));
            archive(::cereal::make_nvp("txpp_dlp_profile_table", m.txpp_dlp_profile_table));
            archive(::cereal::make_nvp("txpp_encap_qos_mapping_table", m.txpp_encap_qos_mapping_table));
            archive(::cereal::make_nvp("txpp_first_enc_type_to_second_enc_type_offset", m.txpp_first_enc_type_to_second_enc_type_offset));
            archive(::cereal::make_nvp("txpp_fwd_header_type_is_l2_table", m.txpp_fwd_header_type_is_l2_table));
            archive(::cereal::make_nvp("txpp_fwd_qos_mapping_table", m.txpp_fwd_qos_mapping_table));
            archive(::cereal::make_nvp("txpp_initial_npe_macro_table", m.txpp_initial_npe_macro_table));
            archive(::cereal::make_nvp("txpp_mapping_qos_tag_table", m.txpp_mapping_qos_tag_table));
            archive(::cereal::make_nvp("uc_ibm_tc_map_table", m.uc_ibm_tc_map_table));
            archive(::cereal::make_nvp("urpf_ipsa_dest_is_lpts_static_table", m.urpf_ipsa_dest_is_lpts_static_table));
            archive(::cereal::make_nvp("vlan_edit_tpid1_profile_hw_table", m.vlan_edit_tpid1_profile_hw_table));
            archive(::cereal::make_nvp("vlan_edit_tpid2_profile_hw_table", m.vlan_edit_tpid2_profile_hw_table));
            archive(::cereal::make_nvp("vlan_format_table", m.vlan_format_table));
            archive(::cereal::make_nvp("vni_table", m.vni_table));
            archive(::cereal::make_nvp("voq_cgm_slice_buffers_consumption_lut_for_enq_table", m.voq_cgm_slice_buffers_consumption_lut_for_enq_table));
            archive(::cereal::make_nvp("voq_cgm_slice_dram_cgm_profile_table", m.voq_cgm_slice_dram_cgm_profile_table));
            archive(::cereal::make_nvp("voq_cgm_slice_pd_consumption_lut_for_enq_table", m.voq_cgm_slice_pd_consumption_lut_for_enq_table));
            archive(::cereal::make_nvp("voq_cgm_slice_profile_buff_region_thresholds_table", m.voq_cgm_slice_profile_buff_region_thresholds_table));
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table", m.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table));
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_region_thresholds_table", m.voq_cgm_slice_profile_pkt_region_thresholds_table));
            archive(::cereal::make_nvp("voq_cgm_slice_slice_cgm_profile_table", m.voq_cgm_slice_slice_cgm_profile_table));
            archive(::cereal::make_nvp("vsid_table", m.vsid_table));
            archive(::cereal::make_nvp("vxlan_l2_dlp_table", m.vxlan_l2_dlp_table));
            archive(::cereal::make_nvp("inject_mact_ldb_to_output_lr", m.inject_mact_ldb_to_output_lr));
            archive(::cereal::make_nvp("lr_filter_write_ptr_reg", m.lr_filter_write_ptr_reg));
            archive(::cereal::make_nvp("lr_write_ptr_reg", m.lr_write_ptr_reg));
            archive(::cereal::make_nvp("m_device_id", m.m_device_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::device_tables& m) {
            archive(::cereal::make_nvp("acl_map_fi_header_type_to_protocol_number_table", m.acl_map_fi_header_type_to_protocol_number_table));
            archive(::cereal::make_nvp("additional_labels_table", m.additional_labels_table));
            archive(::cereal::make_nvp("all_reachable_vector", m.all_reachable_vector));
            archive(::cereal::make_nvp("bfd_desired_tx_interval_table", m.bfd_desired_tx_interval_table));
            archive(::cereal::make_nvp("bfd_detection_multiple_table", m.bfd_detection_multiple_table));
            archive(::cereal::make_nvp("bfd_event_queue_table", m.bfd_event_queue_table));
            archive(::cereal::make_nvp("bfd_inject_inner_da_high_table", m.bfd_inject_inner_da_high_table));
            archive(::cereal::make_nvp("bfd_inject_inner_da_low_table", m.bfd_inject_inner_da_low_table));
            archive(::cereal::make_nvp("bfd_inject_inner_ethernet_header_static_table", m.bfd_inject_inner_ethernet_header_static_table));
            archive(::cereal::make_nvp("bfd_inject_ttl_static_table", m.bfd_inject_ttl_static_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_A_table", m.bfd_ipv6_sip_A_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_B_table", m.bfd_ipv6_sip_B_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_C_table", m.bfd_ipv6_sip_C_table));
            archive(::cereal::make_nvp("bfd_ipv6_sip_D_table", m.bfd_ipv6_sip_D_table));
            archive(::cereal::make_nvp("bfd_punt_encap_static_table", m.bfd_punt_encap_static_table));
            archive(::cereal::make_nvp("bfd_required_tx_interval_table", m.bfd_required_tx_interval_table));
            archive(::cereal::make_nvp("bfd_rx_table", m.bfd_rx_table));
            archive(::cereal::make_nvp("bfd_set_inject_type_static_table", m.bfd_set_inject_type_static_table));
            archive(::cereal::make_nvp("bfd_udp_port_map_static_table", m.bfd_udp_port_map_static_table));
            archive(::cereal::make_nvp("bfd_udp_port_static_table", m.bfd_udp_port_static_table));
            archive(::cereal::make_nvp("bitmap_oqg_map_table", m.bitmap_oqg_map_table));
            archive(::cereal::make_nvp("bvn_tc_map_table", m.bvn_tc_map_table));
            archive(::cereal::make_nvp("calc_checksum_enable_table", m.calc_checksum_enable_table));
            archive(::cereal::make_nvp("ccm_flags_table", m.ccm_flags_table));
            archive(::cereal::make_nvp("cif2npa_c_lri_macro", m.cif2npa_c_lri_macro));
            archive(::cereal::make_nvp("cif2npa_c_mps_macro", m.cif2npa_c_mps_macro));
            archive(::cereal::make_nvp("counters_block_config_table", m.counters_block_config_table));
            archive(::cereal::make_nvp("counters_voq_block_map_table", m.counters_voq_block_map_table));
            archive(::cereal::make_nvp("cud_is_multicast_bitmap", m.cud_is_multicast_bitmap));
            archive(::cereal::make_nvp("cud_narrow_hw_table", m.cud_narrow_hw_table));
            archive(::cereal::make_nvp("cud_wide_hw_table", m.cud_wide_hw_table));
            archive(::cereal::make_nvp("default_egress_ipv4_sec_acl_table", m.default_egress_ipv4_sec_acl_table));
            archive(::cereal::make_nvp("default_egress_ipv6_acl_sec_table", m.default_egress_ipv6_acl_sec_table));
            archive(::cereal::make_nvp("destination_decoding_table", m.destination_decoding_table));
            archive(::cereal::make_nvp("device_mode_table", m.device_mode_table));
            archive(::cereal::make_nvp("dsp_l2_attributes_table", m.dsp_l2_attributes_table));
            archive(::cereal::make_nvp("dsp_l3_attributes_table", m.dsp_l3_attributes_table));
            archive(::cereal::make_nvp("dummy_dip_index_table", m.dummy_dip_index_table));
            archive(::cereal::make_nvp("ecn_remark_static_table", m.ecn_remark_static_table));
            archive(::cereal::make_nvp("egress_mac_ipv4_sec_acl_table", m.egress_mac_ipv4_sec_acl_table));
            archive(::cereal::make_nvp("egress_nh_and_svi_direct0_table", m.egress_nh_and_svi_direct0_table));
            archive(::cereal::make_nvp("egress_nh_and_svi_direct1_table", m.egress_nh_and_svi_direct1_table));
            archive(::cereal::make_nvp("em_mp_table", m.em_mp_table));
            archive(::cereal::make_nvp("em_pfc_cong_table", m.em_pfc_cong_table));
            archive(::cereal::make_nvp("ene_byte_addition_static_table", m.ene_byte_addition_static_table));
            archive(::cereal::make_nvp("ene_macro_code_tpid_profile_static_table", m.ene_macro_code_tpid_profile_static_table));
            archive(::cereal::make_nvp("erpp_fabric_counters_offset_table", m.erpp_fabric_counters_offset_table));
            archive(::cereal::make_nvp("erpp_fabric_counters_table", m.erpp_fabric_counters_table));
            archive(::cereal::make_nvp("eth_meter_profile_mapping_table", m.eth_meter_profile_mapping_table));
            archive(::cereal::make_nvp("eth_oam_set_da_mc2_static_table", m.eth_oam_set_da_mc2_static_table));
            archive(::cereal::make_nvp("eth_oam_set_da_mc_static_table", m.eth_oam_set_da_mc_static_table));
            archive(::cereal::make_nvp("eth_rtf_conf_set_mapping_table", m.eth_rtf_conf_set_mapping_table));
            archive(::cereal::make_nvp("eve_byte_addition_static_table", m.eve_byte_addition_static_table));
            archive(::cereal::make_nvp("eve_to_ethernet_ene_static_table", m.eve_to_ethernet_ene_static_table));
            archive(::cereal::make_nvp("event_queue_table", m.event_queue_table));
            archive(::cereal::make_nvp("external_aux_table", m.external_aux_table));
            archive(::cereal::make_nvp("fabric_and_tm_header_size_static_table", m.fabric_and_tm_header_size_static_table));
            archive(::cereal::make_nvp("fabric_header_ene_macro_table", m.fabric_header_ene_macro_table));
            archive(::cereal::make_nvp("fabric_header_types_static_table", m.fabric_header_types_static_table));
            archive(::cereal::make_nvp("fabric_headers_type_table", m.fabric_headers_type_table));
            archive(::cereal::make_nvp("fabric_init_cfg", m.fabric_init_cfg));
            archive(::cereal::make_nvp("fabric_npuh_size_calculation_static_table", m.fabric_npuh_size_calculation_static_table));
            archive(::cereal::make_nvp("fabric_out_color_map_table", m.fabric_out_color_map_table));
            archive(::cereal::make_nvp("fabric_rx_fwd_error_handling_counter_table", m.fabric_rx_fwd_error_handling_counter_table));
            archive(::cereal::make_nvp("fabric_rx_fwd_error_handling_destination_table", m.fabric_rx_fwd_error_handling_destination_table));
            archive(::cereal::make_nvp("fabric_rx_term_error_handling_counter_table", m.fabric_rx_term_error_handling_counter_table));
            archive(::cereal::make_nvp("fabric_rx_term_error_handling_destination_table", m.fabric_rx_term_error_handling_destination_table));
            archive(::cereal::make_nvp("fabric_scaled_mc_map_to_netork_slice_static_table", m.fabric_scaled_mc_map_to_netork_slice_static_table));
            archive(::cereal::make_nvp("fabric_smcid_threshold_table", m.fabric_smcid_threshold_table));
            archive(::cereal::make_nvp("fabric_term_error_checker_static_table", m.fabric_term_error_checker_static_table));
            archive(::cereal::make_nvp("fabric_tm_headers_table", m.fabric_tm_headers_table));
            archive(::cereal::make_nvp("fabric_transmit_error_checker_static_table", m.fabric_transmit_error_checker_static_table));
            archive(::cereal::make_nvp("fe_broadcast_bmp_table", m.fe_broadcast_bmp_table));
            archive(::cereal::make_nvp("fe_smcid_threshold_table", m.fe_smcid_threshold_table));
            archive(::cereal::make_nvp("fe_smcid_to_mcid_table", m.fe_smcid_to_mcid_table));
            archive(::cereal::make_nvp("fi_core_tcam_table", m.fi_core_tcam_table));
            archive(::cereal::make_nvp("fi_macro_config_table", m.fi_macro_config_table));
            archive(::cereal::make_nvp("filb_voq_mapping", m.filb_voq_mapping));
            archive(::cereal::make_nvp("first_ene_static_table", m.first_ene_static_table));
            archive(::cereal::make_nvp("frm_db_fabric_routing_table", m.frm_db_fabric_routing_table));
            archive(::cereal::make_nvp("fwd_destination_to_tm_result_data", m.fwd_destination_to_tm_result_data));
            archive(::cereal::make_nvp("fwd_type_to_ive_enable_table", m.fwd_type_to_ive_enable_table));
            archive(::cereal::make_nvp("get_ecm_meter_ptr_table", m.get_ecm_meter_ptr_table));
            archive(::cereal::make_nvp("get_ingress_ptp_info_and_is_slp_dm_static_table", m.get_ingress_ptp_info_and_is_slp_dm_static_table));
            archive(::cereal::make_nvp("get_l2_rtf_conf_set_and_init_stages", m.get_l2_rtf_conf_set_and_init_stages));
            archive(::cereal::make_nvp("get_non_comp_mc_value_static_table", m.get_non_comp_mc_value_static_table));
            archive(::cereal::make_nvp("gre_proto_static_table", m.gre_proto_static_table));
            archive(::cereal::make_nvp("hmc_cgm_cgm_lut_table", m.hmc_cgm_cgm_lut_table));
            archive(::cereal::make_nvp("hmc_cgm_profile_global_table", m.hmc_cgm_profile_global_table));
            archive(::cereal::make_nvp("ibm_cmd_table", m.ibm_cmd_table));
            archive(::cereal::make_nvp("ibm_mc_cmd_to_encap_data_table", m.ibm_mc_cmd_to_encap_data_table));
            archive(::cereal::make_nvp("ibm_uc_cmd_to_encap_data_table", m.ibm_uc_cmd_to_encap_data_table));
            archive(::cereal::make_nvp("ifgb_tc_lut_table", m.ifgb_tc_lut_table));
            archive(::cereal::make_nvp("ingress_ip_qos_mapping_table", m.ingress_ip_qos_mapping_table));
            archive(::cereal::make_nvp("ingress_rtf_eth_db1_160_f0_table", m.ingress_rtf_eth_db1_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_eth_db2_160_f0_table", m.ingress_rtf_eth_db2_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db1_160_f0_table", m.ingress_rtf_ipv4_db1_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db1_160_f1_table", m.ingress_rtf_ipv4_db1_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db1_320_f0_table", m.ingress_rtf_ipv4_db1_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db2_160_f0_table", m.ingress_rtf_ipv4_db2_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db2_160_f1_table", m.ingress_rtf_ipv4_db2_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db2_320_f0_table", m.ingress_rtf_ipv4_db2_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db3_160_f0_table", m.ingress_rtf_ipv4_db3_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db3_160_f1_table", m.ingress_rtf_ipv4_db3_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db3_320_f0_table", m.ingress_rtf_ipv4_db3_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db4_160_f0_table", m.ingress_rtf_ipv4_db4_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db4_160_f1_table", m.ingress_rtf_ipv4_db4_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv4_db4_320_f0_table", m.ingress_rtf_ipv4_db4_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db1_160_f0_table", m.ingress_rtf_ipv6_db1_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db1_160_f1_table", m.ingress_rtf_ipv6_db1_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db1_320_f0_table", m.ingress_rtf_ipv6_db1_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db2_160_f0_table", m.ingress_rtf_ipv6_db2_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db2_160_f1_table", m.ingress_rtf_ipv6_db2_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db2_320_f0_table", m.ingress_rtf_ipv6_db2_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db3_160_f0_table", m.ingress_rtf_ipv6_db3_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db3_160_f1_table", m.ingress_rtf_ipv6_db3_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db3_320_f0_table", m.ingress_rtf_ipv6_db3_320_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db4_160_f0_table", m.ingress_rtf_ipv6_db4_160_f0_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db4_160_f1_table", m.ingress_rtf_ipv6_db4_160_f1_table));
            archive(::cereal::make_nvp("ingress_rtf_ipv6_db4_320_f0_table", m.ingress_rtf_ipv6_db4_320_f0_table));
            archive(::cereal::make_nvp("inject_down_select_ene_static_table", m.inject_down_select_ene_static_table));
            archive(::cereal::make_nvp("inject_down_tx_redirect_counter_table", m.inject_down_tx_redirect_counter_table));
            archive(::cereal::make_nvp("inject_up_pif_ifg_init_data_table", m.inject_up_pif_ifg_init_data_table));
            archive(::cereal::make_nvp("inject_up_ssp_init_data_table", m.inject_up_ssp_init_data_table));
            archive(::cereal::make_nvp("inner_tpid_table", m.inner_tpid_table));
            archive(::cereal::make_nvp("ip_fwd_header_mapping_to_ethtype_static_table", m.ip_fwd_header_mapping_to_ethtype_static_table));
            archive(::cereal::make_nvp("ip_ingress_cmp_mcid_static_table", m.ip_ingress_cmp_mcid_static_table));
            archive(::cereal::make_nvp("ip_mc_local_inject_type_static_table", m.ip_mc_local_inject_type_static_table));
            archive(::cereal::make_nvp("ip_mc_next_macro_static_table", m.ip_mc_next_macro_static_table));
            archive(::cereal::make_nvp("ip_meter_profile_mapping_table", m.ip_meter_profile_mapping_table));
            archive(::cereal::make_nvp("ip_prefix_destination_table", m.ip_prefix_destination_table));
            archive(::cereal::make_nvp("ip_relay_to_vni_table", m.ip_relay_to_vni_table));
            archive(::cereal::make_nvp("ip_rx_global_counter_table", m.ip_rx_global_counter_table));
            archive(::cereal::make_nvp("ip_ver_mc_static_table", m.ip_ver_mc_static_table));
            archive(::cereal::make_nvp("ipv4_acl_map_protocol_type_to_protocol_number_table", m.ipv4_acl_map_protocol_type_to_protocol_number_table));
            archive(::cereal::make_nvp("ipv4_acl_sport_static_table", m.ipv4_acl_sport_static_table));
            archive(::cereal::make_nvp("ipv4_ip_tunnel_termination_dip_index_tt0_table", m.ipv4_ip_tunnel_termination_dip_index_tt0_table));
            archive(::cereal::make_nvp("ipv4_ip_tunnel_termination_sip_dip_index_tt0_table", m.ipv4_ip_tunnel_termination_sip_dip_index_tt0_table));
            archive(::cereal::make_nvp("ipv4_ip_tunnel_termination_sip_dip_index_tt1_table", m.ipv4_ip_tunnel_termination_sip_dip_index_tt1_table));
            archive(::cereal::make_nvp("ipv4_lpm_table", m.ipv4_lpm_table));
            archive(::cereal::make_nvp("ipv4_lpts_table", m.ipv4_lpts_table));
            archive(::cereal::make_nvp("ipv4_og_pcl_em_table", m.ipv4_og_pcl_em_table));
            archive(::cereal::make_nvp("ipv4_og_pcl_lpm_table", m.ipv4_og_pcl_lpm_table));
            archive(::cereal::make_nvp("ipv4_rtf_conf_set_mapping_table", m.ipv4_rtf_conf_set_mapping_table));
            archive(::cereal::make_nvp("ipv4_vrf_dip_em_table", m.ipv4_vrf_dip_em_table));
            archive(::cereal::make_nvp("ipv4_vrf_s_g_table", m.ipv4_vrf_s_g_table));
            archive(::cereal::make_nvp("ipv6_acl_sport_static_table", m.ipv6_acl_sport_static_table));
            archive(::cereal::make_nvp("ipv6_first_fragment_static_table", m.ipv6_first_fragment_static_table));
            archive(::cereal::make_nvp("ipv6_lpm_table", m.ipv6_lpm_table));
            archive(::cereal::make_nvp("ipv6_lpts_table", m.ipv6_lpts_table));
            archive(::cereal::make_nvp("ipv6_mc_select_qos_id", m.ipv6_mc_select_qos_id));
            archive(::cereal::make_nvp("ipv6_og_pcl_em_table", m.ipv6_og_pcl_em_table));
            archive(::cereal::make_nvp("ipv6_og_pcl_lpm_table", m.ipv6_og_pcl_lpm_table));
            archive(::cereal::make_nvp("ipv6_rtf_conf_set_mapping_table", m.ipv6_rtf_conf_set_mapping_table));
            archive(::cereal::make_nvp("ipv6_sip_compression_table", m.ipv6_sip_compression_table));
            archive(::cereal::make_nvp("ipv6_vrf_dip_em_table", m.ipv6_vrf_dip_em_table));
            archive(::cereal::make_nvp("ipv6_vrf_s_g_table", m.ipv6_vrf_s_g_table));
            archive(::cereal::make_nvp("is_pacific_b1_static_table", m.is_pacific_b1_static_table));
            archive(::cereal::make_nvp("l2_dlp_table", m.l2_dlp_table));
            archive(::cereal::make_nvp("l2_lp_profile_filter_table", m.l2_lp_profile_filter_table));
            archive(::cereal::make_nvp("l2_lpts_ctrl_fields_static_table", m.l2_lpts_ctrl_fields_static_table));
            archive(::cereal::make_nvp("l2_lpts_ip_fragment_static_table", m.l2_lpts_ip_fragment_static_table));
            archive(::cereal::make_nvp("l2_lpts_ipv4_table", m.l2_lpts_ipv4_table));
            archive(::cereal::make_nvp("l2_lpts_ipv6_table", m.l2_lpts_ipv6_table));
            archive(::cereal::make_nvp("l2_lpts_mac_table", m.l2_lpts_mac_table));
            archive(::cereal::make_nvp("l2_lpts_next_macro_static_table", m.l2_lpts_next_macro_static_table));
            archive(::cereal::make_nvp("l2_lpts_protocol_table", m.l2_lpts_protocol_table));
            archive(::cereal::make_nvp("l2_lpts_skip_p2p_static_table", m.l2_lpts_skip_p2p_static_table));
            archive(::cereal::make_nvp("l2_termination_next_macro_static_table", m.l2_termination_next_macro_static_table));
            archive(::cereal::make_nvp("l2_tunnel_term_next_macro_static_table", m.l2_tunnel_term_next_macro_static_table));
            archive(::cereal::make_nvp("l3_dlp_p_counter_offset_table", m.l3_dlp_p_counter_offset_table));
            archive(::cereal::make_nvp("l3_dlp_table", m.l3_dlp_table));
            archive(::cereal::make_nvp("l3_termination_classify_ip_tunnels_table", m.l3_termination_classify_ip_tunnels_table));
            archive(::cereal::make_nvp("l3_termination_next_macro_static_table", m.l3_termination_next_macro_static_table));
            archive(::cereal::make_nvp("l3_tunnel_termination_next_macro_static_table", m.l3_tunnel_termination_next_macro_static_table));
            archive(::cereal::make_nvp("l3_vxlan_overlay_sa_table", m.l3_vxlan_overlay_sa_table));
            archive(::cereal::make_nvp("large_encap_global_lsp_prefix_table", m.large_encap_global_lsp_prefix_table));
            archive(::cereal::make_nvp("large_encap_ip_tunnel_table", m.large_encap_ip_tunnel_table));
            archive(::cereal::make_nvp("large_encap_mpls_he_no_ldp_table", m.large_encap_mpls_he_no_ldp_table));
            archive(::cereal::make_nvp("large_encap_mpls_ldp_over_te_table", m.large_encap_mpls_ldp_over_te_table));
            archive(::cereal::make_nvp("large_encap_te_he_tunnel_id_table", m.large_encap_te_he_tunnel_id_table));
            archive(::cereal::make_nvp("learn_manager_cfg_max_learn_type_reg", m.learn_manager_cfg_max_learn_type_reg));
            archive(::cereal::make_nvp("light_fi_fabric_table", m.light_fi_fabric_table));
            archive(::cereal::make_nvp("light_fi_npu_base_table", m.light_fi_npu_base_table));
            archive(::cereal::make_nvp("light_fi_npu_encap_table", m.light_fi_npu_encap_table));
            archive(::cereal::make_nvp("light_fi_nw_0_table", m.light_fi_nw_0_table));
            archive(::cereal::make_nvp("light_fi_nw_1_table", m.light_fi_nw_1_table));
            archive(::cereal::make_nvp("light_fi_nw_2_table", m.light_fi_nw_2_table));
            archive(::cereal::make_nvp("light_fi_nw_3_table", m.light_fi_nw_3_table));
            archive(::cereal::make_nvp("light_fi_stages_cfg_table", m.light_fi_stages_cfg_table));
            archive(::cereal::make_nvp("light_fi_tm_table", m.light_fi_tm_table));
            archive(::cereal::make_nvp("link_relay_attributes_table", m.link_relay_attributes_table));
            archive(::cereal::make_nvp("link_up_vector", m.link_up_vector));
            archive(::cereal::make_nvp("lp_over_lag_table", m.lp_over_lag_table));
            archive(::cereal::make_nvp("lpm_destination_prefix_map_table", m.lpm_destination_prefix_map_table));
            archive(::cereal::make_nvp("lpts_2nd_lookup_table", m.lpts_2nd_lookup_table));
            archive(::cereal::make_nvp("lpts_meter_table", m.lpts_meter_table));
            archive(::cereal::make_nvp("lpts_og_application_table", m.lpts_og_application_table));
            archive(::cereal::make_nvp("mac_af_npp_attributes_table", m.mac_af_npp_attributes_table));
            archive(::cereal::make_nvp("mac_da_table", m.mac_da_table));
            archive(::cereal::make_nvp("mac_ethernet_rate_limit_type_static_table", m.mac_ethernet_rate_limit_type_static_table));
            archive(::cereal::make_nvp("mac_forwarding_table", m.mac_forwarding_table));
            archive(::cereal::make_nvp("mac_mc_em_termination_attributes_table", m.mac_mc_em_termination_attributes_table));
            archive(::cereal::make_nvp("mac_mc_tcam_termination_attributes_table", m.mac_mc_tcam_termination_attributes_table));
            archive(::cereal::make_nvp("mac_qos_mapping_table", m.mac_qos_mapping_table));
            archive(::cereal::make_nvp("mac_relay_g_ipv4_table", m.mac_relay_g_ipv4_table));
            archive(::cereal::make_nvp("mac_relay_g_ipv6_table", m.mac_relay_g_ipv6_table));
            archive(::cereal::make_nvp("mac_relay_to_vni_table", m.mac_relay_to_vni_table));
            archive(::cereal::make_nvp("mac_termination_em_table", m.mac_termination_em_table));
            archive(::cereal::make_nvp("mac_termination_next_macro_static_table", m.mac_termination_next_macro_static_table));
            archive(::cereal::make_nvp("mac_termination_no_da_em_table", m.mac_termination_no_da_em_table));
            archive(::cereal::make_nvp("mac_termination_tcam_table", m.mac_termination_tcam_table));
            archive(::cereal::make_nvp("map_ene_subcode_to8bit_static_table", m.map_ene_subcode_to8bit_static_table));
            archive(::cereal::make_nvp("map_inject_ccm_macro_static_table", m.map_inject_ccm_macro_static_table));
            archive(::cereal::make_nvp("map_more_labels_static_table", m.map_more_labels_static_table));
            archive(::cereal::make_nvp("map_recyle_tx_to_rx_data_on_pd_static_table", m.map_recyle_tx_to_rx_data_on_pd_static_table));
            archive(::cereal::make_nvp("map_tm_dp_ecn_to_wa_ecn_dp_static_table", m.map_tm_dp_ecn_to_wa_ecn_dp_static_table));
            archive(::cereal::make_nvp("map_tx_punt_next_macro_static_table", m.map_tx_punt_next_macro_static_table));
            archive(::cereal::make_nvp("map_tx_punt_rcy_next_macro_static_table", m.map_tx_punt_rcy_next_macro_static_table));
            archive(::cereal::make_nvp("mc_bitmap_base_voq_lookup_table", m.mc_bitmap_base_voq_lookup_table));
            archive(::cereal::make_nvp("mc_bitmap_tc_map_table", m.mc_bitmap_tc_map_table));
            archive(::cereal::make_nvp("mc_copy_id_map", m.mc_copy_id_map));
            archive(::cereal::make_nvp("mc_cud_is_wide_table", m.mc_cud_is_wide_table));
            archive(::cereal::make_nvp("mc_em_db", m.mc_em_db));
            archive(::cereal::make_nvp("mc_emdb_tc_map_table", m.mc_emdb_tc_map_table));
            archive(::cereal::make_nvp("mc_fe_links_bmp", m.mc_fe_links_bmp));
            archive(::cereal::make_nvp("mc_ibm_cud_mapping_table", m.mc_ibm_cud_mapping_table));
            archive(::cereal::make_nvp("mc_slice_bitmap_table", m.mc_slice_bitmap_table));
            archive(::cereal::make_nvp("meg_id_format_table", m.meg_id_format_table));
            archive(::cereal::make_nvp("mep_address_prefix_table", m.mep_address_prefix_table));
            archive(::cereal::make_nvp("mii_loopback_table", m.mii_loopback_table));
            archive(::cereal::make_nvp("mirror_code_hw_table", m.mirror_code_hw_table));
            archive(::cereal::make_nvp("mirror_egress_attributes_table", m.mirror_egress_attributes_table));
            archive(::cereal::make_nvp("mirror_to_dsp_in_npu_soft_header_table", m.mirror_to_dsp_in_npu_soft_header_table));
            archive(::cereal::make_nvp("mldp_protection_enabled_static_table", m.mldp_protection_enabled_static_table));
            archive(::cereal::make_nvp("mldp_protection_table", m.mldp_protection_table));
            archive(::cereal::make_nvp("mp_aux_data_table", m.mp_aux_data_table));
            archive(::cereal::make_nvp("mp_data_table", m.mp_data_table));
            archive(::cereal::make_nvp("mpls_encap_control_static_table", m.mpls_encap_control_static_table));
            archive(::cereal::make_nvp("mpls_forwarding_table", m.mpls_forwarding_table));
            archive(::cereal::make_nvp("mpls_header_offset_in_bytes_static_table", m.mpls_header_offset_in_bytes_static_table));
            archive(::cereal::make_nvp("mpls_l3_lsp_static_table", m.mpls_l3_lsp_static_table));
            archive(::cereal::make_nvp("mpls_labels_1_to_4_jump_offset_static_table", m.mpls_labels_1_to_4_jump_offset_static_table));
            archive(::cereal::make_nvp("mpls_lsp_labels_config_static_table", m.mpls_lsp_labels_config_static_table));
            archive(::cereal::make_nvp("mpls_qos_mapping_table", m.mpls_qos_mapping_table));
            archive(::cereal::make_nvp("mpls_resolve_service_labels_static_table", m.mpls_resolve_service_labels_static_table));
            archive(::cereal::make_nvp("mpls_termination_em0_table", m.mpls_termination_em0_table));
            archive(::cereal::make_nvp("mpls_termination_em1_table", m.mpls_termination_em1_table));
            archive(::cereal::make_nvp("mpls_vpn_enabled_static_table", m.mpls_vpn_enabled_static_table));
            archive(::cereal::make_nvp("my_ipv4_table", m.my_ipv4_table));
            archive(::cereal::make_nvp("native_ce_ptr_table", m.native_ce_ptr_table));
            archive(::cereal::make_nvp("native_fec_table", m.native_fec_table));
            archive(::cereal::make_nvp("native_fec_type_decoding_table", m.native_fec_type_decoding_table));
            archive(::cereal::make_nvp("native_frr_table", m.native_frr_table));
            archive(::cereal::make_nvp("native_frr_type_decoding_table", m.native_frr_type_decoding_table));
            archive(::cereal::make_nvp("native_l2_lp_table", m.native_l2_lp_table));
            archive(::cereal::make_nvp("native_l2_lp_type_decoding_table", m.native_l2_lp_type_decoding_table));
            archive(::cereal::make_nvp("native_lb_group_size_table", m.native_lb_group_size_table));
            archive(::cereal::make_nvp("native_lb_table", m.native_lb_table));
            archive(::cereal::make_nvp("native_lb_type_decoding_table", m.native_lb_type_decoding_table));
            archive(::cereal::make_nvp("native_lp_is_pbts_prefix_table", m.native_lp_is_pbts_prefix_table));
            archive(::cereal::make_nvp("native_lp_pbts_map_table", m.native_lp_pbts_map_table));
            archive(::cereal::make_nvp("native_protection_table", m.native_protection_table));
            archive(::cereal::make_nvp("next_header_1_is_l4_over_ipv4_static_table", m.next_header_1_is_l4_over_ipv4_static_table));
            archive(::cereal::make_nvp("nh_macro_code_to_id_l6_static_table", m.nh_macro_code_to_id_l6_static_table));
            archive(::cereal::make_nvp("nhlfe_type_mapping_static_table", m.nhlfe_type_mapping_static_table));
            archive(::cereal::make_nvp("null_rtf_next_macro_static_table", m.null_rtf_next_macro_static_table));
            archive(::cereal::make_nvp("nw_smcid_threshold_table", m.nw_smcid_threshold_table));
            archive(::cereal::make_nvp("oamp_drop_destination_static_table", m.oamp_drop_destination_static_table));
            archive(::cereal::make_nvp("oamp_event_queue_table", m.oamp_event_queue_table));
            archive(::cereal::make_nvp("oamp_redirect_get_counter_table", m.oamp_redirect_get_counter_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_1_table", m.oamp_redirect_punt_eth_hdr_1_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_2_table", m.oamp_redirect_punt_eth_hdr_2_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_3_table", m.oamp_redirect_punt_eth_hdr_3_table));
            archive(::cereal::make_nvp("oamp_redirect_punt_eth_hdr_4_table", m.oamp_redirect_punt_eth_hdr_4_table));
            archive(::cereal::make_nvp("oamp_redirect_table", m.oamp_redirect_table));
            archive(::cereal::make_nvp("obm_next_macro_static_table", m.obm_next_macro_static_table));
            archive(::cereal::make_nvp("og_next_macro_static_table", m.og_next_macro_static_table));
            archive(::cereal::make_nvp("outer_tpid_table", m.outer_tpid_table));
            archive(::cereal::make_nvp("overlay_ipv4_sip_table", m.overlay_ipv4_sip_table));
            archive(::cereal::make_nvp("pad_mtu_inj_check_static_table", m.pad_mtu_inj_check_static_table));
            archive(::cereal::make_nvp("path_lb_type_decoding_table", m.path_lb_type_decoding_table));
            archive(::cereal::make_nvp("path_lp_is_pbts_prefix_table", m.path_lp_is_pbts_prefix_table));
            archive(::cereal::make_nvp("path_lp_pbts_map_table", m.path_lp_pbts_map_table));
            archive(::cereal::make_nvp("path_lp_table", m.path_lp_table));
            archive(::cereal::make_nvp("path_lp_type_decoding_table", m.path_lp_type_decoding_table));
            archive(::cereal::make_nvp("path_protection_table", m.path_protection_table));
            archive(::cereal::make_nvp("pdoq_oq_ifc_mapping", m.pdoq_oq_ifc_mapping));
            archive(::cereal::make_nvp("pdvoq_slice_voq_properties_table", m.pdvoq_slice_voq_properties_table));
            archive(::cereal::make_nvp("per_asbr_and_dpe_table", m.per_asbr_and_dpe_table));
            archive(::cereal::make_nvp("per_pe_and_prefix_vpn_key_large_table", m.per_pe_and_prefix_vpn_key_large_table));
            archive(::cereal::make_nvp("per_pe_and_vrf_vpn_key_large_table", m.per_pe_and_vrf_vpn_key_large_table));
            archive(::cereal::make_nvp("per_port_destination_table", m.per_port_destination_table));
            archive(::cereal::make_nvp("per_vrf_mpls_forwarding_table", m.per_vrf_mpls_forwarding_table));
            archive(::cereal::make_nvp("pfc_destination_table", m.pfc_destination_table));
            archive(::cereal::make_nvp("pfc_event_queue_table", m.pfc_event_queue_table));
            archive(::cereal::make_nvp("pfc_filter_wd_table", m.pfc_filter_wd_table));
            archive(::cereal::make_nvp("pfc_offset_from_vector_static_table", m.pfc_offset_from_vector_static_table));
            archive(::cereal::make_nvp("pfc_ssp_slice_map_table", m.pfc_ssp_slice_map_table));
            archive(::cereal::make_nvp("pfc_tc_latency_table", m.pfc_tc_latency_table));
            archive(::cereal::make_nvp("pfc_tc_table", m.pfc_tc_table));
            archive(::cereal::make_nvp("pfc_tc_wrap_latency_table", m.pfc_tc_wrap_latency_table));
            archive(::cereal::make_nvp("pfc_vector_static_table", m.pfc_vector_static_table));
            archive(::cereal::make_nvp("pin_start_offset_macros", m.pin_start_offset_macros));
            archive(::cereal::make_nvp("pma_loopback_table", m.pma_loopback_table));
            archive(::cereal::make_nvp("port_dspa_group_size_table", m.port_dspa_group_size_table));
            archive(::cereal::make_nvp("port_dspa_table", m.port_dspa_table));
            archive(::cereal::make_nvp("port_dspa_type_decoding_table", m.port_dspa_type_decoding_table));
            archive(::cereal::make_nvp("port_npp_protection_table", m.port_npp_protection_table));
            archive(::cereal::make_nvp("port_npp_protection_type_decoding_table", m.port_npp_protection_type_decoding_table));
            archive(::cereal::make_nvp("port_protection_table", m.port_protection_table));
            archive(::cereal::make_nvp("punt_ethertype_static_table", m.punt_ethertype_static_table));
            archive(::cereal::make_nvp("punt_rcy_inject_header_ene_encap_table", m.punt_rcy_inject_header_ene_encap_table));
            archive(::cereal::make_nvp("punt_select_nw_ene_static_table", m.punt_select_nw_ene_static_table));
            archive(::cereal::make_nvp("punt_tunnel_transport_encap_table", m.punt_tunnel_transport_encap_table));
            archive(::cereal::make_nvp("punt_tunnel_transport_extended_encap_table", m.punt_tunnel_transport_extended_encap_table));
            archive(::cereal::make_nvp("punt_tunnel_transport_extended_encap_table2", m.punt_tunnel_transport_extended_encap_table2));
            archive(::cereal::make_nvp("pwe_label_table", m.pwe_label_table));
            archive(::cereal::make_nvp("pwe_to_l3_dest_table", m.pwe_to_l3_dest_table));
            archive(::cereal::make_nvp("pwe_vpls_label_table", m.pwe_vpls_label_table));
            archive(::cereal::make_nvp("pwe_vpls_tunnel_label_table", m.pwe_vpls_tunnel_label_table));
            archive(::cereal::make_nvp("reassembly_source_port_map_table", m.reassembly_source_port_map_table));
            archive(::cereal::make_nvp("recycle_override_table", m.recycle_override_table));
            archive(::cereal::make_nvp("recycled_inject_up_info_table", m.recycled_inject_up_info_table));
            archive(::cereal::make_nvp("redirect_destination_table", m.redirect_destination_table));
            archive(::cereal::make_nvp("redirect_table", m.redirect_table));
            archive(::cereal::make_nvp("resolution_pfc_select_table", m.resolution_pfc_select_table));
            archive(::cereal::make_nvp("resolution_set_next_macro_table", m.resolution_set_next_macro_table));
            archive(::cereal::make_nvp("rewrite_sa_prefix_index_table", m.rewrite_sa_prefix_index_table));
            archive(::cereal::make_nvp("rmep_last_time_table", m.rmep_last_time_table));
            archive(::cereal::make_nvp("rmep_state_table", m.rmep_state_table));
            archive(::cereal::make_nvp("rpf_fec_access_map_table", m.rpf_fec_access_map_table));
            archive(::cereal::make_nvp("rpf_fec_table", m.rpf_fec_table));
            archive(::cereal::make_nvp("rtf_conf_set_to_og_pcl_compress_bits_mapping_table", m.rtf_conf_set_to_og_pcl_compress_bits_mapping_table));
            archive(::cereal::make_nvp("rtf_conf_set_to_og_pcl_ids_mapping_table", m.rtf_conf_set_to_og_pcl_ids_mapping_table));
            archive(::cereal::make_nvp("rtf_conf_set_to_post_fwd_stage_mapping_table", m.rtf_conf_set_to_post_fwd_stage_mapping_table));
            archive(::cereal::make_nvp("rtf_next_macro_static_table", m.rtf_next_macro_static_table));
            archive(::cereal::make_nvp("rx_counters_block_config_table", m.rx_counters_block_config_table));
            archive(::cereal::make_nvp("rx_fwd_error_handling_counter_table", m.rx_fwd_error_handling_counter_table));
            archive(::cereal::make_nvp("rx_fwd_error_handling_destination_table", m.rx_fwd_error_handling_destination_table));
            archive(::cereal::make_nvp("rx_ip_p_counter_offset_static_table", m.rx_ip_p_counter_offset_static_table));
            archive(::cereal::make_nvp("rx_map_npp_to_ssp_table", m.rx_map_npp_to_ssp_table));
            archive(::cereal::make_nvp("rx_meter_block_meter_attribute_table", m.rx_meter_block_meter_attribute_table));
            archive(::cereal::make_nvp("rx_meter_block_meter_profile_table", m.rx_meter_block_meter_profile_table));
            archive(::cereal::make_nvp("rx_meter_block_meter_shaper_configuration_table", m.rx_meter_block_meter_shaper_configuration_table));
            archive(::cereal::make_nvp("rx_meter_distributed_meter_profile_table", m.rx_meter_distributed_meter_profile_table));
            archive(::cereal::make_nvp("rx_meter_exact_meter_decision_mapping_table", m.rx_meter_exact_meter_decision_mapping_table));
            archive(::cereal::make_nvp("rx_meter_meter_profile_table", m.rx_meter_meter_profile_table));
            archive(::cereal::make_nvp("rx_meter_meter_shaper_configuration_table", m.rx_meter_meter_shaper_configuration_table));
            archive(::cereal::make_nvp("rx_meter_meters_attribute_table", m.rx_meter_meters_attribute_table));
            archive(::cereal::make_nvp("rx_meter_rate_limiter_shaper_configuration_table", m.rx_meter_rate_limiter_shaper_configuration_table));
            archive(::cereal::make_nvp("rx_meter_stat_meter_decision_mapping_table", m.rx_meter_stat_meter_decision_mapping_table));
            archive(::cereal::make_nvp("rx_npu_to_tm_dest_table", m.rx_npu_to_tm_dest_table));
            archive(::cereal::make_nvp("rx_obm_code_table", m.rx_obm_code_table));
            archive(::cereal::make_nvp("rx_obm_punt_src_and_code_table", m.rx_obm_punt_src_and_code_table));
            archive(::cereal::make_nvp("rx_redirect_code_ext_table", m.rx_redirect_code_ext_table));
            archive(::cereal::make_nvp("rx_redirect_code_table", m.rx_redirect_code_table));
            archive(::cereal::make_nvp("rx_redirect_next_macro_static_table", m.rx_redirect_next_macro_static_table));
            archive(::cereal::make_nvp("rx_term_error_handling_counter_table", m.rx_term_error_handling_counter_table));
            archive(::cereal::make_nvp("rx_term_error_handling_destination_table", m.rx_term_error_handling_destination_table));
            archive(::cereal::make_nvp("rxpdr_dsp_lookup_table", m.rxpdr_dsp_lookup_table));
            archive(::cereal::make_nvp("rxpdr_dsp_tc_map", m.rxpdr_dsp_tc_map));
            archive(::cereal::make_nvp("sch_oqse_cfg", m.sch_oqse_cfg));
            archive(::cereal::make_nvp("second_ene_static_table", m.second_ene_static_table));
            archive(::cereal::make_nvp("select_inject_next_macro_static_table", m.select_inject_next_macro_static_table));
            archive(::cereal::make_nvp("service_lp_attributes_table", m.service_lp_attributes_table));
            archive(::cereal::make_nvp("service_mapping_em0_ac_port_table", m.service_mapping_em0_ac_port_table));
            archive(::cereal::make_nvp("service_mapping_em0_ac_port_tag_table", m.service_mapping_em0_ac_port_tag_table));
            archive(::cereal::make_nvp("service_mapping_em0_ac_port_tag_tag_table", m.service_mapping_em0_ac_port_tag_tag_table));
            archive(::cereal::make_nvp("service_mapping_em0_pwe_tag_table", m.service_mapping_em0_pwe_tag_table));
            archive(::cereal::make_nvp("service_mapping_em1_ac_port_tag_table", m.service_mapping_em1_ac_port_tag_table));
            archive(::cereal::make_nvp("service_mapping_tcam_ac_port_table", m.service_mapping_tcam_ac_port_table));
            archive(::cereal::make_nvp("service_mapping_tcam_ac_port_tag_table", m.service_mapping_tcam_ac_port_tag_table));
            archive(::cereal::make_nvp("service_mapping_tcam_ac_port_tag_tag_table", m.service_mapping_tcam_ac_port_tag_tag_table));
            archive(::cereal::make_nvp("service_mapping_tcam_pwe_tag_table", m.service_mapping_tcam_pwe_tag_table));
            archive(::cereal::make_nvp("service_relay_attributes_table", m.service_relay_attributes_table));
            archive(::cereal::make_nvp("set_ene_macro_and_bytes_to_remove_table", m.set_ene_macro_and_bytes_to_remove_table));
            archive(::cereal::make_nvp("sgacl_table", m.sgacl_table));
            archive(::cereal::make_nvp("sip_index_table", m.sip_index_table));
            archive(::cereal::make_nvp("slice_modes_table", m.slice_modes_table));
            archive(::cereal::make_nvp("slp_based_forwarding_table", m.slp_based_forwarding_table));
            archive(::cereal::make_nvp("small_encap_mpls_he_asbr_table", m.small_encap_mpls_he_asbr_table));
            archive(::cereal::make_nvp("small_encap_mpls_he_te_table", m.small_encap_mpls_he_te_table));
            archive(::cereal::make_nvp("snoop_code_hw_table", m.snoop_code_hw_table));
            archive(::cereal::make_nvp("snoop_table", m.snoop_table));
            archive(::cereal::make_nvp("snoop_to_dsp_in_npu_soft_header_table", m.snoop_to_dsp_in_npu_soft_header_table));
            archive(::cereal::make_nvp("source_pif_hw_table", m.source_pif_hw_table));
            archive(::cereal::make_nvp("stage2_lb_group_size_table", m.stage2_lb_group_size_table));
            archive(::cereal::make_nvp("stage2_lb_table", m.stage2_lb_table));
            archive(::cereal::make_nvp("stage3_lb_group_size_table", m.stage3_lb_group_size_table));
            archive(::cereal::make_nvp("stage3_lb_table", m.stage3_lb_table));
            archive(::cereal::make_nvp("stage3_lb_type_decoding_table", m.stage3_lb_type_decoding_table));
            archive(::cereal::make_nvp("svl_next_macro_static_table", m.svl_next_macro_static_table));
            archive(::cereal::make_nvp("te_headend_lsp_counter_offset_table", m.te_headend_lsp_counter_offset_table));
            archive(::cereal::make_nvp("termination_to_forwarding_fi_hardwired_table", m.termination_to_forwarding_fi_hardwired_table));
            archive(::cereal::make_nvp("tm_ibm_cmd_to_destination", m.tm_ibm_cmd_to_destination));
            archive(::cereal::make_nvp("ts_cmd_hw_static_table", m.ts_cmd_hw_static_table));
            archive(::cereal::make_nvp("tunnel_dlp_p_counter_offset_table", m.tunnel_dlp_p_counter_offset_table));
            archive(::cereal::make_nvp("tunnel_qos_static_table", m.tunnel_qos_static_table));
            archive(::cereal::make_nvp("tx_counters_block_config_table", m.tx_counters_block_config_table));
            archive(::cereal::make_nvp("tx_error_handling_counter_table", m.tx_error_handling_counter_table));
            archive(::cereal::make_nvp("tx_punt_eth_encap_table", m.tx_punt_eth_encap_table));
            archive(::cereal::make_nvp("tx_redirect_code_table", m.tx_redirect_code_table));
            archive(::cereal::make_nvp("txpdr_mc_list_size_table", m.txpdr_mc_list_size_table));
            archive(::cereal::make_nvp("txpdr_tc_map_table", m.txpdr_tc_map_table));
            archive(::cereal::make_nvp("txpp_dlp_profile_table", m.txpp_dlp_profile_table));
            archive(::cereal::make_nvp("txpp_encap_qos_mapping_table", m.txpp_encap_qos_mapping_table));
            archive(::cereal::make_nvp("txpp_first_enc_type_to_second_enc_type_offset", m.txpp_first_enc_type_to_second_enc_type_offset));
            archive(::cereal::make_nvp("txpp_fwd_header_type_is_l2_table", m.txpp_fwd_header_type_is_l2_table));
            archive(::cereal::make_nvp("txpp_fwd_qos_mapping_table", m.txpp_fwd_qos_mapping_table));
            archive(::cereal::make_nvp("txpp_initial_npe_macro_table", m.txpp_initial_npe_macro_table));
            archive(::cereal::make_nvp("txpp_mapping_qos_tag_table", m.txpp_mapping_qos_tag_table));
            archive(::cereal::make_nvp("uc_ibm_tc_map_table", m.uc_ibm_tc_map_table));
            archive(::cereal::make_nvp("urpf_ipsa_dest_is_lpts_static_table", m.urpf_ipsa_dest_is_lpts_static_table));
            archive(::cereal::make_nvp("vlan_edit_tpid1_profile_hw_table", m.vlan_edit_tpid1_profile_hw_table));
            archive(::cereal::make_nvp("vlan_edit_tpid2_profile_hw_table", m.vlan_edit_tpid2_profile_hw_table));
            archive(::cereal::make_nvp("vlan_format_table", m.vlan_format_table));
            archive(::cereal::make_nvp("vni_table", m.vni_table));
            archive(::cereal::make_nvp("voq_cgm_slice_buffers_consumption_lut_for_enq_table", m.voq_cgm_slice_buffers_consumption_lut_for_enq_table));
            archive(::cereal::make_nvp("voq_cgm_slice_dram_cgm_profile_table", m.voq_cgm_slice_dram_cgm_profile_table));
            archive(::cereal::make_nvp("voq_cgm_slice_pd_consumption_lut_for_enq_table", m.voq_cgm_slice_pd_consumption_lut_for_enq_table));
            archive(::cereal::make_nvp("voq_cgm_slice_profile_buff_region_thresholds_table", m.voq_cgm_slice_profile_buff_region_thresholds_table));
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table", m.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table));
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_region_thresholds_table", m.voq_cgm_slice_profile_pkt_region_thresholds_table));
            archive(::cereal::make_nvp("voq_cgm_slice_slice_cgm_profile_table", m.voq_cgm_slice_slice_cgm_profile_table));
            archive(::cereal::make_nvp("vsid_table", m.vsid_table));
            archive(::cereal::make_nvp("vxlan_l2_dlp_table", m.vxlan_l2_dlp_table));
            archive(::cereal::make_nvp("inject_mact_ldb_to_output_lr", m.inject_mact_ldb_to_output_lr));
            archive(::cereal::make_nvp("lr_filter_write_ptr_reg", m.lr_filter_write_ptr_reg));
            archive(::cereal::make_nvp("lr_write_ptr_reg", m.lr_write_ptr_reg));
            archive(::cereal::make_nvp("m_device_id", m.m_device_id));
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::device_tables& m)
{
    serializer_class<silicon_one::device_tables>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::device_tables&);

template <class Archive>
void
load(Archive& archive, silicon_one::device_tables& m)
{
    serializer_class<silicon_one::device_tables>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::device_tables&);



}

