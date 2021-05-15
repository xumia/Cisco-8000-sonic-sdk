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

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_curr_and_next_prot_type_t&);
template <class Archive> void load(Archive&, npl_curr_and_next_prot_type_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ene_inject_down_payload_t&);
template <class Archive> void load(Archive&, npl_ene_inject_down_payload_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_extended_encap_data2_t&);
template <class Archive> void load(Archive&, npl_extended_encap_data2_t&);

template <class Archive> void save(Archive&, const npl_extended_encap_data_t&);
template <class Archive> void load(Archive&, npl_extended_encap_data_t&);

template <class Archive> void save(Archive&, const npl_fwd_layer_and_rtf_stage_compressed_fields_t&);
template <class Archive> void load(Archive&, npl_fwd_layer_and_rtf_stage_compressed_fields_t&);

template <class Archive> void save(Archive&, const npl_ip_encap_data_t&);
template <class Archive> void load(Archive&, npl_ip_encap_data_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_and_post_fwd_stage_t&);
template <class Archive> void load(Archive&, npl_ip_ver_and_post_fwd_stage_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_init_rtf_stage_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive> void save(Archive&, const npl_l2_relay_id_t&);
template <class Archive> void load(Archive&, npl_l2_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_large_em_label_encap_data_and_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_large_em_label_encap_data_and_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_lp_id_t&);
template <class Archive> void load(Archive&, npl_lp_id_t&);

template <class Archive> void save(Archive&, const npl_lp_rtf_conf_set_t&);
template <class Archive> void load(Archive&, npl_lp_rtf_conf_set_t&);

template <class Archive> void save(Archive&, const npl_lpm_prefix_fec_access_map_output_t&);
template <class Archive> void load(Archive&, npl_lpm_prefix_fec_access_map_output_t&);

template <class Archive> void save(Archive&, const npl_nhlfe_t&);
template <class Archive> void load(Archive&, npl_nhlfe_t&);

template <class Archive> void save(Archive&, const npl_obm_next_macro_static_table_update_next_macro_action_payload_t&);
template <class Archive> void load(Archive&, npl_obm_next_macro_static_table_update_next_macro_action_payload_t&);

template <class Archive> void save(Archive&, const npl_pbts_map_result_t&);
template <class Archive> void load(Archive&, npl_pbts_map_result_t&);

template <class Archive> void save(Archive&, const npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t&);
template <class Archive> void load(Archive&, npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t&);

template <class Archive> void save(Archive&, const npl_pdoq_oq_ifc_mapping_result_t&);
template <class Archive> void load(Archive&, npl_pdoq_oq_ifc_mapping_result_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_bank_pair_offset_result_t&);
template <class Archive> void load(Archive&, npl_pdvoq_bank_pair_offset_result_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_slice_dram_wred_lut_result_t&);
template <class Archive> void load(Archive&, npl_pdvoq_slice_dram_wred_lut_result_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_slice_voq_properties_result_t&);
template <class Archive> void load(Archive&, npl_pdvoq_slice_voq_properties_result_t&);

template <class Archive> void save(Archive&, const npl_per_rtf_step_og_pcl_compress_bits_t&);
template <class Archive> void load(Archive&, npl_per_rtf_step_og_pcl_compress_bits_t&);

template <class Archive> void save(Archive&, const npl_per_rtf_step_og_pcl_ids_t&);
template <class Archive> void load(Archive&, npl_per_rtf_step_og_pcl_ids_t&);

template <class Archive> void save(Archive&, const npl_pfc_em_lookup_t&);
template <class Archive> void load(Archive&, npl_pfc_em_lookup_t&);

template <class Archive> void save(Archive&, const npl_pfc_rx_counter_offset_t&);
template <class Archive> void load(Archive&, npl_pfc_rx_counter_offset_t&);

template <class Archive> void save(Archive&, const npl_pfc_ssp_info_table_t&);
template <class Archive> void load(Archive&, npl_pfc_ssp_info_table_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_pma_loopback_data_t&);
template <class Archive> void load(Archive&, npl_pma_loopback_data_t&);

template <class Archive> void save(Archive&, const npl_post_fwd_params_t&);
template <class Archive> void load(Archive&, npl_post_fwd_params_t&);

template <class Archive> void save(Archive&, const npl_punt_nw_encap_ptr_t&);
template <class Archive> void load(Archive&, npl_punt_nw_encap_ptr_t&);

template <class Archive> void save(Archive&, const npl_pwe_to_l3_lookup_result_t&);
template <class Archive> void load(Archive&, npl_pwe_to_l3_lookup_result_t&);

template <class Archive> void save(Archive&, const npl_reassembly_source_port_map_key_t&);
template <class Archive> void load(Archive&, npl_reassembly_source_port_map_key_t&);

template <class Archive> void save(Archive&, const npl_reassembly_source_port_map_result_t&);
template <class Archive> void load(Archive&, npl_reassembly_source_port_map_result_t&);

template <class Archive> void save(Archive&, const npl_redirect_code_t&);
template <class Archive> void load(Archive&, npl_redirect_code_t&);

template <class Archive> void save(Archive&, const npl_redirect_destination_reg_t&);
template <class Archive> void load(Archive&, npl_redirect_destination_reg_t&);

template <class Archive> void save(Archive&, const npl_rmep_data_t&);
template <class Archive> void load(Archive&, npl_rmep_data_t&);

template <class Archive> void save(Archive&, const npl_rtf_compressed_fields_for_next_macro_t&);
template <class Archive> void load(Archive&, npl_rtf_compressed_fields_for_next_macro_t&);

template <class Archive> void save(Archive&, const npl_rtf_step_t&);
template <class Archive> void load(Archive&, npl_rtf_step_t&);

template <class Archive> void save(Archive&, const npl_scanner_id_t&);
template <class Archive> void load(Archive&, npl_scanner_id_t&);

template <class Archive> void save(Archive&, const npl_select_macros_t&);
template <class Archive> void load(Archive&, npl_select_macros_t&);

template <class Archive> void save(Archive&, const npl_trap_conditions_t&);
template <class Archive> void load(Archive&, npl_trap_conditions_t&);

template <class Archive> void save(Archive&, const npl_traps_t&);
template <class Archive> void load(Archive&, npl_traps_t&);

template <class Archive> void save(Archive&, const npl_voq_profile_len&);
template <class Archive> void load(Archive&, npl_voq_profile_len&);

template <class Archive> void save(Archive&, const npl_vpn_label_encap_data_t&);
template <class Archive> void load(Archive&, npl_vpn_label_encap_data_t&);

template<>
class serializer_class<npl_obm_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_obm_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_obm_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_obm_next_macro_static_table_value_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_obm_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_obm_next_macro_static_table_value_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_obm_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_next_macro_action", m.update_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_next_macro_action", m.update_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_obm_next_macro_static_table_value_t::npl_obm_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_og_next_macro_static_table_set_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_og_next_macro_static_table_set_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_next_macro_static_table_set_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_og_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_og_next_macro_static_table_set_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_next_macro_static_table_set_macro_payload_t&);



template<>
class serializer_class<npl_og_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("ip_version", m.ip_version));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("ip_version", m.ip_version));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_next_macro_static_table_key_t& m)
{
    serializer_class<npl_og_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_og_next_macro_static_table_key_t& m)
{
    serializer_class<npl_og_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_og_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_next_macro_static_table_value_t& m)
{
    serializer_class<npl_og_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_og_next_macro_static_table_value_t& m)
{
    serializer_class<npl_og_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_og_next_macro_static_table_value_t::npl_og_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_outer_tpid_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_outer_tpid_table_key_t& m) {
        uint64_t m_tpid_ptr = m.tpid_ptr;
            archive(::cereal::make_nvp("tpid_ptr", m_tpid_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_outer_tpid_table_key_t& m) {
        uint64_t m_tpid_ptr;
            archive(::cereal::make_nvp("tpid_ptr", m_tpid_ptr));
        m.tpid_ptr = m_tpid_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_outer_tpid_table_key_t& m)
{
    serializer_class<npl_outer_tpid_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_outer_tpid_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_outer_tpid_table_key_t& m)
{
    serializer_class<npl_outer_tpid_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_outer_tpid_table_key_t&);



template<>
class serializer_class<npl_outer_tpid_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_outer_tpid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_outer_tpid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_outer_tpid_table_value_t& m)
{
    serializer_class<npl_outer_tpid_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_outer_tpid_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_outer_tpid_table_value_t& m)
{
    serializer_class<npl_outer_tpid_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_outer_tpid_table_value_t&);



template<>
class serializer_class<npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t& m) {
        uint64_t m_tpid = m.tpid;
            archive(::cereal::make_nvp("tpid", m_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t& m) {
        uint64_t m_tpid;
            archive(::cereal::make_nvp("tpid", m_tpid));
        m.tpid = m_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t& m)
{
    serializer_class<npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t& m)
{
    serializer_class<npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_outer_tpid_table_value_t::npl_outer_tpid_table_payloads_t&);



template<>
class serializer_class<npl_overlay_ipv4_sip_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_overlay_ipv4_sip_table_key_t& m) {
        uint64_t m_sip = m.sip;
        uint64_t m_vxlan_tunnel_loopback = m.vxlan_tunnel_loopback;
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("vxlan_tunnel_loopback", m_vxlan_tunnel_loopback));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_overlay_ipv4_sip_table_key_t& m) {
        uint64_t m_sip;
        uint64_t m_vxlan_tunnel_loopback;
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("vxlan_tunnel_loopback", m_vxlan_tunnel_loopback));
        m.sip = m_sip;
        m.vxlan_tunnel_loopback = m_vxlan_tunnel_loopback;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_overlay_ipv4_sip_table_key_t& m)
{
    serializer_class<npl_overlay_ipv4_sip_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_overlay_ipv4_sip_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_overlay_ipv4_sip_table_key_t& m)
{
    serializer_class<npl_overlay_ipv4_sip_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_overlay_ipv4_sip_table_key_t&);



template<>
class serializer_class<npl_overlay_ipv4_sip_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_overlay_ipv4_sip_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_overlay_ipv4_sip_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_overlay_ipv4_sip_table_value_t& m)
{
    serializer_class<npl_overlay_ipv4_sip_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_overlay_ipv4_sip_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_overlay_ipv4_sip_table_value_t& m)
{
    serializer_class<npl_overlay_ipv4_sip_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_overlay_ipv4_sip_table_value_t&);



template<>
class serializer_class<npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t& m) {
            archive(::cereal::make_nvp("slp_id", m.slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t& m) {
            archive(::cereal::make_nvp("slp_id", m.slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t& m)
{
    serializer_class<npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t& m)
{
    serializer_class<npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_overlay_ipv4_sip_table_value_t::npl_overlay_ipv4_sip_table_payloads_t&);



template<>
class serializer_class<npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pad_mtu_inj_check_static_table_pad_mtu_inj_next_macro_action_payload_t&);



template<>
class serializer_class<npl_pad_mtu_inj_check_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pad_mtu_inj_check_static_table_key_t& m) {
        uint64_t m_l3_tx_local_vars_fwd_pkt_size = m.l3_tx_local_vars_fwd_pkt_size;
            archive(::cereal::make_nvp("tx_npu_header_is_inject_up", m.tx_npu_header_is_inject_up));
            archive(::cereal::make_nvp("l3_tx_local_vars_fwd_pkt_size", m_l3_tx_local_vars_fwd_pkt_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pad_mtu_inj_check_static_table_key_t& m) {
        uint64_t m_l3_tx_local_vars_fwd_pkt_size;
            archive(::cereal::make_nvp("tx_npu_header_is_inject_up", m.tx_npu_header_is_inject_up));
            archive(::cereal::make_nvp("l3_tx_local_vars_fwd_pkt_size", m_l3_tx_local_vars_fwd_pkt_size));
        m.l3_tx_local_vars_fwd_pkt_size = m_l3_tx_local_vars_fwd_pkt_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pad_mtu_inj_check_static_table_key_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pad_mtu_inj_check_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pad_mtu_inj_check_static_table_key_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pad_mtu_inj_check_static_table_key_t&);



template<>
class serializer_class<npl_pad_mtu_inj_check_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pad_mtu_inj_check_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pad_mtu_inj_check_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pad_mtu_inj_check_static_table_value_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pad_mtu_inj_check_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pad_mtu_inj_check_static_table_value_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pad_mtu_inj_check_static_table_value_t&);



template<>
class serializer_class<npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("pad_mtu_inj_next_macro_action", m.pad_mtu_inj_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("pad_mtu_inj_next_macro_action", m.pad_mtu_inj_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t& m)
{
    serializer_class<npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pad_mtu_inj_check_static_table_value_t::npl_pad_mtu_inj_check_static_table_payloads_t&);



template<>
class serializer_class<npl_pbts_map_table_stage0_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage0_key_t& m) {
        uint64_t m_qos_3_bits = m.qos_3_bits;
        uint64_t m_destination_2_bits = m.destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage0_key_t& m) {
        uint64_t m_qos_3_bits;
        uint64_t m_destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
        m.qos_3_bits = m_qos_3_bits;
        m.destination_2_bits = m_destination_2_bits;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage0_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage0_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage0_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage0_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage0_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage0_key_t&);



template<>
class serializer_class<npl_pbts_map_table_stage0_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage0_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage0_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage0_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage0_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage0_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage0_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage0_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage0_value_t&);



template<>
class serializer_class<npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage0_value_t::npl_pbts_map_table_stage0_payloads_t&);



template<>
class serializer_class<npl_pbts_map_table_stage1_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage1_key_t& m) {
        uint64_t m_qos_3_bits = m.qos_3_bits;
        uint64_t m_destination_2_bits = m.destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage1_key_t& m) {
        uint64_t m_qos_3_bits;
        uint64_t m_destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
        m.qos_3_bits = m_qos_3_bits;
        m.destination_2_bits = m_destination_2_bits;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage1_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage1_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage1_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage1_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage1_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage1_key_t&);



template<>
class serializer_class<npl_pbts_map_table_stage1_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage1_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage1_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage1_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage1_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage1_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage1_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage1_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage1_value_t&);



template<>
class serializer_class<npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage1_value_t::npl_pbts_map_table_stage1_payloads_t&);



template<>
class serializer_class<npl_pbts_map_table_stage2_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage2_key_t& m) {
        uint64_t m_qos_3_bits = m.qos_3_bits;
        uint64_t m_destination_2_bits = m.destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage2_key_t& m) {
        uint64_t m_qos_3_bits;
        uint64_t m_destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
        m.qos_3_bits = m_qos_3_bits;
        m.destination_2_bits = m_destination_2_bits;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage2_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage2_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage2_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage2_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage2_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage2_key_t&);



template<>
class serializer_class<npl_pbts_map_table_stage2_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage2_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage2_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage2_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage2_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage2_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage2_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage2_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage2_value_t&);



template<>
class serializer_class<npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage2_value_t::npl_pbts_map_table_stage2_payloads_t&);



template<>
class serializer_class<npl_pbts_map_table_stage3_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage3_key_t& m) {
        uint64_t m_qos_3_bits = m.qos_3_bits;
        uint64_t m_destination_2_bits = m.destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage3_key_t& m) {
        uint64_t m_qos_3_bits;
        uint64_t m_destination_2_bits;
            archive(::cereal::make_nvp("qos_3_bits", m_qos_3_bits));
            archive(::cereal::make_nvp("destination_2_bits", m_destination_2_bits));
        m.qos_3_bits = m_qos_3_bits;
        m.destination_2_bits = m_destination_2_bits;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage3_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage3_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage3_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage3_key_t& m)
{
    serializer_class<npl_pbts_map_table_stage3_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage3_key_t&);



template<>
class serializer_class<npl_pbts_map_table_stage3_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage3_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage3_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage3_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage3_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage3_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage3_value_t& m)
{
    serializer_class<npl_pbts_map_table_stage3_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage3_value_t&);



template<>
class serializer_class<npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t& m) {
            archive(::cereal::make_nvp("pbts_map_res", m.pbts_map_res));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t& m)
{
    serializer_class<npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pbts_map_table_stage3_value_t::npl_pbts_map_table_stage3_payloads_t&);



template<>
class serializer_class<npl_pdoq_oq_ifc_mapping_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdoq_oq_ifc_mapping_key_t& m) {
        uint64_t m_dest_oq = m.dest_oq;
            archive(::cereal::make_nvp("dest_oq", m_dest_oq));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdoq_oq_ifc_mapping_key_t& m) {
        uint64_t m_dest_oq;
            archive(::cereal::make_nvp("dest_oq", m_dest_oq));
        m.dest_oq = m_dest_oq;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdoq_oq_ifc_mapping_key_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdoq_oq_ifc_mapping_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pdoq_oq_ifc_mapping_key_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdoq_oq_ifc_mapping_key_t&);



template<>
class serializer_class<npl_pdoq_oq_ifc_mapping_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdoq_oq_ifc_mapping_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdoq_oq_ifc_mapping_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdoq_oq_ifc_mapping_value_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdoq_oq_ifc_mapping_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pdoq_oq_ifc_mapping_value_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdoq_oq_ifc_mapping_value_t&);



template<>
class serializer_class<npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t& m) {
            archive(::cereal::make_nvp("pdoq_oq_ifc_mapping_result", m.pdoq_oq_ifc_mapping_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t& m) {
            archive(::cereal::make_nvp("pdoq_oq_ifc_mapping_result", m.pdoq_oq_ifc_mapping_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t& m)
{
    serializer_class<npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdoq_oq_ifc_mapping_value_t::npl_pdoq_oq_ifc_mapping_payloads_t&);



template<>
class serializer_class<npl_pdvoq_bank_pair_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_bank_pair_offset_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_bank_pair_offset_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_bank_pair_offset_table_key_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_bank_pair_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_bank_pair_offset_table_key_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_bank_pair_offset_table_key_t&);



template<>
class serializer_class<npl_pdvoq_bank_pair_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_bank_pair_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_bank_pair_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_bank_pair_offset_table_value_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_bank_pair_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_bank_pair_offset_table_value_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_bank_pair_offset_table_value_t&);



template<>
class serializer_class<npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("pdvoq_bank_pair_offset_result", m.pdvoq_bank_pair_offset_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("pdvoq_bank_pair_offset_result", m.pdvoq_bank_pair_offset_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t& m)
{
    serializer_class<npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_bank_pair_offset_table_value_t::npl_pdvoq_bank_pair_offset_table_payloads_t&);



template<>
class serializer_class<npl_pdvoq_slice_dram_wred_lut_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_slice_dram_wred_lut_table_key_t& m) {
        uint64_t m_packet_size_range = m.packet_size_range;
        uint64_t m_queue_size_level = m.queue_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("queue_size_level", m_queue_size_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_slice_dram_wred_lut_table_key_t& m) {
        uint64_t m_packet_size_range;
        uint64_t m_queue_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("queue_size_level", m_queue_size_level));
        m.packet_size_range = m_packet_size_range;
        m.queue_size_level = m_queue_size_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_slice_dram_wred_lut_table_key_t& m)
{
    serializer_class<npl_pdvoq_slice_dram_wred_lut_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_slice_dram_wred_lut_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_slice_dram_wred_lut_table_key_t& m)
{
    serializer_class<npl_pdvoq_slice_dram_wred_lut_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_slice_dram_wred_lut_table_key_t&);



template<>
class serializer_class<npl_pdvoq_slice_dram_wred_lut_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_slice_dram_wred_lut_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_slice_dram_wred_lut_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_slice_dram_wred_lut_table_value_t& m)
{
    serializer_class<npl_pdvoq_slice_dram_wred_lut_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_slice_dram_wred_lut_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_slice_dram_wred_lut_table_value_t& m)
{
    serializer_class<npl_pdvoq_slice_dram_wred_lut_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_slice_dram_wred_lut_table_value_t&);



template<>
class serializer_class<npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t& m) {
            archive(::cereal::make_nvp("pdvoq_slice_dram_wred_lut_result", m.pdvoq_slice_dram_wred_lut_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t& m) {
            archive(::cereal::make_nvp("pdvoq_slice_dram_wred_lut_result", m.pdvoq_slice_dram_wred_lut_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t& m)
{
    serializer_class<npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t& m)
{
    serializer_class<npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_slice_dram_wred_lut_table_value_t::npl_pdvoq_slice_dram_wred_lut_table_payloads_t&);



template<>
class serializer_class<npl_pdvoq_slice_voq_properties_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_slice_voq_properties_table_key_t& m) {
        uint64_t m_voq_num = m.voq_num;
            archive(::cereal::make_nvp("voq_num", m_voq_num));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_slice_voq_properties_table_key_t& m) {
        uint64_t m_voq_num;
            archive(::cereal::make_nvp("voq_num", m_voq_num));
        m.voq_num = m_voq_num;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_slice_voq_properties_table_key_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_slice_voq_properties_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_slice_voq_properties_table_key_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_slice_voq_properties_table_key_t&);



template<>
class serializer_class<npl_pdvoq_slice_voq_properties_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_slice_voq_properties_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_slice_voq_properties_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_slice_voq_properties_table_value_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_slice_voq_properties_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_slice_voq_properties_table_value_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_slice_voq_properties_table_value_t&);



template<>
class serializer_class<npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t& m) {
            archive(::cereal::make_nvp("pdvoq_slice_voq_properties_result", m.pdvoq_slice_voq_properties_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t& m) {
            archive(::cereal::make_nvp("pdvoq_slice_voq_properties_result", m.pdvoq_slice_voq_properties_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t& m)
{
    serializer_class<npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pdvoq_slice_voq_properties_table_value_t::npl_pdvoq_slice_voq_properties_table_payloads_t&);



template<>
class serializer_class<npl_per_asbr_and_dpe_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_asbr_and_dpe_table_key_t& m) {
        uint64_t m_dpe = m.dpe;
        uint64_t m_asbr = m.asbr;
            archive(::cereal::make_nvp("dpe", m_dpe));
            archive(::cereal::make_nvp("asbr", m_asbr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_asbr_and_dpe_table_key_t& m) {
        uint64_t m_dpe;
        uint64_t m_asbr;
            archive(::cereal::make_nvp("dpe", m_dpe));
            archive(::cereal::make_nvp("asbr", m_asbr));
        m.dpe = m_dpe;
        m.asbr = m_asbr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_asbr_and_dpe_table_key_t& m)
{
    serializer_class<npl_per_asbr_and_dpe_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_asbr_and_dpe_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_per_asbr_and_dpe_table_key_t& m)
{
    serializer_class<npl_per_asbr_and_dpe_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_asbr_and_dpe_table_key_t&);



template<>
class serializer_class<npl_per_asbr_and_dpe_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_asbr_and_dpe_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_asbr_and_dpe_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_asbr_and_dpe_table_value_t& m)
{
    serializer_class<npl_per_asbr_and_dpe_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_asbr_and_dpe_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_per_asbr_and_dpe_table_value_t& m)
{
    serializer_class<npl_per_asbr_and_dpe_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_asbr_and_dpe_table_value_t&);



template<>
class serializer_class<npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t& m) {
            archive(::cereal::make_nvp("large_em_label_encap_data_and_counter_ptr", m.large_em_label_encap_data_and_counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t& m) {
            archive(::cereal::make_nvp("large_em_label_encap_data_and_counter_ptr", m.large_em_label_encap_data_and_counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t& m)
{
    serializer_class<npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t& m)
{
    serializer_class<npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_asbr_and_dpe_table_value_t::npl_per_asbr_and_dpe_table_payloads_t&);



template<>
class serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_pe_and_prefix_vpn_key_large_table_key_t& m) {
        uint64_t m_ip_prefix_id = m.ip_prefix_id;
        uint64_t m_lsp_destination = m.lsp_destination;
            archive(::cereal::make_nvp("ip_prefix_id", m_ip_prefix_id));
            archive(::cereal::make_nvp("lsp_destination", m_lsp_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_pe_and_prefix_vpn_key_large_table_key_t& m) {
        uint64_t m_ip_prefix_id;
        uint64_t m_lsp_destination;
            archive(::cereal::make_nvp("ip_prefix_id", m_ip_prefix_id));
            archive(::cereal::make_nvp("lsp_destination", m_lsp_destination));
        m.ip_prefix_id = m_ip_prefix_id;
        m.lsp_destination = m_lsp_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_pe_and_prefix_vpn_key_large_table_key_t& m)
{
    serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_pe_and_prefix_vpn_key_large_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_per_pe_and_prefix_vpn_key_large_table_key_t& m)
{
    serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_pe_and_prefix_vpn_key_large_table_key_t&);



template<>
class serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_pe_and_prefix_vpn_key_large_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_pe_and_prefix_vpn_key_large_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_pe_and_prefix_vpn_key_large_table_value_t& m)
{
    serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_pe_and_prefix_vpn_key_large_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_per_pe_and_prefix_vpn_key_large_table_value_t& m)
{
    serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_pe_and_prefix_vpn_key_large_table_value_t&);



template<>
class serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t& m)
{
    serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t& m)
{
    serializer_class<npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_pe_and_prefix_vpn_key_large_table_value_t::npl_per_pe_and_prefix_vpn_key_large_table_payloads_t&);



template<>
class serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_pe_and_vrf_vpn_key_large_table_key_t& m) {
        uint64_t m_lsp_destination = m.lsp_destination;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("lsp_destination", m_lsp_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_pe_and_vrf_vpn_key_large_table_key_t& m) {
        uint64_t m_lsp_destination;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("lsp_destination", m_lsp_destination));
        m.lsp_destination = m_lsp_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_pe_and_vrf_vpn_key_large_table_key_t& m)
{
    serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_pe_and_vrf_vpn_key_large_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_per_pe_and_vrf_vpn_key_large_table_key_t& m)
{
    serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_pe_and_vrf_vpn_key_large_table_key_t&);



template<>
class serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_pe_and_vrf_vpn_key_large_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_pe_and_vrf_vpn_key_large_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_pe_and_vrf_vpn_key_large_table_value_t& m)
{
    serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_pe_and_vrf_vpn_key_large_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_per_pe_and_vrf_vpn_key_large_table_value_t& m)
{
    serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_pe_and_vrf_vpn_key_large_table_value_t&);



template<>
class serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t& m)
{
    serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t& m)
{
    serializer_class<npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_pe_and_vrf_vpn_key_large_table_value_t::npl_per_pe_and_vrf_vpn_key_large_table_payloads_t&);



template<>
class serializer_class<npl_per_port_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_port_destination_table_key_t& m) {
        uint64_t m_device_rx_source_if_pif = m.device_rx_source_if_pif;
        uint64_t m_device_rx_source_if_ifg = m.device_rx_source_if_ifg;
            archive(::cereal::make_nvp("device_rx_source_if_pif", m_device_rx_source_if_pif));
            archive(::cereal::make_nvp("device_rx_source_if_ifg", m_device_rx_source_if_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_port_destination_table_key_t& m) {
        uint64_t m_device_rx_source_if_pif;
        uint64_t m_device_rx_source_if_ifg;
            archive(::cereal::make_nvp("device_rx_source_if_pif", m_device_rx_source_if_pif));
            archive(::cereal::make_nvp("device_rx_source_if_ifg", m_device_rx_source_if_ifg));
        m.device_rx_source_if_pif = m_device_rx_source_if_pif;
        m.device_rx_source_if_ifg = m_device_rx_source_if_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_port_destination_table_key_t& m)
{
    serializer_class<npl_per_port_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_port_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_per_port_destination_table_key_t& m)
{
    serializer_class<npl_per_port_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_port_destination_table_key_t&);



template<>
class serializer_class<npl_per_port_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_port_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_port_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_port_destination_table_value_t& m)
{
    serializer_class<npl_per_port_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_port_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_per_port_destination_table_value_t& m)
{
    serializer_class<npl_per_port_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_port_destination_table_value_t&);



template<>
class serializer_class<npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t& m) {
        uint64_t m_destination_local_vars_fwd_destination = m.destination_local_vars_fwd_destination;
            archive(::cereal::make_nvp("destination_local_vars_fwd_destination", m_destination_local_vars_fwd_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t& m) {
        uint64_t m_destination_local_vars_fwd_destination;
            archive(::cereal::make_nvp("destination_local_vars_fwd_destination", m_destination_local_vars_fwd_destination));
        m.destination_local_vars_fwd_destination = m_destination_local_vars_fwd_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t& m)
{
    serializer_class<npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t& m)
{
    serializer_class<npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_port_destination_table_value_t::npl_per_port_destination_table_payloads_t&);



template<>
class serializer_class<npl_per_vrf_mpls_forwarding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_vrf_mpls_forwarding_table_key_t& m) {
        uint64_t m_label = m.label;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("vrf_id", m.vrf_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_vrf_mpls_forwarding_table_key_t& m) {
        uint64_t m_label;
            archive(::cereal::make_nvp("label", m_label));
            archive(::cereal::make_nvp("vrf_id", m.vrf_id));
        m.label = m_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_vrf_mpls_forwarding_table_key_t& m)
{
    serializer_class<npl_per_vrf_mpls_forwarding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_vrf_mpls_forwarding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_per_vrf_mpls_forwarding_table_key_t& m)
{
    serializer_class<npl_per_vrf_mpls_forwarding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_vrf_mpls_forwarding_table_key_t&);



template<>
class serializer_class<npl_per_vrf_mpls_forwarding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_vrf_mpls_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_vrf_mpls_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_vrf_mpls_forwarding_table_value_t& m)
{
    serializer_class<npl_per_vrf_mpls_forwarding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_vrf_mpls_forwarding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_per_vrf_mpls_forwarding_table_value_t& m)
{
    serializer_class<npl_per_vrf_mpls_forwarding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_vrf_mpls_forwarding_table_value_t&);



template<>
class serializer_class<npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("nhlfe", m.nhlfe));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("nhlfe", m.nhlfe));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t& m)
{
    serializer_class<npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t& m)
{
    serializer_class<npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_per_vrf_mpls_forwarding_table_value_t::npl_per_vrf_mpls_forwarding_table_payloads_t&);



template<>
class serializer_class<npl_pfc_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_destination_table_key_t& m) {
        uint64_t m_ssp1 = m.ssp1;
        uint64_t m_ssp2 = m.ssp2;
        uint64_t m_redirect1 = m.redirect1;
        uint64_t m_redirect2 = m.redirect2;
            archive(::cereal::make_nvp("ssp1", m_ssp1));
            archive(::cereal::make_nvp("ssp2", m_ssp2));
            archive(::cereal::make_nvp("redirect1", m_redirect1));
            archive(::cereal::make_nvp("redirect2", m_redirect2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_destination_table_key_t& m) {
        uint64_t m_ssp1;
        uint64_t m_ssp2;
        uint64_t m_redirect1;
        uint64_t m_redirect2;
            archive(::cereal::make_nvp("ssp1", m_ssp1));
            archive(::cereal::make_nvp("ssp2", m_ssp2));
            archive(::cereal::make_nvp("redirect1", m_redirect1));
            archive(::cereal::make_nvp("redirect2", m_redirect2));
        m.ssp1 = m_ssp1;
        m.ssp2 = m_ssp2;
        m.redirect1 = m_redirect1;
        m.redirect2 = m_redirect2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_destination_table_key_t& m)
{
    serializer_class<npl_pfc_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_destination_table_key_t& m)
{
    serializer_class<npl_pfc_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_destination_table_key_t&);



template<>
class serializer_class<npl_pfc_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_destination_table_value_t& m)
{
    serializer_class<npl_pfc_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_destination_table_value_t& m)
{
    serializer_class<npl_pfc_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_destination_table_value_t&);



template<>
class serializer_class<npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_em_lookup_result", m.pfc_em_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_em_lookup_result", m.pfc_em_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t& m)
{
    serializer_class<npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t& m)
{
    serializer_class<npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_destination_table_value_t::npl_pfc_destination_table_payloads_t&);



template<>
class serializer_class<npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_filter_wd_table_pfc_filter_wd_action_payload_t&);



template<>
class serializer_class<npl_pfc_filter_wd_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_filter_wd_table_key_t& m) {
        uint64_t m_tc = m.tc;
        uint64_t m_dsp = m.dsp;
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dsp", m_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_filter_wd_table_key_t& m) {
        uint64_t m_tc;
        uint64_t m_dsp;
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dsp", m_dsp));
        m.tc = m_tc;
        m.dsp = m_dsp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_filter_wd_table_key_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_filter_wd_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_filter_wd_table_key_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_filter_wd_table_key_t&);



template<>
class serializer_class<npl_pfc_filter_wd_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_filter_wd_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_filter_wd_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_filter_wd_table_value_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_filter_wd_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_filter_wd_table_value_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_filter_wd_table_value_t&);



template<>
class serializer_class<npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_filter_wd_action", m.pfc_filter_wd_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_filter_wd_action", m.pfc_filter_wd_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t& m)
{
    serializer_class<npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_filter_wd_table_value_t::npl_pfc_filter_wd_table_payloads_t&);



template<>
class serializer_class<npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t& m) {
        uint64_t m_trap = m.trap;
            archive(::cereal::make_nvp("offset", m.offset));
            archive(::cereal::make_nvp("trap", m_trap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t& m) {
        uint64_t m_trap;
            archive(::cereal::make_nvp("offset", m.offset));
            archive(::cereal::make_nvp("trap", m_trap));
        m.trap = m_trap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_offset_from_vector_static_table_update_mirror_commands_payload_t&);



template<>
class serializer_class<npl_pfc_offset_from_vector_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_offset_from_vector_static_table_key_t& m) {
        uint64_t m_vector = m.vector;
            archive(::cereal::make_nvp("vector", m_vector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_offset_from_vector_static_table_key_t& m) {
        uint64_t m_vector;
            archive(::cereal::make_nvp("vector", m_vector));
        m.vector = m_vector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_offset_from_vector_static_table_key_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_offset_from_vector_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_offset_from_vector_static_table_key_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_offset_from_vector_static_table_key_t&);



template<>
class serializer_class<npl_pfc_offset_from_vector_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_offset_from_vector_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_offset_from_vector_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_offset_from_vector_static_table_value_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_offset_from_vector_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_offset_from_vector_static_table_value_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_offset_from_vector_static_table_value_t&);



template<>
class serializer_class<npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_mirror_commands", m.update_mirror_commands));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_mirror_commands", m.update_mirror_commands));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t& m)
{
    serializer_class<npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_offset_from_vector_static_table_value_t::npl_pfc_offset_from_vector_static_table_payloads_t&);



template<>
class serializer_class<npl_pfc_ssp_slice_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_ssp_slice_map_table_key_t& m) {
        uint64_t m_ssp = m.ssp;
            archive(::cereal::make_nvp("ssp", m_ssp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_ssp_slice_map_table_key_t& m) {
        uint64_t m_ssp;
            archive(::cereal::make_nvp("ssp", m_ssp));
        m.ssp = m_ssp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_ssp_slice_map_table_key_t& m)
{
    serializer_class<npl_pfc_ssp_slice_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_ssp_slice_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_ssp_slice_map_table_key_t& m)
{
    serializer_class<npl_pfc_ssp_slice_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_ssp_slice_map_table_key_t&);



template<>
class serializer_class<npl_pfc_ssp_slice_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_ssp_slice_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_ssp_slice_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_ssp_slice_map_table_value_t& m)
{
    serializer_class<npl_pfc_ssp_slice_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_ssp_slice_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_ssp_slice_map_table_value_t& m)
{
    serializer_class<npl_pfc_ssp_slice_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_ssp_slice_map_table_value_t&);



template<>
class serializer_class<npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_ssp_info", m.pfc_ssp_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_ssp_info", m.pfc_ssp_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t& m)
{
    serializer_class<npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t& m)
{
    serializer_class<npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_ssp_slice_map_table_value_t::npl_pfc_ssp_slice_map_table_payloads_t&);



template<>
class serializer_class<npl_pin_start_offset_macros_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pin_start_offset_macros_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pin_start_offset_macros_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pin_start_offset_macros_key_t& m)
{
    serializer_class<npl_pin_start_offset_macros_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pin_start_offset_macros_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pin_start_offset_macros_key_t& m)
{
    serializer_class<npl_pin_start_offset_macros_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pin_start_offset_macros_key_t&);



template<>
class serializer_class<npl_pin_start_offset_macros_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pin_start_offset_macros_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pin_start_offset_macros_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pin_start_offset_macros_value_t& m)
{
    serializer_class<npl_pin_start_offset_macros_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pin_start_offset_macros_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pin_start_offset_macros_value_t& m)
{
    serializer_class<npl_pin_start_offset_macros_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pin_start_offset_macros_value_t&);



template<>
class serializer_class<npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t& m) {
            archive(::cereal::make_nvp("select_macros", m.select_macros));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t& m) {
            archive(::cereal::make_nvp("select_macros", m.select_macros));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t& m)
{
    serializer_class<npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t& m)
{
    serializer_class<npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pin_start_offset_macros_value_t::npl_pin_start_offset_macros_payloads_t&);



template<>
class serializer_class<npl_pma_loopback_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pma_loopback_table_key_t& m) {
        uint64_t m_device_packet_info_ifg = m.device_packet_info_ifg;
        uint64_t m_device_packet_info_pif = m.device_packet_info_pif;
            archive(::cereal::make_nvp("device_packet_info_ifg", m_device_packet_info_ifg));
            archive(::cereal::make_nvp("device_packet_info_pif", m_device_packet_info_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pma_loopback_table_key_t& m) {
        uint64_t m_device_packet_info_ifg;
        uint64_t m_device_packet_info_pif;
            archive(::cereal::make_nvp("device_packet_info_ifg", m_device_packet_info_ifg));
            archive(::cereal::make_nvp("device_packet_info_pif", m_device_packet_info_pif));
        m.device_packet_info_ifg = m_device_packet_info_ifg;
        m.device_packet_info_pif = m_device_packet_info_pif;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pma_loopback_table_key_t& m)
{
    serializer_class<npl_pma_loopback_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pma_loopback_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pma_loopback_table_key_t& m)
{
    serializer_class<npl_pma_loopback_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pma_loopback_table_key_t&);



template<>
class serializer_class<npl_pma_loopback_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pma_loopback_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pma_loopback_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pma_loopback_table_value_t& m)
{
    serializer_class<npl_pma_loopback_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pma_loopback_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pma_loopback_table_value_t& m)
{
    serializer_class<npl_pma_loopback_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pma_loopback_table_value_t&);



template<>
class serializer_class<npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t& m) {
            archive(::cereal::make_nvp("pma_loopback_data", m.pma_loopback_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t& m) {
            archive(::cereal::make_nvp("pma_loopback_data", m.pma_loopback_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t& m)
{
    serializer_class<npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t& m)
{
    serializer_class<npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pma_loopback_table_value_t::npl_pma_loopback_table_payloads_t&);



template<>
class serializer_class<npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_post_fwd_rtf_next_macro_static_table_set_macro_payload_t&);



template<>
class serializer_class<npl_post_fwd_rtf_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_key_t& m) {
        uint64_t m_next_proto_type = m.next_proto_type;
            archive(::cereal::make_nvp("ip_ver_and_post_fwd_stage", m.ip_ver_and_post_fwd_stage));
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
            archive(::cereal::make_nvp("eth_rtf_stage", m.eth_rtf_stage));
            archive(::cereal::make_nvp("fwd_layer_and_rtf_stage", m.fwd_layer_and_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_key_t& m) {
        uint64_t m_next_proto_type;
            archive(::cereal::make_nvp("ip_ver_and_post_fwd_stage", m.ip_ver_and_post_fwd_stage));
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
            archive(::cereal::make_nvp("eth_rtf_stage", m.eth_rtf_stage));
            archive(::cereal::make_nvp("fwd_layer_and_rtf_stage", m.fwd_layer_and_rtf_stage));
        m.next_proto_type = m_next_proto_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_key_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_post_fwd_rtf_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_key_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_post_fwd_rtf_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_post_fwd_rtf_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_value_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_post_fwd_rtf_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_value_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_post_fwd_rtf_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_post_fwd_rtf_next_macro_static_table_value_t::npl_post_fwd_rtf_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_probe_marker_1_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_probe_marker_1_static_table_key_t& m) {
        uint64_t m_probe_marker_1 = m.probe_marker_1;
            archive(::cereal::make_nvp("probe_marker_1", m_probe_marker_1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_probe_marker_1_static_table_key_t& m) {
        uint64_t m_probe_marker_1;
            archive(::cereal::make_nvp("probe_marker_1", m_probe_marker_1));
        m.probe_marker_1 = m_probe_marker_1;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_probe_marker_1_static_table_key_t& m)
{
    serializer_class<npl_probe_marker_1_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_probe_marker_1_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_probe_marker_1_static_table_key_t& m)
{
    serializer_class<npl_probe_marker_1_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_probe_marker_1_static_table_key_t&);



template<>
class serializer_class<npl_probe_marker_1_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_probe_marker_1_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_probe_marker_1_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_probe_marker_1_static_table_value_t& m)
{
    serializer_class<npl_probe_marker_1_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_probe_marker_1_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_probe_marker_1_static_table_value_t& m)
{
    serializer_class<npl_probe_marker_1_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_probe_marker_1_static_table_value_t&);



template<>
class serializer_class<npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("probe_marker_1_match", m.probe_marker_1_match));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("probe_marker_1_match", m.probe_marker_1_match));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t& m)
{
    serializer_class<npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t& m)
{
    serializer_class<npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_probe_marker_1_static_table_value_t::npl_probe_marker_1_static_table_payloads_t&);



template<>
class serializer_class<npl_probe_marker_2_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_probe_marker_2_static_table_key_t& m) {
        uint64_t m_probe_marker_2 = m.probe_marker_2;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("probe_marker_2", m_probe_marker_2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_probe_marker_2_static_table_key_t& m) {
        uint64_t m_probe_marker_2;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("probe_marker_2", m_probe_marker_2));
        m.probe_marker_2 = m_probe_marker_2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_probe_marker_2_static_table_key_t& m)
{
    serializer_class<npl_probe_marker_2_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_probe_marker_2_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_probe_marker_2_static_table_key_t& m)
{
    serializer_class<npl_probe_marker_2_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_probe_marker_2_static_table_key_t&);



template<>
class serializer_class<npl_probe_marker_2_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_probe_marker_2_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_probe_marker_2_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_probe_marker_2_static_table_value_t& m)
{
    serializer_class<npl_probe_marker_2_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_probe_marker_2_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_probe_marker_2_static_table_value_t& m)
{
    serializer_class<npl_probe_marker_2_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_probe_marker_2_static_table_value_t&);



template<>
class serializer_class<npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("probe_marker_2_match", m.probe_marker_2_match));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("probe_marker_2_match", m.probe_marker_2_match));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t& m)
{
    serializer_class<npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t& m)
{
    serializer_class<npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_probe_marker_2_static_table_value_t::npl_probe_marker_2_static_table_payloads_t&);



template<>
class serializer_class<npl_punt_ethertype_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_ethertype_static_table_key_t& m) {
        uint64_t m_punt_nw_encap_type = m.punt_nw_encap_type;
            archive(::cereal::make_nvp("punt_nw_encap_type", m_punt_nw_encap_type));
            archive(::cereal::make_nvp("punt_format", m.punt_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_ethertype_static_table_key_t& m) {
        uint64_t m_punt_nw_encap_type;
            archive(::cereal::make_nvp("punt_nw_encap_type", m_punt_nw_encap_type));
            archive(::cereal::make_nvp("punt_format", m.punt_format));
        m.punt_nw_encap_type = m_punt_nw_encap_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_ethertype_static_table_key_t& m)
{
    serializer_class<npl_punt_ethertype_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_ethertype_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_ethertype_static_table_key_t& m)
{
    serializer_class<npl_punt_ethertype_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_ethertype_static_table_key_t&);



template<>
class serializer_class<npl_punt_ethertype_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_ethertype_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_ethertype_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_ethertype_static_table_value_t& m)
{
    serializer_class<npl_punt_ethertype_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_ethertype_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_ethertype_static_table_value_t& m)
{
    serializer_class<npl_punt_ethertype_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_ethertype_static_table_value_t&);



template<>
class serializer_class<npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t& m) {
        uint64_t m_pd_ene_encap_data_punt_ethertype = m.pd_ene_encap_data_punt_ethertype;
            archive(::cereal::make_nvp("pd_ene_encap_data_punt_ethertype", m_pd_ene_encap_data_punt_ethertype));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t& m) {
        uint64_t m_pd_ene_encap_data_punt_ethertype;
            archive(::cereal::make_nvp("pd_ene_encap_data_punt_ethertype", m_pd_ene_encap_data_punt_ethertype));
        m.pd_ene_encap_data_punt_ethertype = m_pd_ene_encap_data_punt_ethertype;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t& m)
{
    serializer_class<npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t& m)
{
    serializer_class<npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_ethertype_static_table_value_t::npl_punt_ethertype_static_table_payloads_t&);



template<>
class serializer_class<npl_punt_rcy_inject_header_ene_encap_table_found_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_found_payload_t& m) {
            archive(::cereal::make_nvp("ene_inject_down_payload", m.ene_inject_down_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_found_payload_t& m) {
            archive(::cereal::make_nvp("ene_inject_down_payload", m.ene_inject_down_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_found_payload_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_found_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_rcy_inject_header_ene_encap_table_found_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_found_payload_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_found_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_rcy_inject_header_ene_encap_table_found_payload_t&);



template<>
class serializer_class<npl_punt_rcy_inject_header_ene_encap_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_key_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_rcy_inject_header_ene_encap_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_key_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_rcy_inject_header_ene_encap_table_key_t&);



template<>
class serializer_class<npl_punt_rcy_inject_header_ene_encap_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_value_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_rcy_inject_header_ene_encap_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_value_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_rcy_inject_header_ene_encap_table_value_t&);



template<>
class serializer_class<npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t& m)
{
    serializer_class<npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_rcy_inject_header_ene_encap_table_value_t::npl_punt_rcy_inject_header_ene_encap_table_payloads_t&);



template<>
class serializer_class<npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t& m) {
            archive(::cereal::make_nvp("first_ene_macro", m.first_ene_macro));
            archive(::cereal::make_nvp("ene_macro_0", m.ene_macro_0));
            archive(::cereal::make_nvp("ene_macro_1", m.ene_macro_1));
            archive(::cereal::make_nvp("ene_macro_2", m.ene_macro_2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t& m) {
            archive(::cereal::make_nvp("first_ene_macro", m.first_ene_macro));
            archive(::cereal::make_nvp("ene_macro_0", m.ene_macro_0));
            archive(::cereal::make_nvp("ene_macro_1", m.ene_macro_1));
            archive(::cereal::make_nvp("ene_macro_2", m.ene_macro_2));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_select_nw_ene_static_table_tx_punt_set_ene_macro_payload_t&);



template<>
class serializer_class<npl_punt_select_nw_ene_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_select_nw_ene_static_table_key_t& m) {
        uint64_t m_is_punt_rcy = m.is_punt_rcy;
            archive(::cereal::make_nvp("is_punt_rcy", m_is_punt_rcy));
            archive(::cereal::make_nvp("punt_nw_encap_type", m.punt_nw_encap_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_select_nw_ene_static_table_key_t& m) {
        uint64_t m_is_punt_rcy;
            archive(::cereal::make_nvp("is_punt_rcy", m_is_punt_rcy));
            archive(::cereal::make_nvp("punt_nw_encap_type", m.punt_nw_encap_type));
        m.is_punt_rcy = m_is_punt_rcy;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_select_nw_ene_static_table_key_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_select_nw_ene_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_select_nw_ene_static_table_key_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_select_nw_ene_static_table_key_t&);



template<>
class serializer_class<npl_punt_select_nw_ene_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_select_nw_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_select_nw_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_select_nw_ene_static_table_value_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_select_nw_ene_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_select_nw_ene_static_table_value_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_select_nw_ene_static_table_value_t&);



template<>
class serializer_class<npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("tx_punt_set_ene_macro", m.tx_punt_set_ene_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("tx_punt_set_ene_macro", m.tx_punt_set_ene_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t& m)
{
    serializer_class<npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_select_nw_ene_static_table_value_t::npl_punt_select_nw_ene_static_table_payloads_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_encap_table_ip_gre_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_encap_table_ip_gre_payload_t& m) {
        uint64_t m_tos = m.tos;
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("ip_encap_data", m.ip_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_encap_table_ip_gre_payload_t& m) {
        uint64_t m_tos;
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("ip_encap_data", m.ip_encap_data));
        m.tos = m_tos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_encap_table_ip_gre_payload_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_ip_gre_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_encap_table_ip_gre_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_encap_table_ip_gre_payload_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_ip_gre_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_encap_table_ip_gre_payload_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_encap_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_encap_table_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_encap_table_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_encap_table_key_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_encap_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_encap_table_key_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_encap_table_key_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_encap_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_encap_table_value_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_encap_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_encap_table_value_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_encap_table_value_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_gre", m.ip_gre));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_gre", m.ip_gre));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t& m)
{
    serializer_class<npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_encap_table_value_t::npl_punt_tunnel_transport_encap_table_payloads_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_extended_encap_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table_key_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_extended_encap_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table_key_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_extended_encap_table_key_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_extended_encap_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table_value_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_extended_encap_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table_value_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_extended_encap_table_value_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("extended_encap_data", m.extended_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("extended_encap_data", m.extended_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_extended_encap_table_value_t::npl_punt_tunnel_transport_extended_encap_table_payloads_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_extended_encap_table2_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table2_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table2_key_t& m) {
            archive(::cereal::make_nvp("punt_nw_encap_ptr", m.punt_nw_encap_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table2_key_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table2_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_extended_encap_table2_key_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table2_key_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table2_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_extended_encap_table2_key_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_extended_encap_table2_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table2_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table2_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table2_value_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table2_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_extended_encap_table2_value_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table2_value_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table2_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_extended_encap_table2_value_t&);



template<>
class serializer_class<npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t& m) {
            archive(::cereal::make_nvp("extended_encap_data2", m.extended_encap_data2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t& m) {
            archive(::cereal::make_nvp("extended_encap_data2", m.extended_encap_data2));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t& m)
{
    serializer_class<npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_punt_tunnel_transport_extended_encap_table2_value_t::npl_punt_tunnel_transport_extended_encap_table2_payloads_t&);



template<>
class serializer_class<npl_pwe_label_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_label_table_key_t& m) {
        uint64_t m_pwe_id = m.pwe_id;
            archive(::cereal::make_nvp("pwe_id", m_pwe_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_label_table_key_t& m) {
        uint64_t m_pwe_id;
            archive(::cereal::make_nvp("pwe_id", m_pwe_id));
        m.pwe_id = m_pwe_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_label_table_key_t& m)
{
    serializer_class<npl_pwe_label_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_label_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_label_table_key_t& m)
{
    serializer_class<npl_pwe_label_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_label_table_key_t&);



template<>
class serializer_class<npl_pwe_label_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_label_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_label_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_label_table_value_t& m)
{
    serializer_class<npl_pwe_label_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_label_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_label_table_value_t& m)
{
    serializer_class<npl_pwe_label_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_label_table_value_t&);



template<>
class serializer_class<npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t& m)
{
    serializer_class<npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t& m)
{
    serializer_class<npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_label_table_value_t::npl_pwe_label_table_payloads_t&);



template<>
class serializer_class<npl_pwe_to_l3_dest_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_to_l3_dest_table_key_t& m) {
        uint64_t m_pwe_l2_dlp = m.pwe_l2_dlp;
            archive(::cereal::make_nvp("pwe_l2_dlp", m_pwe_l2_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_to_l3_dest_table_key_t& m) {
        uint64_t m_pwe_l2_dlp;
            archive(::cereal::make_nvp("pwe_l2_dlp", m_pwe_l2_dlp));
        m.pwe_l2_dlp = m_pwe_l2_dlp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_to_l3_dest_table_key_t& m)
{
    serializer_class<npl_pwe_to_l3_dest_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_to_l3_dest_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_to_l3_dest_table_key_t& m)
{
    serializer_class<npl_pwe_to_l3_dest_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_to_l3_dest_table_key_t&);



template<>
class serializer_class<npl_pwe_to_l3_dest_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_to_l3_dest_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_to_l3_dest_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_to_l3_dest_table_value_t& m)
{
    serializer_class<npl_pwe_to_l3_dest_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_to_l3_dest_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_to_l3_dest_table_value_t& m)
{
    serializer_class<npl_pwe_to_l3_dest_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_to_l3_dest_table_value_t&);



template<>
class serializer_class<npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t& m) {
            archive(::cereal::make_nvp("l3_destination", m.l3_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t& m) {
            archive(::cereal::make_nvp("l3_destination", m.l3_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t& m)
{
    serializer_class<npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t& m)
{
    serializer_class<npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_to_l3_dest_table_value_t::npl_pwe_to_l3_dest_table_payloads_t&);



template<>
class serializer_class<npl_pwe_vpls_label_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_vpls_label_table_key_t& m) {
        uint64_t m_lsp_destination = m.lsp_destination;
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("lsp_destination", m_lsp_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_vpls_label_table_key_t& m) {
        uint64_t m_lsp_destination;
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("lsp_destination", m_lsp_destination));
        m.lsp_destination = m_lsp_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_vpls_label_table_key_t& m)
{
    serializer_class<npl_pwe_vpls_label_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_vpls_label_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_vpls_label_table_key_t& m)
{
    serializer_class<npl_pwe_vpls_label_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_vpls_label_table_key_t&);



template<>
class serializer_class<npl_pwe_vpls_label_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_vpls_label_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_vpls_label_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_vpls_label_table_value_t& m)
{
    serializer_class<npl_pwe_vpls_label_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_vpls_label_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_vpls_label_table_value_t& m)
{
    serializer_class<npl_pwe_vpls_label_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_vpls_label_table_value_t&);



template<>
class serializer_class<npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t& m)
{
    serializer_class<npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t& m)
{
    serializer_class<npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_vpls_label_table_value_t::npl_pwe_vpls_label_table_payloads_t&);



template<>
class serializer_class<npl_pwe_vpls_tunnel_label_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_vpls_tunnel_label_table_key_t& m) {
        uint64_t m_te_tunnel = m.te_tunnel;
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_vpls_tunnel_label_table_key_t& m) {
        uint64_t m_te_tunnel;
            archive(::cereal::make_nvp("l2_relay_id", m.l2_relay_id));
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
        m.te_tunnel = m_te_tunnel;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_vpls_tunnel_label_table_key_t& m)
{
    serializer_class<npl_pwe_vpls_tunnel_label_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_vpls_tunnel_label_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_vpls_tunnel_label_table_key_t& m)
{
    serializer_class<npl_pwe_vpls_tunnel_label_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_vpls_tunnel_label_table_key_t&);



template<>
class serializer_class<npl_pwe_vpls_tunnel_label_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_vpls_tunnel_label_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_vpls_tunnel_label_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_vpls_tunnel_label_table_value_t& m)
{
    serializer_class<npl_pwe_vpls_tunnel_label_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_vpls_tunnel_label_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_vpls_tunnel_label_table_value_t& m)
{
    serializer_class<npl_pwe_vpls_tunnel_label_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_vpls_tunnel_label_table_value_t&);



template<>
class serializer_class<npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t& m) {
            archive(::cereal::make_nvp("vpn_encap_data", m.vpn_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t& m)
{
    serializer_class<npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t& m)
{
    serializer_class<npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pwe_vpls_tunnel_label_table_value_t::npl_pwe_vpls_tunnel_label_table_payloads_t&);



template<>
class serializer_class<npl_reassembly_source_port_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_reassembly_source_port_map_table_key_t& m) {
            archive(::cereal::make_nvp("source_if", m.source_if));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_reassembly_source_port_map_table_key_t& m) {
            archive(::cereal::make_nvp("source_if", m.source_if));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_reassembly_source_port_map_table_key_t& m)
{
    serializer_class<npl_reassembly_source_port_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_reassembly_source_port_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_reassembly_source_port_map_table_key_t& m)
{
    serializer_class<npl_reassembly_source_port_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_reassembly_source_port_map_table_key_t&);



template<>
class serializer_class<npl_reassembly_source_port_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_reassembly_source_port_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_reassembly_source_port_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_reassembly_source_port_map_table_value_t& m)
{
    serializer_class<npl_reassembly_source_port_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_reassembly_source_port_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_reassembly_source_port_map_table_value_t& m)
{
    serializer_class<npl_reassembly_source_port_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_reassembly_source_port_map_table_value_t&);



template<>
class serializer_class<npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("reassembly_source_port_map_result", m.reassembly_source_port_map_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("reassembly_source_port_map_result", m.reassembly_source_port_map_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t& m)
{
    serializer_class<npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t& m)
{
    serializer_class<npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_reassembly_source_port_map_table_value_t::npl_reassembly_source_port_map_table_payloads_t&);



template<>
class serializer_class<npl_recycle_override_table_init_rx_data_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycle_override_table_init_rx_data_payload_t& m) {
        uint64_t m_override_source_port_table = m.override_source_port_table;
        uint64_t m_first_header_type = m.first_header_type;
        uint64_t m_first_header_is_layer = m.first_header_is_layer;
        uint64_t m_initial_layer_index = m.initial_layer_index;
        uint64_t m_np_macro_id = m.np_macro_id;
        uint64_t m_fi_macro_id = m.fi_macro_id;
            archive(::cereal::make_nvp("override_source_port_table", m_override_source_port_table));
            archive(::cereal::make_nvp("first_header_type", m_first_header_type));
            archive(::cereal::make_nvp("first_header_is_layer", m_first_header_is_layer));
            archive(::cereal::make_nvp("initial_layer_index", m_initial_layer_index));
            archive(::cereal::make_nvp("initial_rx_data", m.initial_rx_data));
            archive(::cereal::make_nvp("tag_swap_cmd", m.tag_swap_cmd));
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
            archive(::cereal::make_nvp("fi_macro_id", m_fi_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycle_override_table_init_rx_data_payload_t& m) {
        uint64_t m_override_source_port_table;
        uint64_t m_first_header_type;
        uint64_t m_first_header_is_layer;
        uint64_t m_initial_layer_index;
        uint64_t m_np_macro_id;
        uint64_t m_fi_macro_id;
            archive(::cereal::make_nvp("override_source_port_table", m_override_source_port_table));
            archive(::cereal::make_nvp("first_header_type", m_first_header_type));
            archive(::cereal::make_nvp("first_header_is_layer", m_first_header_is_layer));
            archive(::cereal::make_nvp("initial_layer_index", m_initial_layer_index));
            archive(::cereal::make_nvp("initial_rx_data", m.initial_rx_data));
            archive(::cereal::make_nvp("tag_swap_cmd", m.tag_swap_cmd));
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
            archive(::cereal::make_nvp("fi_macro_id", m_fi_macro_id));
        m.override_source_port_table = m_override_source_port_table;
        m.first_header_type = m_first_header_type;
        m.first_header_is_layer = m_first_header_is_layer;
        m.initial_layer_index = m_initial_layer_index;
        m.np_macro_id = m_np_macro_id;
        m.fi_macro_id = m_fi_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycle_override_table_init_rx_data_payload_t& m)
{
    serializer_class<npl_recycle_override_table_init_rx_data_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycle_override_table_init_rx_data_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_recycle_override_table_init_rx_data_payload_t& m)
{
    serializer_class<npl_recycle_override_table_init_rx_data_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycle_override_table_init_rx_data_payload_t&);



template<>
class serializer_class<npl_recycle_override_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycle_override_table_key_t& m) {
        uint64_t m_rxpp_npu_input_rcy_code_1_ = m.rxpp_npu_input_rcy_code_1_;
        uint64_t m_packet_is_rescheduled_recycle = m.packet_is_rescheduled_recycle;
        uint64_t m_rxpp_npu_input_tx_to_rx_rcy_data_3_0_ = m.rxpp_npu_input_tx_to_rx_rcy_data_3_0_;
            archive(::cereal::make_nvp("rxpp_npu_input_rcy_code_1_", m_rxpp_npu_input_rcy_code_1_));
            archive(::cereal::make_nvp("packet_is_rescheduled_recycle", m_packet_is_rescheduled_recycle));
            archive(::cereal::make_nvp("rxpp_npu_input_tx_to_rx_rcy_data_3_0_", m_rxpp_npu_input_tx_to_rx_rcy_data_3_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycle_override_table_key_t& m) {
        uint64_t m_rxpp_npu_input_rcy_code_1_;
        uint64_t m_packet_is_rescheduled_recycle;
        uint64_t m_rxpp_npu_input_tx_to_rx_rcy_data_3_0_;
            archive(::cereal::make_nvp("rxpp_npu_input_rcy_code_1_", m_rxpp_npu_input_rcy_code_1_));
            archive(::cereal::make_nvp("packet_is_rescheduled_recycle", m_packet_is_rescheduled_recycle));
            archive(::cereal::make_nvp("rxpp_npu_input_tx_to_rx_rcy_data_3_0_", m_rxpp_npu_input_tx_to_rx_rcy_data_3_0_));
        m.rxpp_npu_input_rcy_code_1_ = m_rxpp_npu_input_rcy_code_1_;
        m.packet_is_rescheduled_recycle = m_packet_is_rescheduled_recycle;
        m.rxpp_npu_input_tx_to_rx_rcy_data_3_0_ = m_rxpp_npu_input_tx_to_rx_rcy_data_3_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycle_override_table_key_t& m)
{
    serializer_class<npl_recycle_override_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycle_override_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_recycle_override_table_key_t& m)
{
    serializer_class<npl_recycle_override_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycle_override_table_key_t&);



template<>
class serializer_class<npl_recycle_override_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycle_override_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycle_override_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycle_override_table_value_t& m)
{
    serializer_class<npl_recycle_override_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycle_override_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_recycle_override_table_value_t& m)
{
    serializer_class<npl_recycle_override_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycle_override_table_value_t&);



template<>
class serializer_class<npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_rx_data", m.init_rx_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_rx_data", m.init_rx_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t& m)
{
    serializer_class<npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t& m)
{
    serializer_class<npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycle_override_table_value_t::npl_recycle_override_table_payloads_t&);



template<>
class serializer_class<npl_recycled_inject_up_info_table_update_data_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycled_inject_up_info_table_update_data_payload_t& m) {
        uint64_t m_ssp = m.ssp;
            archive(::cereal::make_nvp("ssp", m_ssp));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("init_data_selector", m.init_data_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycled_inject_up_info_table_update_data_payload_t& m) {
        uint64_t m_ssp;
            archive(::cereal::make_nvp("ssp", m_ssp));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("init_data_selector", m.init_data_selector));
        m.ssp = m_ssp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycled_inject_up_info_table_update_data_payload_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_update_data_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycled_inject_up_info_table_update_data_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_recycled_inject_up_info_table_update_data_payload_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_update_data_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycled_inject_up_info_table_update_data_payload_t&);



template<>
class serializer_class<npl_recycled_inject_up_info_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycled_inject_up_info_table_key_t& m) {
        uint64_t m_tx_to_rx_rcy_data = m.tx_to_rx_rcy_data;
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m_tx_to_rx_rcy_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycled_inject_up_info_table_key_t& m) {
        uint64_t m_tx_to_rx_rcy_data;
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m_tx_to_rx_rcy_data));
        m.tx_to_rx_rcy_data = m_tx_to_rx_rcy_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycled_inject_up_info_table_key_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycled_inject_up_info_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_recycled_inject_up_info_table_key_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycled_inject_up_info_table_key_t&);



template<>
class serializer_class<npl_recycled_inject_up_info_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycled_inject_up_info_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycled_inject_up_info_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycled_inject_up_info_table_value_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycled_inject_up_info_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_recycled_inject_up_info_table_value_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycled_inject_up_info_table_value_t&);



template<>
class serializer_class<npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_data", m.update_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_data", m.update_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t& m)
{
    serializer_class<npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_recycled_inject_up_info_table_value_t::npl_recycled_inject_up_info_table_payloads_t&);



template<>
class serializer_class<npl_redirect_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_destination_table_key_t& m) {
        uint64_t m_device_packet_info_ifg = m.device_packet_info_ifg;
            archive(::cereal::make_nvp("device_packet_info_ifg", m_device_packet_info_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_destination_table_key_t& m) {
        uint64_t m_device_packet_info_ifg;
            archive(::cereal::make_nvp("device_packet_info_ifg", m_device_packet_info_ifg));
        m.device_packet_info_ifg = m_device_packet_info_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_destination_table_key_t& m)
{
    serializer_class<npl_redirect_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_destination_table_key_t& m)
{
    serializer_class<npl_redirect_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_destination_table_key_t&);



template<>
class serializer_class<npl_redirect_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_destination_table_value_t& m)
{
    serializer_class<npl_redirect_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_destination_table_value_t& m)
{
    serializer_class<npl_redirect_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_destination_table_value_t&);



template<>
class serializer_class<npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("redirect_destination_reg", m.redirect_destination_reg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("redirect_destination_reg", m.redirect_destination_reg));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t& m)
{
    serializer_class<npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t& m)
{
    serializer_class<npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_destination_table_value_t::npl_redirect_destination_table_payloads_t&);



template<>
class serializer_class<npl_redirect_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_table_key_t& m) {
            archive(::cereal::make_nvp("traps", m.traps));
            archive(::cereal::make_nvp("trap_conditions", m.trap_conditions));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_table_key_t& m) {
            archive(::cereal::make_nvp("traps", m.traps));
            archive(::cereal::make_nvp("trap_conditions", m.trap_conditions));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_table_key_t& m)
{
    serializer_class<npl_redirect_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_table_key_t& m)
{
    serializer_class<npl_redirect_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_table_key_t&);



template<>
class serializer_class<npl_redirect_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_table_value_t& m)
{
    serializer_class<npl_redirect_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_table_value_t& m)
{
    serializer_class<npl_redirect_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_table_value_t&);



template<>
class serializer_class<npl_redirect_table_value_t::npl_redirect_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_redirect_table_value_t::npl_redirect_table_payloads_t& m) {
            archive(::cereal::make_nvp("redirect_code", m.redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_redirect_table_value_t::npl_redirect_table_payloads_t& m) {
            archive(::cereal::make_nvp("redirect_code", m.redirect_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_redirect_table_value_t::npl_redirect_table_payloads_t& m)
{
    serializer_class<npl_redirect_table_value_t::npl_redirect_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_redirect_table_value_t::npl_redirect_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_redirect_table_value_t::npl_redirect_table_payloads_t& m)
{
    serializer_class<npl_redirect_table_value_t::npl_redirect_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_redirect_table_value_t::npl_redirect_table_payloads_t&);



template<>
class serializer_class<npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t& m) {
        uint64_t m_next_is_fwd_done = m.next_is_fwd_done;
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("next_is_fwd_done", m_next_is_fwd_done));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t& m) {
        uint64_t m_next_is_fwd_done;
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("next_is_fwd_done", m_next_is_fwd_done));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.next_is_fwd_done = m_next_is_fwd_done;
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_set_next_macro_table_resolution_set_next_macro_payload_t&);



template<>
class serializer_class<npl_resolution_set_next_macro_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_set_next_macro_table_key_t& m) {
        uint64_t m_is_pfc_enable = m.is_pfc_enable;
            archive(::cereal::make_nvp("is_inject_up", m.is_inject_up));
            archive(::cereal::make_nvp("is_pfc_enable", m_is_pfc_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_set_next_macro_table_key_t& m) {
        uint64_t m_is_pfc_enable;
            archive(::cereal::make_nvp("is_inject_up", m.is_inject_up));
            archive(::cereal::make_nvp("is_pfc_enable", m_is_pfc_enable));
        m.is_pfc_enable = m_is_pfc_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_set_next_macro_table_key_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_set_next_macro_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_set_next_macro_table_key_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_set_next_macro_table_key_t&);



template<>
class serializer_class<npl_resolution_set_next_macro_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_set_next_macro_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_set_next_macro_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_set_next_macro_table_value_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_set_next_macro_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_set_next_macro_table_value_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_set_next_macro_table_value_t&);



template<>
class serializer_class<npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_set_next_macro", m.resolution_set_next_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_set_next_macro", m.resolution_set_next_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t& m)
{
    serializer_class<npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_set_next_macro_table_value_t::npl_resolution_set_next_macro_table_payloads_t&);



template<>
class serializer_class<npl_rmep_last_time_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rmep_last_time_table_key_t& m) {
            archive(::cereal::make_nvp("rmep_key", m.rmep_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rmep_last_time_table_key_t& m) {
            archive(::cereal::make_nvp("rmep_key", m.rmep_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rmep_last_time_table_key_t& m)
{
    serializer_class<npl_rmep_last_time_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rmep_last_time_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rmep_last_time_table_key_t& m)
{
    serializer_class<npl_rmep_last_time_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rmep_last_time_table_key_t&);



template<>
class serializer_class<npl_rmep_last_time_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rmep_last_time_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rmep_last_time_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rmep_last_time_table_value_t& m)
{
    serializer_class<npl_rmep_last_time_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rmep_last_time_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rmep_last_time_table_value_t& m)
{
    serializer_class<npl_rmep_last_time_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rmep_last_time_table_value_t&);



template<>
class serializer_class<npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t& m) {
        uint64_t m_rmep_result_rmep_last_time_result = m.rmep_result_rmep_last_time_result;
            archive(::cereal::make_nvp("rmep_result_rmep_last_time_result", m_rmep_result_rmep_last_time_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t& m) {
        uint64_t m_rmep_result_rmep_last_time_result;
            archive(::cereal::make_nvp("rmep_result_rmep_last_time_result", m_rmep_result_rmep_last_time_result));
        m.rmep_result_rmep_last_time_result = m_rmep_result_rmep_last_time_result;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t& m)
{
    serializer_class<npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t& m)
{
    serializer_class<npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rmep_last_time_table_value_t::npl_rmep_last_time_table_payloads_t&);



template<>
class serializer_class<npl_rmep_state_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rmep_state_table_key_t& m) {
            archive(::cereal::make_nvp("rmep_key", m.rmep_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rmep_state_table_key_t& m) {
            archive(::cereal::make_nvp("rmep_key", m.rmep_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rmep_state_table_key_t& m)
{
    serializer_class<npl_rmep_state_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rmep_state_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rmep_state_table_key_t& m)
{
    serializer_class<npl_rmep_state_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rmep_state_table_key_t&);



template<>
class serializer_class<npl_rmep_state_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rmep_state_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rmep_state_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rmep_state_table_value_t& m)
{
    serializer_class<npl_rmep_state_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rmep_state_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rmep_state_table_value_t& m)
{
    serializer_class<npl_rmep_state_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rmep_state_table_value_t&);



template<>
class serializer_class<npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t& m) {
            archive(::cereal::make_nvp("rmep_result_rmep_state_table_result", m.rmep_result_rmep_state_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t& m) {
            archive(::cereal::make_nvp("rmep_result_rmep_state_table_result", m.rmep_result_rmep_state_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t& m)
{
    serializer_class<npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t& m)
{
    serializer_class<npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rmep_state_table_value_t::npl_rmep_state_table_payloads_t&);



template<>
class serializer_class<npl_rpf_fec_access_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_fec_access_map_table_key_t& m) {
        uint64_t m_prefix = m.prefix;
            archive(::cereal::make_nvp("prefix", m_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_access_map_table_key_t& m) {
        uint64_t m_prefix;
            archive(::cereal::make_nvp("prefix", m_prefix));
        m.prefix = m_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_fec_access_map_table_key_t& m)
{
    serializer_class<npl_rpf_fec_access_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_fec_access_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_fec_access_map_table_key_t& m)
{
    serializer_class<npl_rpf_fec_access_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_fec_access_map_table_key_t&);



template<>
class serializer_class<npl_rpf_fec_access_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_fec_access_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_access_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_fec_access_map_table_value_t& m)
{
    serializer_class<npl_rpf_fec_access_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_fec_access_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_fec_access_map_table_value_t& m)
{
    serializer_class<npl_rpf_fec_access_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_fec_access_map_table_value_t&);



template<>
class serializer_class<npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_prefix_fec_access_map", m.lpm_prefix_fec_access_map));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_prefix_fec_access_map", m.lpm_prefix_fec_access_map));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t& m)
{
    serializer_class<npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t& m)
{
    serializer_class<npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_fec_access_map_table_value_t::npl_rpf_fec_access_map_table_payloads_t&);



template<>
class serializer_class<npl_rpf_fec_table_found_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_fec_table_found_payload_t& m) {
            archive(::cereal::make_nvp("dst", m.dst));
            archive(::cereal::make_nvp("dummy_bit", m.dummy_bit));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_table_found_payload_t& m) {
            archive(::cereal::make_nvp("dst", m.dst));
            archive(::cereal::make_nvp("dummy_bit", m.dummy_bit));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_fec_table_found_payload_t& m)
{
    serializer_class<npl_rpf_fec_table_found_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_fec_table_found_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_fec_table_found_payload_t& m)
{
    serializer_class<npl_rpf_fec_table_found_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_fec_table_found_payload_t&);



template<>
class serializer_class<npl_rpf_fec_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_fec_table_key_t& m) {
        uint64_t m_fec = m.fec;
            archive(::cereal::make_nvp("fec", m_fec));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_table_key_t& m) {
        uint64_t m_fec;
            archive(::cereal::make_nvp("fec", m_fec));
        m.fec = m_fec;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_fec_table_key_t& m)
{
    serializer_class<npl_rpf_fec_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_fec_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_fec_table_key_t& m)
{
    serializer_class<npl_rpf_fec_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_fec_table_key_t&);



template<>
class serializer_class<npl_rpf_fec_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_fec_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_fec_table_value_t& m)
{
    serializer_class<npl_rpf_fec_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_fec_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_fec_table_value_t& m)
{
    serializer_class<npl_rpf_fec_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_fec_table_value_t&);



template<>
class serializer_class<npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t& m)
{
    serializer_class<npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t& m)
{
    serializer_class<npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rpf_fec_table_value_t::npl_rpf_fec_table_payloads_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_key_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("per_rtf_step_og_pcl_compress_bits", m.per_rtf_step_og_pcl_compress_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("per_rtf_step_og_pcl_compress_bits", m.per_rtf_step_og_pcl_compress_bits));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_compress_bits_mapping_table_payloads_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_key_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("per_rtf_step_og_pcl_ids", m.per_rtf_step_og_pcl_ids));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("per_rtf_step_og_pcl_ids", m.per_rtf_step_og_pcl_ids));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t& m)
{
    serializer_class<npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_og_pcl_ids_mapping_table_value_t::npl_rtf_conf_set_to_og_pcl_ids_mapping_table_payloads_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("ip_version", m.ip_version));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("ip_version", m.ip_version));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t& m)
{
    serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t& m)
{
    serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_key_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t& m)
{
    serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t& m)
{
    serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t&);



template<>
class serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("post_fwd_params", m.post_fwd_params));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("post_fwd_params", m.post_fwd_params));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t& m)
{
    serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t& m)
{
    serializer_class<npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_conf_set_to_post_fwd_stage_mapping_table_value_t::npl_rtf_conf_set_to_post_fwd_stage_mapping_table_payloads_t&);



template<>
class serializer_class<npl_rtf_next_macro_static_table_set_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_jump_to_fwd = m.jump_to_fwd;
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("jump_to_fwd", m_jump_to_fwd));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_jump_to_fwd;
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("jump_to_fwd", m_jump_to_fwd));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.jump_to_fwd = m_jump_to_fwd;
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_set_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_next_macro_static_table_set_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_set_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_next_macro_static_table_set_macro_payload_t&);



template<>
class serializer_class<npl_rtf_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("curr_and_next_prot_type", m.curr_and_next_prot_type));
            archive(::cereal::make_nvp("pd_tunnel_ipv4_ipv6_init_rtf_stage", m.pd_tunnel_ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("next_rtf_stage", m.next_rtf_stage));
            archive(::cereal::make_nvp("rtf_indications", m.rtf_indications));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("curr_and_next_prot_type", m.curr_and_next_prot_type));
            archive(::cereal::make_nvp("pd_tunnel_ipv4_ipv6_init_rtf_stage", m.pd_tunnel_ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("next_rtf_stage", m.next_rtf_stage));
            archive(::cereal::make_nvp("rtf_indications", m.rtf_indications));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_next_macro_static_table_key_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_next_macro_static_table_key_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_rtf_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_next_macro_static_table_value_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_next_macro_static_table_value_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rtf_next_macro_static_table_value_t::npl_rtf_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_rx_counters_bank_id_map_config_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_bank_id_map_config_key_t& m) {
        uint64_t m_npu_bank_id = m.npu_bank_id;
        uint64_t m_ifg = m.ifg;
            archive(::cereal::make_nvp("npu_bank_id", m_npu_bank_id));
            archive(::cereal::make_nvp("ifg", m_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_bank_id_map_config_key_t& m) {
        uint64_t m_npu_bank_id;
        uint64_t m_ifg;
            archive(::cereal::make_nvp("npu_bank_id", m_npu_bank_id));
            archive(::cereal::make_nvp("ifg", m_ifg));
        m.npu_bank_id = m_npu_bank_id;
        m.ifg = m_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_counters_bank_id_map_config_key_t& m)
{
    serializer_class<npl_rx_counters_bank_id_map_config_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_counters_bank_id_map_config_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_counters_bank_id_map_config_key_t& m)
{
    serializer_class<npl_rx_counters_bank_id_map_config_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_counters_bank_id_map_config_key_t&);



template<>
class serializer_class<npl_rx_counters_bank_id_map_config_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_bank_id_map_config_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_bank_id_map_config_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_counters_bank_id_map_config_value_t& m)
{
    serializer_class<npl_rx_counters_bank_id_map_config_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_counters_bank_id_map_config_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_counters_bank_id_map_config_value_t& m)
{
    serializer_class<npl_rx_counters_bank_id_map_config_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_counters_bank_id_map_config_value_t&);



template<>
class serializer_class<npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t& m) {
        uint64_t m_counter_bank_id = m.counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t& m) {
        uint64_t m_counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
        m.counter_bank_id = m_counter_bank_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t& m)
{
    serializer_class<npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t& m)
{
    serializer_class<npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_counters_bank_id_map_config_value_t::npl_rx_counters_bank_id_map_config_payloads_t&);



template<>
class serializer_class<npl_rx_counters_block_config_table_config_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_block_config_table_config_payload_t& m) {
        uint64_t m_inc_addr_for_set = m.inc_addr_for_set;
            archive(::cereal::make_nvp("inc_addr_for_set", m_inc_addr_for_set));
            archive(::cereal::make_nvp("bank_set_type", m.bank_set_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_block_config_table_config_payload_t& m) {
        uint64_t m_inc_addr_for_set;
            archive(::cereal::make_nvp("inc_addr_for_set", m_inc_addr_for_set));
            archive(::cereal::make_nvp("bank_set_type", m.bank_set_type));
        m.inc_addr_for_set = m_inc_addr_for_set;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_counters_block_config_table_config_payload_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_config_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_counters_block_config_table_config_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_counters_block_config_table_config_payload_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_config_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_counters_block_config_table_config_payload_t&);



template<>
class serializer_class<npl_rx_counters_block_config_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_block_config_table_key_t& m) {
        uint64_t m_counter_bank_id = m.counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_block_config_table_key_t& m) {
        uint64_t m_counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
        m.counter_bank_id = m_counter_bank_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_counters_block_config_table_key_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_counters_block_config_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_counters_block_config_table_key_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_counters_block_config_table_key_t&);



template<>
class serializer_class<npl_rx_counters_block_config_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_block_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_block_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_counters_block_config_table_value_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_counters_block_config_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_counters_block_config_table_value_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_counters_block_config_table_value_t&);



template<>
class serializer_class<npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("config", m.config));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("config", m.config));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t& m)
{
    serializer_class<npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_counters_block_config_table_value_t::npl_rx_counters_block_config_table_payloads_t&);



template<>
class serializer_class<npl_rx_fwd_error_handling_counter_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_counter_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_counter_table_update_result_payload_t&);



template<>
class serializer_class<npl_rx_fwd_error_handling_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_key_t& m) {
        uint64_t m_ser = m.ser;
        uint64_t m_pd_source_if_pif = m.pd_source_if_pif;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("pd_source_if_pif", m_pd_source_if_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_counter_table_key_t& m) {
        uint64_t m_ser;
        uint64_t m_pd_source_if_pif;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("pd_source_if_pif", m_pd_source_if_pif));
        m.ser = m_ser;
        m.pd_source_if_pif = m_pd_source_if_pif;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_counter_table_key_t&);



template<>
class serializer_class<npl_rx_fwd_error_handling_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_counter_table_value_t&);



template<>
class serializer_class<npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_counter_table_value_t::npl_rx_fwd_error_handling_counter_table_payloads_t&);



template<>
class serializer_class<npl_rx_fwd_error_handling_destination_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_destination_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_destination_table_update_result_payload_t&);



}

