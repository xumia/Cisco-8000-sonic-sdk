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

template <class Archive> void save(Archive&, const npl_additional_mpls_labels_offset_t&);
template <class Archive> void load(Archive&, npl_additional_mpls_labels_offset_t&);

template <class Archive> void save(Archive&, const npl_aux_table_key_t&);
template <class Archive> void load(Archive&, npl_aux_table_key_t&);

template <class Archive> void save(Archive&, const npl_aux_table_result_t&);
template <class Archive> void load(Archive&, npl_aux_table_result_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_cud_mapping_local_vars_t_anonymous_union_mapped_cud_t&);
template <class Archive> void load(Archive&, npl_cud_mapping_local_vars_t_anonymous_union_mapped_cud_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_dsp_map_info_t&);
template <class Archive> void load(Archive&, npl_dsp_map_info_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_ibm_encap_header_on_direct_t&);
template <class Archive> void load(Archive&, npl_ibm_encap_header_on_direct_t&);

template <class Archive> void save(Archive&, const npl_ingress_qos_result_t&);
template <class Archive> void load(Archive&, npl_ingress_qos_result_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_init_rtf_stage_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_lsp_encap_fields_t&);
template <class Archive> void load(Archive&, npl_lsp_encap_fields_t&);

template <class Archive> void save(Archive&, const npl_lsp_impose_mpls_labels_ene_offset_t&);
template <class Archive> void load(Archive&, npl_lsp_impose_mpls_labels_ene_offset_t&);

template <class Archive> void save(Archive&, const npl_mc_bitmap_base_voq_lookup_table_result_t&);
template <class Archive> void load(Archive&, npl_mc_bitmap_base_voq_lookup_table_result_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db__key_t&);
template <class Archive> void load(Archive&, npl_mc_em_db__key_t&);

template <class Archive> void save(Archive&, const npl_mc_em_db_result_t&);
template <class Archive> void load(Archive&, npl_mc_em_db_result_t&);

template <class Archive> void save(Archive&, const npl_mc_fe_links_bmp_db_result_t&);
template <class Archive> void load(Archive&, npl_mc_fe_links_bmp_db_result_t&);

template <class Archive> void save(Archive&, const npl_mc_slice_bitmap_table_entry_t&);
template <class Archive> void load(Archive&, npl_mc_slice_bitmap_table_entry_t&);

template <class Archive> void save(Archive&, const npl_mcid_t&);
template <class Archive> void load(Archive&, npl_mcid_t&);

template <class Archive> void save(Archive&, const npl_mii_loopback_data_t&);
template <class Archive> void load(Archive&, npl_mii_loopback_data_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_entry_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_entry_t&);

template <class Archive> void save(Archive&, const npl_mldp_protection_id_t&);
template <class Archive> void load(Archive&, npl_mldp_protection_id_t&);

template <class Archive> void save(Archive&, const npl_mp_data_result_t&);
template <class Archive> void load(Archive&, npl_mp_data_result_t&);

template <class Archive> void save(Archive&, const npl_mpls_encap_control_bits_t&);
template <class Archive> void load(Archive&, npl_mpls_encap_control_bits_t&);

template <class Archive> void save(Archive&, const npl_mpls_first_ene_macro_control_t&);
template <class Archive> void load(Archive&, npl_mpls_first_ene_macro_control_t&);

template <class Archive> void save(Archive&, const npl_mpls_termination_res_t&);
template <class Archive> void load(Archive&, npl_mpls_termination_res_t&);

template <class Archive> void save(Archive&, const npl_ms_voq_fabric_context_offset_table_result_t&);
template <class Archive> void load(Archive&, npl_ms_voq_fabric_context_offset_table_result_t&);

template <class Archive> void save(Archive&, const npl_my_ipv4_table_payload_t&);
template <class Archive> void load(Archive&, npl_my_ipv4_table_payload_t&);

template <class Archive> void save(Archive&, const npl_nhlfe_t&);
template <class Archive> void load(Archive&, npl_nhlfe_t&);

template <class Archive> void save(Archive&, const npl_nhlfe_type_attributes_t&);
template <class Archive> void load(Archive&, npl_nhlfe_type_attributes_t&);

template <class Archive> void save(Archive&, const npl_npp_sgt_map_header_t&);
template <class Archive> void load(Archive&, npl_npp_sgt_map_header_t&);

template <class Archive> void save(Archive&, const npl_num_outer_transport_labels_t&);
template <class Archive> void load(Archive&, npl_num_outer_transport_labels_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_scanner_id_t&);
template <class Archive> void load(Archive&, npl_scanner_id_t&);

template <class Archive> void save(Archive&, const npl_snoop_or_rcy_data_t&);
template <class Archive> void load(Archive&, npl_snoop_or_rcy_data_t&);

template<>
class serializer_class<npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t& m) {
            archive(::cereal::make_nvp("next_macro", m.next_macro));
            archive(::cereal::make_nvp("second_ene_macro", m.second_ene_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t& m) {
            archive(::cereal::make_nvp("next_macro", m.next_macro));
            archive(::cereal::make_nvp("second_ene_macro", m.second_ene_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_inject_ccm_macro_static_table_map_inject_ccm_macro_payload_t&);



template<>
class serializer_class<npl_map_inject_ccm_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_inject_ccm_macro_static_table_key_t& m) {
        uint64_t m_outer_tpid_ptr = m.outer_tpid_ptr;
        uint64_t m_inner_tpid_ptr = m.inner_tpid_ptr;
            archive(::cereal::make_nvp("outer_tpid_ptr", m_outer_tpid_ptr));
            archive(::cereal::make_nvp("inner_tpid_ptr", m_inner_tpid_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_inject_ccm_macro_static_table_key_t& m) {
        uint64_t m_outer_tpid_ptr;
        uint64_t m_inner_tpid_ptr;
            archive(::cereal::make_nvp("outer_tpid_ptr", m_outer_tpid_ptr));
            archive(::cereal::make_nvp("inner_tpid_ptr", m_inner_tpid_ptr));
        m.outer_tpid_ptr = m_outer_tpid_ptr;
        m.inner_tpid_ptr = m_inner_tpid_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_inject_ccm_macro_static_table_key_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_inject_ccm_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_map_inject_ccm_macro_static_table_key_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_inject_ccm_macro_static_table_key_t&);



template<>
class serializer_class<npl_map_inject_ccm_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_inject_ccm_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_inject_ccm_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_inject_ccm_macro_static_table_value_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_inject_ccm_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_map_inject_ccm_macro_static_table_value_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_inject_ccm_macro_static_table_value_t&);



template<>
class serializer_class<npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("map_inject_ccm_macro", m.map_inject_ccm_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("map_inject_ccm_macro", m.map_inject_ccm_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t& m)
{
    serializer_class<npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_inject_ccm_macro_static_table_value_t::npl_map_inject_ccm_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_map_more_labels_static_table_set_value_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_more_labels_static_table_set_value_payload_t& m) {
            archive(::cereal::make_nvp("more_labels_offset", m.more_labels_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_more_labels_static_table_set_value_payload_t& m) {
            archive(::cereal::make_nvp("more_labels_offset", m.more_labels_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_more_labels_static_table_set_value_payload_t& m)
{
    serializer_class<npl_map_more_labels_static_table_set_value_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_more_labels_static_table_set_value_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_map_more_labels_static_table_set_value_payload_t& m)
{
    serializer_class<npl_map_more_labels_static_table_set_value_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_more_labels_static_table_set_value_payload_t&);



template<>
class serializer_class<npl_map_more_labels_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_more_labels_static_table_key_t& m) {
        uint64_t m_num_labels_is_8 = m.num_labels_is_8;
        uint64_t m_num_labels = m.num_labels;
            archive(::cereal::make_nvp("num_labels_is_8", m_num_labels_is_8));
            archive(::cereal::make_nvp("num_labels", m_num_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_more_labels_static_table_key_t& m) {
        uint64_t m_num_labels_is_8;
        uint64_t m_num_labels;
            archive(::cereal::make_nvp("num_labels_is_8", m_num_labels_is_8));
            archive(::cereal::make_nvp("num_labels", m_num_labels));
        m.num_labels_is_8 = m_num_labels_is_8;
        m.num_labels = m_num_labels;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_more_labels_static_table_key_t& m)
{
    serializer_class<npl_map_more_labels_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_more_labels_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_map_more_labels_static_table_key_t& m)
{
    serializer_class<npl_map_more_labels_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_more_labels_static_table_key_t&);



template<>
class serializer_class<npl_map_more_labels_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_more_labels_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_more_labels_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_more_labels_static_table_value_t& m)
{
    serializer_class<npl_map_more_labels_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_more_labels_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_map_more_labels_static_table_value_t& m)
{
    serializer_class<npl_map_more_labels_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_more_labels_static_table_value_t&);



template<>
class serializer_class<npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t& m)
{
    serializer_class<npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t& m)
{
    serializer_class<npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_more_labels_static_table_value_t::npl_map_more_labels_static_table_payloads_t&);



template<>
class serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t& m) {
            archive(::cereal::make_nvp("dsp_map_dma_info", m.dsp_map_dma_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t& m) {
            archive(::cereal::make_nvp("dsp_map_dma_info", m.dsp_map_dma_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t& m)
{
    serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t& m)
{
    serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_recyle_tx_to_rx_data_on_pd_static_table_key_t&);



template<>
class serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t& m)
{
    serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t& m)
{
    serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t&);



template<>
class serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("pd_recycle_data", m.pd_recycle_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("pd_recycle_data", m.pd_recycle_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t& m)
{
    serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t& m)
{
    serializer_class<npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_recyle_tx_to_rx_data_on_pd_static_table_value_t::npl_map_recyle_tx_to_rx_data_on_pd_static_table_payloads_t&);



template<>
class serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t& m) {
        uint64_t m_tm_h_ecn = m.tm_h_ecn;
        uint64_t m_tm_h_dp_0 = m.tm_h_dp_0;
            archive(::cereal::make_nvp("tm_h_ecn", m_tm_h_ecn));
            archive(::cereal::make_nvp("tm_h_dp_0", m_tm_h_dp_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t& m) {
        uint64_t m_tm_h_ecn;
        uint64_t m_tm_h_dp_0;
            archive(::cereal::make_nvp("tm_h_ecn", m_tm_h_ecn));
            archive(::cereal::make_nvp("tm_h_dp_0", m_tm_h_dp_0));
        m.tm_h_ecn = m_tm_h_ecn;
        m.tm_h_dp_0 = m_tm_h_dp_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t& m)
{
    serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t& m)
{
    serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_key_t&);



template<>
class serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t& m)
{
    serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t& m)
{
    serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t&);



template<>
class serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t& m) {
        uint64_t m_dp_ecn_wa_local_var_new_dp = m.dp_ecn_wa_local_var_new_dp;
            archive(::cereal::make_nvp("dp_ecn_wa_local_var_new_dp", m_dp_ecn_wa_local_var_new_dp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t& m) {
        uint64_t m_dp_ecn_wa_local_var_new_dp;
            archive(::cereal::make_nvp("dp_ecn_wa_local_var_new_dp", m_dp_ecn_wa_local_var_new_dp));
        m.dp_ecn_wa_local_var_new_dp = m_dp_ecn_wa_local_var_new_dp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t& m)
{
    serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t& m)
{
    serializer_class<npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_value_t::npl_map_tm_dp_ecn_to_wa_ecn_dp_static_table_payloads_t&);



template<>
class serializer_class<npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t& m) {
        uint64_t m_ene_bytes_added = m.ene_bytes_added;
        uint64_t m_pl_inc = m.pl_inc;
            archive(::cereal::make_nvp("ene_bytes_added", m_ene_bytes_added));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m.macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t& m) {
        uint64_t m_ene_bytes_added;
        uint64_t m_pl_inc;
            archive(::cereal::make_nvp("ene_bytes_added", m_ene_bytes_added));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m.macro_id));
        m.ene_bytes_added = m_ene_bytes_added;
        m.pl_inc = m_pl_inc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_next_macro_static_table_tx_punt_next_macro_payload_t&);



template<>
class serializer_class<npl_map_tx_punt_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("cud_type", m.cud_type));
            archive(::cereal::make_nvp("punt_encap_type", m.punt_encap_type));
            archive(::cereal::make_nvp("punt_format", m.punt_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("cud_type", m.cud_type));
            archive(::cereal::make_nvp("punt_encap_type", m.punt_encap_type));
            archive(::cereal::make_nvp("punt_format", m.punt_format));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_key_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_next_macro_static_table_key_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_map_tx_punt_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_value_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_next_macro_static_table_value_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("tx_punt_next_macro", m.tx_punt_next_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("tx_punt_next_macro", m.tx_punt_next_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_next_macro_static_table_value_t::npl_map_tx_punt_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m.macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t& m) {
        uint64_t m_pl_inc;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m.macro_id));
        m.pl_inc = m_pl_inc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_rcy_next_macro_static_table_set_npe_next_macro_payload_t&);



template<>
class serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_key_t& m) {
        uint64_t m_inject_only = m.inject_only;
        uint64_t m_eth_stage = m.eth_stage;
        uint64_t m_redirect_code = m.redirect_code;
            archive(::cereal::make_nvp("inject_only", m_inject_only));
            archive(::cereal::make_nvp("eth_stage", m_eth_stage));
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_key_t& m) {
        uint64_t m_inject_only;
        uint64_t m_eth_stage;
        uint64_t m_redirect_code;
            archive(::cereal::make_nvp("inject_only", m_inject_only));
            archive(::cereal::make_nvp("eth_stage", m_eth_stage));
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
        m.inject_only = m_inject_only;
        m.eth_stage = m_eth_stage;
        m.redirect_code = m_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_key_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_rcy_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_key_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_rcy_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_value_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_rcy_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_value_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_rcy_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_npe_next_macro", m.set_npe_next_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_npe_next_macro", m.set_npe_next_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_map_tx_punt_rcy_next_macro_static_table_value_t::npl_map_tx_punt_rcy_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_mc_bitmap_base_voq_lookup_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_key_t& m) {
        uint64_t m_rxpdr_local_vars_current_slice = m.rxpdr_local_vars_current_slice;
            archive(::cereal::make_nvp("rxpdr_local_vars_current_slice", m_rxpdr_local_vars_current_slice));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_key_t& m) {
        uint64_t m_rxpdr_local_vars_current_slice;
            archive(::cereal::make_nvp("rxpdr_local_vars_current_slice", m_rxpdr_local_vars_current_slice));
        m.rxpdr_local_vars_current_slice = m_rxpdr_local_vars_current_slice;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_key_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_base_voq_lookup_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_key_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_base_voq_lookup_table_key_t&);



template<>
class serializer_class<npl_mc_bitmap_base_voq_lookup_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_value_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_base_voq_lookup_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_value_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_base_voq_lookup_table_value_t&);



template<>
class serializer_class<npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t& m) {
            archive(::cereal::make_nvp("mc_bitmap_base_voq_lookup_table_result", m.mc_bitmap_base_voq_lookup_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t& m) {
            archive(::cereal::make_nvp("mc_bitmap_base_voq_lookup_table_result", m.mc_bitmap_base_voq_lookup_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t& m)
{
    serializer_class<npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_base_voq_lookup_table_value_t::npl_mc_bitmap_base_voq_lookup_table_payloads_t&);



template<>
class serializer_class<npl_mc_bitmap_tc_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_tc_map_table_key_t& m) {
        uint64_t m_mc_bitmap_base_voq_lookup_table_result_tc_map_profile = m.mc_bitmap_base_voq_lookup_table_result_tc_map_profile;
        uint64_t m_rxpp_pd_tc = m.rxpp_pd_tc;
            archive(::cereal::make_nvp("mc_bitmap_base_voq_lookup_table_result_tc_map_profile", m_mc_bitmap_base_voq_lookup_table_result_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_tc_map_table_key_t& m) {
        uint64_t m_mc_bitmap_base_voq_lookup_table_result_tc_map_profile;
        uint64_t m_rxpp_pd_tc;
            archive(::cereal::make_nvp("mc_bitmap_base_voq_lookup_table_result_tc_map_profile", m_mc_bitmap_base_voq_lookup_table_result_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
        m.mc_bitmap_base_voq_lookup_table_result_tc_map_profile = m_mc_bitmap_base_voq_lookup_table_result_tc_map_profile;
        m.rxpp_pd_tc = m_rxpp_pd_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_tc_map_table_key_t& m)
{
    serializer_class<npl_mc_bitmap_tc_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_tc_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_tc_map_table_key_t& m)
{
    serializer_class<npl_mc_bitmap_tc_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_tc_map_table_key_t&);



template<>
class serializer_class<npl_mc_bitmap_tc_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_tc_map_table_value_t& m)
{
    serializer_class<npl_mc_bitmap_tc_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_tc_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_tc_map_table_value_t& m)
{
    serializer_class<npl_mc_bitmap_tc_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_tc_map_table_value_t&);



template<>
class serializer_class<npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t& m) {
        uint64_t m_rxpdr_local_vars_tc_offset = m.rxpdr_local_vars_tc_offset;
            archive(::cereal::make_nvp("rxpdr_local_vars_tc_offset", m_rxpdr_local_vars_tc_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t& m) {
        uint64_t m_rxpdr_local_vars_tc_offset;
            archive(::cereal::make_nvp("rxpdr_local_vars_tc_offset", m_rxpdr_local_vars_tc_offset));
        m.rxpdr_local_vars_tc_offset = m_rxpdr_local_vars_tc_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t& m)
{
    serializer_class<npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t& m)
{
    serializer_class<npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_bitmap_tc_map_table_value_t::npl_mc_bitmap_tc_map_table_payloads_t&);



template<>
class serializer_class<npl_mc_copy_id_map_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_copy_id_map_update_payload_t& m) {
        uint64_t m_map_cud = m.map_cud;
        uint64_t m_encap_type = m.encap_type;
        uint64_t m_mc_copy_id_msbs = m.mc_copy_id_msbs;
            archive(::cereal::make_nvp("map_cud", m_map_cud));
            archive(::cereal::make_nvp("encap_type", m_encap_type));
            archive(::cereal::make_nvp("mc_copy_id_msbs", m_mc_copy_id_msbs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_copy_id_map_update_payload_t& m) {
        uint64_t m_map_cud;
        uint64_t m_encap_type;
        uint64_t m_mc_copy_id_msbs;
            archive(::cereal::make_nvp("map_cud", m_map_cud));
            archive(::cereal::make_nvp("encap_type", m_encap_type));
            archive(::cereal::make_nvp("mc_copy_id_msbs", m_mc_copy_id_msbs));
        m.map_cud = m_map_cud;
        m.encap_type = m_encap_type;
        m.mc_copy_id_msbs = m_mc_copy_id_msbs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_copy_id_map_update_payload_t& m)
{
    serializer_class<npl_mc_copy_id_map_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_copy_id_map_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_copy_id_map_update_payload_t& m)
{
    serializer_class<npl_mc_copy_id_map_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_copy_id_map_update_payload_t&);



template<>
class serializer_class<npl_mc_copy_id_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_copy_id_map_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_17_12_ = m.cud_mapping_local_vars_mc_copy_id_17_12_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_17_12_", m_cud_mapping_local_vars_mc_copy_id_17_12_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_copy_id_map_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_17_12_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_17_12_", m_cud_mapping_local_vars_mc_copy_id_17_12_));
        m.cud_mapping_local_vars_mc_copy_id_17_12_ = m_cud_mapping_local_vars_mc_copy_id_17_12_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_copy_id_map_key_t& m)
{
    serializer_class<npl_mc_copy_id_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_copy_id_map_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_copy_id_map_key_t& m)
{
    serializer_class<npl_mc_copy_id_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_copy_id_map_key_t&);



template<>
class serializer_class<npl_mc_copy_id_map_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_copy_id_map_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_copy_id_map_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_copy_id_map_value_t& m)
{
    serializer_class<npl_mc_copy_id_map_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_copy_id_map_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_copy_id_map_value_t& m)
{
    serializer_class<npl_mc_copy_id_map_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_copy_id_map_value_t&);



template<>
class serializer_class<npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t& m)
{
    serializer_class<npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t& m)
{
    serializer_class<npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_copy_id_map_value_t::npl_mc_copy_id_map_payloads_t&);



template<>
class serializer_class<npl_mc_cud_is_wide_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_cud_is_wide_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_12_7_ = m.cud_mapping_local_vars_mc_copy_id_12_7_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_12_7_", m_cud_mapping_local_vars_mc_copy_id_12_7_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_cud_is_wide_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_12_7_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_12_7_", m_cud_mapping_local_vars_mc_copy_id_12_7_));
        m.cud_mapping_local_vars_mc_copy_id_12_7_ = m_cud_mapping_local_vars_mc_copy_id_12_7_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_cud_is_wide_table_key_t& m)
{
    serializer_class<npl_mc_cud_is_wide_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_cud_is_wide_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_cud_is_wide_table_key_t& m)
{
    serializer_class<npl_mc_cud_is_wide_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_cud_is_wide_table_key_t&);



template<>
class serializer_class<npl_mc_cud_is_wide_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_cud_is_wide_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_cud_is_wide_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_cud_is_wide_table_value_t& m)
{
    serializer_class<npl_mc_cud_is_wide_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_cud_is_wide_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_cud_is_wide_table_value_t& m)
{
    serializer_class<npl_mc_cud_is_wide_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_cud_is_wide_table_value_t&);



template<>
class serializer_class<npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_cud_is_wide = m.cud_mapping_local_vars_mc_cud_is_wide;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_cud_is_wide", m_cud_mapping_local_vars_mc_cud_is_wide));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_cud_is_wide;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_cud_is_wide", m_cud_mapping_local_vars_mc_cud_is_wide));
        m.cud_mapping_local_vars_mc_cud_is_wide = m_cud_mapping_local_vars_mc_cud_is_wide;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t& m)
{
    serializer_class<npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t& m)
{
    serializer_class<npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_cud_is_wide_table_value_t::npl_mc_cud_is_wide_table_payloads_t&);



template<>
class serializer_class<npl_mc_cud_table_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_cud_table_update_payload_t& m) {
        uint64_t m_mapped_cud_is_narrow = m.mapped_cud_is_narrow;
            archive(::cereal::make_nvp("mapped_cud_is_narrow", m_mapped_cud_is_narrow));
            archive(::cereal::make_nvp("mapped_cud", m.mapped_cud));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_cud_table_update_payload_t& m) {
        uint64_t m_mapped_cud_is_narrow;
            archive(::cereal::make_nvp("mapped_cud_is_narrow", m_mapped_cud_is_narrow));
            archive(::cereal::make_nvp("mapped_cud", m.mapped_cud));
        m.mapped_cud_is_narrow = m_mapped_cud_is_narrow;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_cud_table_update_payload_t& m)
{
    serializer_class<npl_mc_cud_table_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_cud_table_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_cud_table_update_payload_t& m)
{
    serializer_class<npl_mc_cud_table_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_cud_table_update_payload_t&);



template<>
class serializer_class<npl_mc_cud_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_cud_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_exp_mc_copy_id_14_1_ = m.cud_mapping_local_vars_exp_mc_copy_id_14_1_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_exp_mc_copy_id_14_1_", m_cud_mapping_local_vars_exp_mc_copy_id_14_1_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_cud_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_exp_mc_copy_id_14_1_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_exp_mc_copy_id_14_1_", m_cud_mapping_local_vars_exp_mc_copy_id_14_1_));
        m.cud_mapping_local_vars_exp_mc_copy_id_14_1_ = m_cud_mapping_local_vars_exp_mc_copy_id_14_1_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_cud_table_key_t& m)
{
    serializer_class<npl_mc_cud_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_cud_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_cud_table_key_t& m)
{
    serializer_class<npl_mc_cud_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_cud_table_key_t&);



template<>
class serializer_class<npl_mc_cud_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_cud_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_cud_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_cud_table_value_t& m)
{
    serializer_class<npl_mc_cud_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_cud_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_cud_table_value_t& m)
{
    serializer_class<npl_mc_cud_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_cud_table_value_t&);



template<>
class serializer_class<npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t& m)
{
    serializer_class<npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t& m)
{
    serializer_class<npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_cud_table_value_t::npl_mc_cud_table_payloads_t&);



template<>
class serializer_class<npl_mc_em_db_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_key_t& m) {
            archive(::cereal::make_nvp("mc_em_db_key", m.mc_em_db_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_key_t& m) {
            archive(::cereal::make_nvp("mc_em_db_key", m.mc_em_db_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_key_t& m)
{
    serializer_class<npl_mc_em_db_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_key_t& m)
{
    serializer_class<npl_mc_em_db_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_key_t&);



template<>
class serializer_class<npl_mc_em_db_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_value_t& m)
{
    serializer_class<npl_mc_em_db_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_value_t& m)
{
    serializer_class<npl_mc_em_db_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_value_t&);



template<>
class serializer_class<npl_mc_em_db_value_t::npl_mc_em_db_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_em_db_value_t::npl_mc_em_db_payloads_t& m) {
            archive(::cereal::make_nvp("mc_em_db_result", m.mc_em_db_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_em_db_value_t::npl_mc_em_db_payloads_t& m) {
            archive(::cereal::make_nvp("mc_em_db_result", m.mc_em_db_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_em_db_value_t::npl_mc_em_db_payloads_t& m)
{
    serializer_class<npl_mc_em_db_value_t::npl_mc_em_db_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_em_db_value_t::npl_mc_em_db_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_em_db_value_t::npl_mc_em_db_payloads_t& m)
{
    serializer_class<npl_mc_em_db_value_t::npl_mc_em_db_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_em_db_value_t::npl_mc_em_db_payloads_t&);



template<>
class serializer_class<npl_mc_emdb_tc_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_emdb_tc_map_table_key_t& m) {
        uint64_t m_rxpdr_local_vars_tc_map_profile_1_0_ = m.rxpdr_local_vars_tc_map_profile_1_0_;
        uint64_t m_rxpp_pd_tc = m.rxpp_pd_tc;
            archive(::cereal::make_nvp("rxpdr_local_vars_tc_map_profile_1_0_", m_rxpdr_local_vars_tc_map_profile_1_0_));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_emdb_tc_map_table_key_t& m) {
        uint64_t m_rxpdr_local_vars_tc_map_profile_1_0_;
        uint64_t m_rxpp_pd_tc;
            archive(::cereal::make_nvp("rxpdr_local_vars_tc_map_profile_1_0_", m_rxpdr_local_vars_tc_map_profile_1_0_));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
        m.rxpdr_local_vars_tc_map_profile_1_0_ = m_rxpdr_local_vars_tc_map_profile_1_0_;
        m.rxpp_pd_tc = m_rxpp_pd_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_emdb_tc_map_table_key_t& m)
{
    serializer_class<npl_mc_emdb_tc_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_emdb_tc_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_emdb_tc_map_table_key_t& m)
{
    serializer_class<npl_mc_emdb_tc_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_emdb_tc_map_table_key_t&);



template<>
class serializer_class<npl_mc_emdb_tc_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_emdb_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_emdb_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_emdb_tc_map_table_value_t& m)
{
    serializer_class<npl_mc_emdb_tc_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_emdb_tc_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_emdb_tc_map_table_value_t& m)
{
    serializer_class<npl_mc_emdb_tc_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_emdb_tc_map_table_value_t&);



template<>
class serializer_class<npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t& m) {
        uint64_t m_rxpdr_local_vars_tc_offset = m.rxpdr_local_vars_tc_offset;
            archive(::cereal::make_nvp("rxpdr_local_vars_tc_offset", m_rxpdr_local_vars_tc_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t& m) {
        uint64_t m_rxpdr_local_vars_tc_offset;
            archive(::cereal::make_nvp("rxpdr_local_vars_tc_offset", m_rxpdr_local_vars_tc_offset));
        m.rxpdr_local_vars_tc_offset = m_rxpdr_local_vars_tc_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t& m)
{
    serializer_class<npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t& m)
{
    serializer_class<npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_emdb_tc_map_table_value_t::npl_mc_emdb_tc_map_table_payloads_t&);



template<>
class serializer_class<npl_mc_fe_links_bmp_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_fe_links_bmp_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_15_0_ = m.rxpp_pd_fwd_destination_15_0_;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_15_0_", m_rxpp_pd_fwd_destination_15_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_fe_links_bmp_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_15_0_;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_15_0_", m_rxpp_pd_fwd_destination_15_0_));
        m.rxpp_pd_fwd_destination_15_0_ = m_rxpp_pd_fwd_destination_15_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_fe_links_bmp_key_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_fe_links_bmp_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_fe_links_bmp_key_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_fe_links_bmp_key_t&);



template<>
class serializer_class<npl_mc_fe_links_bmp_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_fe_links_bmp_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_fe_links_bmp_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_fe_links_bmp_value_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_fe_links_bmp_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_fe_links_bmp_value_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_fe_links_bmp_value_t&);



template<>
class serializer_class<npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t& m) {
            archive(::cereal::make_nvp("mc_fe_links_bmp_db_result", m.mc_fe_links_bmp_db_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t& m) {
            archive(::cereal::make_nvp("mc_fe_links_bmp_db_result", m.mc_fe_links_bmp_db_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t& m)
{
    serializer_class<npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_fe_links_bmp_value_t::npl_mc_fe_links_bmp_payloads_t&);



template<>
class serializer_class<npl_mc_ibm_cud_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_ibm_cud_mapping_table_key_t& m) {
        uint64_t m_ibm_mc_cud_key = m.ibm_mc_cud_key;
            archive(::cereal::make_nvp("ibm_mc_cud_key", m_ibm_mc_cud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_ibm_cud_mapping_table_key_t& m) {
        uint64_t m_ibm_mc_cud_key;
            archive(::cereal::make_nvp("ibm_mc_cud_key", m_ibm_mc_cud_key));
        m.ibm_mc_cud_key = m_ibm_mc_cud_key;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_ibm_cud_mapping_table_key_t& m)
{
    serializer_class<npl_mc_ibm_cud_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_ibm_cud_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_ibm_cud_mapping_table_key_t& m)
{
    serializer_class<npl_mc_ibm_cud_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_ibm_cud_mapping_table_key_t&);



template<>
class serializer_class<npl_mc_ibm_cud_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_ibm_cud_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_ibm_cud_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_ibm_cud_mapping_table_value_t& m)
{
    serializer_class<npl_mc_ibm_cud_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_ibm_cud_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_ibm_cud_mapping_table_value_t& m)
{
    serializer_class<npl_mc_ibm_cud_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_ibm_cud_mapping_table_value_t&);



template<>
class serializer_class<npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("mc_ibm_cud_mapping_encap", m.mc_ibm_cud_mapping_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("mc_ibm_cud_mapping_encap", m.mc_ibm_cud_mapping_encap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t& m)
{
    serializer_class<npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t& m)
{
    serializer_class<npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_ibm_cud_mapping_table_value_t::npl_mc_ibm_cud_mapping_table_payloads_t&);



template<>
class serializer_class<npl_mc_slice_bitmap_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_slice_bitmap_table_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_15_0_ = m.rxpp_pd_fwd_destination_15_0_;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_15_0_", m_rxpp_pd_fwd_destination_15_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_slice_bitmap_table_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_15_0_;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_15_0_", m_rxpp_pd_fwd_destination_15_0_));
        m.rxpp_pd_fwd_destination_15_0_ = m_rxpp_pd_fwd_destination_15_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_slice_bitmap_table_key_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_slice_bitmap_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_slice_bitmap_table_key_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_slice_bitmap_table_key_t&);



template<>
class serializer_class<npl_mc_slice_bitmap_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_slice_bitmap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_slice_bitmap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_slice_bitmap_table_value_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_slice_bitmap_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_slice_bitmap_table_value_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_slice_bitmap_table_value_t&);



template<>
class serializer_class<npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t& m) {
            archive(::cereal::make_nvp("mc_slice_bitmap_table_result", m.mc_slice_bitmap_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t& m) {
            archive(::cereal::make_nvp("mc_slice_bitmap_table_result", m.mc_slice_bitmap_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t& m)
{
    serializer_class<npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mc_slice_bitmap_table_value_t::npl_mc_slice_bitmap_table_payloads_t&);



template<>
class serializer_class<npl_meg_id_format_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meg_id_format_table_key_t& m) {
        uint64_t m_eth_oam_ccm_meg_id_format = m.eth_oam_ccm_meg_id_format;
        uint64_t m_meg_id_length = m.meg_id_length;
            archive(::cereal::make_nvp("eth_oam_mp_table_read_payload_meg_id_format", m.eth_oam_mp_table_read_payload_meg_id_format));
            archive(::cereal::make_nvp("eth_oam_ccm_meg_id_format", m_eth_oam_ccm_meg_id_format));
            archive(::cereal::make_nvp("meg_id_length", m_meg_id_length));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meg_id_format_table_key_t& m) {
        uint64_t m_eth_oam_ccm_meg_id_format;
        uint64_t m_meg_id_length;
            archive(::cereal::make_nvp("eth_oam_mp_table_read_payload_meg_id_format", m.eth_oam_mp_table_read_payload_meg_id_format));
            archive(::cereal::make_nvp("eth_oam_ccm_meg_id_format", m_eth_oam_ccm_meg_id_format));
            archive(::cereal::make_nvp("meg_id_length", m_meg_id_length));
        m.eth_oam_ccm_meg_id_format = m_eth_oam_ccm_meg_id_format;
        m.meg_id_length = m_meg_id_length;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meg_id_format_table_key_t& m)
{
    serializer_class<npl_meg_id_format_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meg_id_format_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_meg_id_format_table_key_t& m)
{
    serializer_class<npl_meg_id_format_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meg_id_format_table_key_t&);



template<>
class serializer_class<npl_meg_id_format_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meg_id_format_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meg_id_format_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meg_id_format_table_value_t& m)
{
    serializer_class<npl_meg_id_format_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meg_id_format_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_meg_id_format_table_value_t& m)
{
    serializer_class<npl_meg_id_format_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meg_id_format_table_value_t&);



template<>
class serializer_class<npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t& m) {
        uint64_t m_eth_wrong_meg_id_format = m.eth_wrong_meg_id_format;
            archive(::cereal::make_nvp("eth_wrong_meg_id_format", m_eth_wrong_meg_id_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t& m) {
        uint64_t m_eth_wrong_meg_id_format;
            archive(::cereal::make_nvp("eth_wrong_meg_id_format", m_eth_wrong_meg_id_format));
        m.eth_wrong_meg_id_format = m_eth_wrong_meg_id_format;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t& m)
{
    serializer_class<npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t& m)
{
    serializer_class<npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_meg_id_format_table_value_t::npl_meg_id_format_table_payloads_t&);



template<>
class serializer_class<npl_mep_address_prefix_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mep_address_prefix_table_key_t& m) {
        uint64_t m_mep_address_prefix_index = m.mep_address_prefix_index;
            archive(::cereal::make_nvp("mep_address_prefix_index", m_mep_address_prefix_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mep_address_prefix_table_key_t& m) {
        uint64_t m_mep_address_prefix_index;
            archive(::cereal::make_nvp("mep_address_prefix_index", m_mep_address_prefix_index));
        m.mep_address_prefix_index = m_mep_address_prefix_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mep_address_prefix_table_key_t& m)
{
    serializer_class<npl_mep_address_prefix_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mep_address_prefix_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mep_address_prefix_table_key_t& m)
{
    serializer_class<npl_mep_address_prefix_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mep_address_prefix_table_key_t&);



template<>
class serializer_class<npl_mep_address_prefix_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mep_address_prefix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mep_address_prefix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mep_address_prefix_table_value_t& m)
{
    serializer_class<npl_mep_address_prefix_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mep_address_prefix_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mep_address_prefix_table_value_t& m)
{
    serializer_class<npl_mep_address_prefix_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mep_address_prefix_table_value_t&);



template<>
class serializer_class<npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t& m) {
        uint64_t m_mep_mac_address_prefix = m.mep_mac_address_prefix;
            archive(::cereal::make_nvp("mep_mac_address_prefix", m_mep_mac_address_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t& m) {
        uint64_t m_mep_mac_address_prefix;
            archive(::cereal::make_nvp("mep_mac_address_prefix", m_mep_mac_address_prefix));
        m.mep_mac_address_prefix = m_mep_mac_address_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t& m)
{
    serializer_class<npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t& m)
{
    serializer_class<npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mep_address_prefix_table_value_t::npl_mep_address_prefix_table_payloads_t&);



template<>
class serializer_class<npl_mii_loopback_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mii_loopback_table_key_t& m) {
        uint64_t m_device_packet_info_ifg = m.device_packet_info_ifg;
        uint64_t m_device_packet_info_pif = m.device_packet_info_pif;
            archive(::cereal::make_nvp("device_packet_info_ifg", m_device_packet_info_ifg));
            archive(::cereal::make_nvp("device_packet_info_pif", m_device_packet_info_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mii_loopback_table_key_t& m) {
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
save(Archive& archive, const npl_mii_loopback_table_key_t& m)
{
    serializer_class<npl_mii_loopback_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mii_loopback_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mii_loopback_table_key_t& m)
{
    serializer_class<npl_mii_loopback_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mii_loopback_table_key_t&);



template<>
class serializer_class<npl_mii_loopback_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mii_loopback_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mii_loopback_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mii_loopback_table_value_t& m)
{
    serializer_class<npl_mii_loopback_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mii_loopback_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mii_loopback_table_value_t& m)
{
    serializer_class<npl_mii_loopback_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mii_loopback_table_value_t&);



template<>
class serializer_class<npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t& m) {
            archive(::cereal::make_nvp("mii_loopback_data", m.mii_loopback_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t& m) {
            archive(::cereal::make_nvp("mii_loopback_data", m.mii_loopback_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t& m)
{
    serializer_class<npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t& m)
{
    serializer_class<npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mii_loopback_table_value_t::npl_mii_loopback_table_payloads_t&);



template<>
class serializer_class<npl_mirror_code_2_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_code_2_hw_table_key_t& m) {
        uint64_t m_pd_mirror_code_2 = m.pd_mirror_code_2;
            archive(::cereal::make_nvp("pd_mirror_code_2", m_pd_mirror_code_2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_code_2_hw_table_key_t& m) {
        uint64_t m_pd_mirror_code_2;
            archive(::cereal::make_nvp("pd_mirror_code_2", m_pd_mirror_code_2));
        m.pd_mirror_code_2 = m_pd_mirror_code_2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_code_2_hw_table_key_t& m)
{
    serializer_class<npl_mirror_code_2_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_code_2_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_code_2_hw_table_key_t& m)
{
    serializer_class<npl_mirror_code_2_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_code_2_hw_table_key_t&);



template<>
class serializer_class<npl_mirror_code_2_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_code_2_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_code_2_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_code_2_hw_table_value_t& m)
{
    serializer_class<npl_mirror_code_2_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_code_2_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_code_2_hw_table_value_t& m)
{
    serializer_class<npl_mirror_code_2_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_code_2_hw_table_value_t&);



template<>
class serializer_class<npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t& m) {
        uint64_t m_rxpp_pd_rxn_in_mirror_cmd2 = m.rxpp_pd_rxn_in_mirror_cmd2;
            archive(::cereal::make_nvp("rxpp_pd_rxn_in_mirror_cmd2", m_rxpp_pd_rxn_in_mirror_cmd2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t& m) {
        uint64_t m_rxpp_pd_rxn_in_mirror_cmd2;
            archive(::cereal::make_nvp("rxpp_pd_rxn_in_mirror_cmd2", m_rxpp_pd_rxn_in_mirror_cmd2));
        m.rxpp_pd_rxn_in_mirror_cmd2 = m_rxpp_pd_rxn_in_mirror_cmd2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t& m)
{
    serializer_class<npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t& m)
{
    serializer_class<npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_code_2_hw_table_value_t::npl_mirror_code_2_hw_table_payloads_t&);



template<>
class serializer_class<npl_mirror_code_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_code_hw_table_key_t& m) {
        uint64_t m_pd_common_leaba_fields_mirror_code = m.pd_common_leaba_fields_mirror_code;
            archive(::cereal::make_nvp("pd_common_leaba_fields_mirror_code", m_pd_common_leaba_fields_mirror_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_code_hw_table_key_t& m) {
        uint64_t m_pd_common_leaba_fields_mirror_code;
            archive(::cereal::make_nvp("pd_common_leaba_fields_mirror_code", m_pd_common_leaba_fields_mirror_code));
        m.pd_common_leaba_fields_mirror_code = m_pd_common_leaba_fields_mirror_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_code_hw_table_key_t& m)
{
    serializer_class<npl_mirror_code_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_code_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_code_hw_table_key_t& m)
{
    serializer_class<npl_mirror_code_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_code_hw_table_key_t&);



template<>
class serializer_class<npl_mirror_code_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_code_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_code_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_code_hw_table_value_t& m)
{
    serializer_class<npl_mirror_code_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_code_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_code_hw_table_value_t& m)
{
    serializer_class<npl_mirror_code_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_code_hw_table_value_t&);



template<>
class serializer_class<npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t& m) {
        uint64_t m_rxpp_pd_rxn_in_mirror_cmd1 = m.rxpp_pd_rxn_in_mirror_cmd1;
            archive(::cereal::make_nvp("rxpp_pd_rxn_in_mirror_cmd1", m_rxpp_pd_rxn_in_mirror_cmd1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t& m) {
        uint64_t m_rxpp_pd_rxn_in_mirror_cmd1;
            archive(::cereal::make_nvp("rxpp_pd_rxn_in_mirror_cmd1", m_rxpp_pd_rxn_in_mirror_cmd1));
        m.rxpp_pd_rxn_in_mirror_cmd1 = m_rxpp_pd_rxn_in_mirror_cmd1;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t& m)
{
    serializer_class<npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t& m)
{
    serializer_class<npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_code_hw_table_value_t::npl_mirror_code_hw_table_payloads_t&);



template<>
class serializer_class<npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t& m) {
        uint64_t m_session_id = m.session_id;
            archive(::cereal::make_nvp("session_id", m_session_id));
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t& m) {
        uint64_t m_session_id;
            archive(::cereal::make_nvp("session_id", m_session_id));
            archive(::cereal::make_nvp("counter", m.counter));
        m.session_id = m_session_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_egress_attributes_table_set_mirror_egress_attributes_payload_t&);



template<>
class serializer_class<npl_mirror_egress_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_egress_attributes_table_key_t& m) {
        uint64_t m_mirror_code = m.mirror_code;
            archive(::cereal::make_nvp("is_ibm", m.is_ibm));
            archive(::cereal::make_nvp("mirror_code", m_mirror_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_egress_attributes_table_key_t& m) {
        uint64_t m_mirror_code;
            archive(::cereal::make_nvp("is_ibm", m.is_ibm));
            archive(::cereal::make_nvp("mirror_code", m_mirror_code));
        m.mirror_code = m_mirror_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_egress_attributes_table_key_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_egress_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_egress_attributes_table_key_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_egress_attributes_table_key_t&);



template<>
class serializer_class<npl_mirror_egress_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_egress_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_egress_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_egress_attributes_table_value_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_egress_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_egress_attributes_table_value_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_egress_attributes_table_value_t&);



template<>
class serializer_class<npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_mirror_egress_attributes", m.set_mirror_egress_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_mirror_egress_attributes", m.set_mirror_egress_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t& m)
{
    serializer_class<npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_egress_attributes_table_value_t::npl_mirror_egress_attributes_table_payloads_t&);



template<>
class serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_to_dsp_in_npu_soft_header_table_key_t& m) {
        uint64_t m_mirror_code = m.mirror_code;
            archive(::cereal::make_nvp("mirror_code", m_mirror_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_to_dsp_in_npu_soft_header_table_key_t& m) {
        uint64_t m_mirror_code;
            archive(::cereal::make_nvp("mirror_code", m_mirror_code));
        m.mirror_code = m_mirror_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_to_dsp_in_npu_soft_header_table_key_t& m)
{
    serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_to_dsp_in_npu_soft_header_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_to_dsp_in_npu_soft_header_table_key_t& m)
{
    serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_to_dsp_in_npu_soft_header_table_key_t&);



template<>
class serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_to_dsp_in_npu_soft_header_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_to_dsp_in_npu_soft_header_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_to_dsp_in_npu_soft_header_table_value_t& m)
{
    serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_to_dsp_in_npu_soft_header_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_to_dsp_in_npu_soft_header_table_value_t& m)
{
    serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_to_dsp_in_npu_soft_header_table_value_t&);



template<>
class serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t& m) {
        uint64_t m_update_dsp_in_npu_soft_header = m.update_dsp_in_npu_soft_header;
            archive(::cereal::make_nvp("update_dsp_in_npu_soft_header", m_update_dsp_in_npu_soft_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t& m) {
        uint64_t m_update_dsp_in_npu_soft_header;
            archive(::cereal::make_nvp("update_dsp_in_npu_soft_header", m_update_dsp_in_npu_soft_header));
        m.update_dsp_in_npu_soft_header = m_update_dsp_in_npu_soft_header;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t& m)
{
    serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t& m)
{
    serializer_class<npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mirror_to_dsp_in_npu_soft_header_table_value_t::npl_mirror_to_dsp_in_npu_soft_header_table_payloads_t&);



template<>
class serializer_class<npl_mldp_protection_enabled_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_enabled_static_table_key_t& m) {
        uint64_t m_is_mc = m.is_mc;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("l3_encap", m.l3_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_enabled_static_table_key_t& m) {
        uint64_t m_is_mc;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("l3_encap", m.l3_encap));
        m.is_mc = m_is_mc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_enabled_static_table_key_t& m)
{
    serializer_class<npl_mldp_protection_enabled_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_enabled_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_enabled_static_table_key_t& m)
{
    serializer_class<npl_mldp_protection_enabled_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_enabled_static_table_key_t&);



template<>
class serializer_class<npl_mldp_protection_enabled_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_enabled_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_enabled_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_enabled_static_table_value_t& m)
{
    serializer_class<npl_mldp_protection_enabled_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_enabled_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_enabled_static_table_value_t& m)
{
    serializer_class<npl_mldp_protection_enabled_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_enabled_static_table_value_t&);



template<>
class serializer_class<npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t& m) {
        uint64_t m_enabled = m.enabled;
            archive(::cereal::make_nvp("enabled", m_enabled));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t& m) {
        uint64_t m_enabled;
            archive(::cereal::make_nvp("enabled", m_enabled));
        m.enabled = m_enabled;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t& m)
{
    serializer_class<npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t& m)
{
    serializer_class<npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_enabled_static_table_value_t::npl_mldp_protection_enabled_static_table_payloads_t&);



template<>
class serializer_class<npl_mldp_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_table_key_t& m) {
            archive(::cereal::make_nvp("mlp_protection", m.mlp_protection));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_table_key_t& m) {
            archive(::cereal::make_nvp("mlp_protection", m.mlp_protection));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_table_key_t& m)
{
    serializer_class<npl_mldp_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_table_key_t& m)
{
    serializer_class<npl_mldp_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_table_key_t&);



template<>
class serializer_class<npl_mldp_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_table_value_t& m)
{
    serializer_class<npl_mldp_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_table_value_t& m)
{
    serializer_class<npl_mldp_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_table_value_t&);



template<>
class serializer_class<npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("mld_entry", m.mld_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("mld_entry", m.mld_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t& m)
{
    serializer_class<npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t& m)
{
    serializer_class<npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mldp_protection_table_value_t::npl_mldp_protection_table_payloads_t&);



template<>
class serializer_class<npl_mp_aux_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_aux_data_table_key_t& m) {
            archive(::cereal::make_nvp("aux_table_key", m.aux_table_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_aux_data_table_key_t& m) {
            archive(::cereal::make_nvp("aux_table_key", m.aux_table_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_aux_data_table_key_t& m)
{
    serializer_class<npl_mp_aux_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_aux_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_aux_data_table_key_t& m)
{
    serializer_class<npl_mp_aux_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_aux_data_table_key_t&);



template<>
class serializer_class<npl_mp_aux_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_aux_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_aux_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_aux_data_table_value_t& m)
{
    serializer_class<npl_mp_aux_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_aux_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_aux_data_table_value_t& m)
{
    serializer_class<npl_mp_aux_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_aux_data_table_value_t&);



template<>
class serializer_class<npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("aux_table_result", m.aux_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("aux_table_result", m.aux_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t& m)
{
    serializer_class<npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t& m)
{
    serializer_class<npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_aux_data_table_value_t::npl_mp_aux_data_table_payloads_t&);



template<>
class serializer_class<npl_mp_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_data_table_key_t& m) {
            archive(::cereal::make_nvp("line_id", m.line_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_data_table_key_t& m) {
            archive(::cereal::make_nvp("line_id", m.line_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_data_table_key_t& m)
{
    serializer_class<npl_mp_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_data_table_key_t& m)
{
    serializer_class<npl_mp_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_data_table_key_t&);



template<>
class serializer_class<npl_mp_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_data_table_value_t& m)
{
    serializer_class<npl_mp_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_data_table_value_t& m)
{
    serializer_class<npl_mp_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_data_table_value_t&);



template<>
class serializer_class<npl_mp_data_table_value_t::npl_mp_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mp_data_table_value_t::npl_mp_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("mp_data_result", m.mp_data_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mp_data_table_value_t::npl_mp_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("mp_data_result", m.mp_data_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mp_data_table_value_t::npl_mp_data_table_payloads_t& m)
{
    serializer_class<npl_mp_data_table_value_t::npl_mp_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mp_data_table_value_t::npl_mp_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mp_data_table_value_t::npl_mp_data_table_payloads_t& m)
{
    serializer_class<npl_mp_data_table_value_t::npl_mp_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mp_data_table_value_t::npl_mp_data_table_payloads_t&);



template<>
class serializer_class<npl_mpls_encap_control_static_table_set_mpls_controls_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_encap_control_static_table_set_mpls_controls_payload_t& m) {
        uint64_t m_is_vpn = m.is_vpn;
        uint64_t m_is_asbr = m.is_asbr;
            archive(::cereal::make_nvp("mpls_encap_control_bits", m.mpls_encap_control_bits));
            archive(::cereal::make_nvp("is_vpn", m_is_vpn));
            archive(::cereal::make_nvp("is_asbr", m_is_asbr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_encap_control_static_table_set_mpls_controls_payload_t& m) {
        uint64_t m_is_vpn;
        uint64_t m_is_asbr;
            archive(::cereal::make_nvp("mpls_encap_control_bits", m.mpls_encap_control_bits));
            archive(::cereal::make_nvp("is_vpn", m_is_vpn));
            archive(::cereal::make_nvp("is_asbr", m_is_asbr));
        m.is_vpn = m_is_vpn;
        m.is_asbr = m_is_asbr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_encap_control_static_table_set_mpls_controls_payload_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_set_mpls_controls_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_encap_control_static_table_set_mpls_controls_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_encap_control_static_table_set_mpls_controls_payload_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_set_mpls_controls_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_encap_control_static_table_set_mpls_controls_payload_t&);



template<>
class serializer_class<npl_mpls_encap_control_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_encap_control_static_table_key_t& m) {
        uint64_t m_lsp_type = m.lsp_type;
            archive(::cereal::make_nvp("encap_type", m.encap_type));
            archive(::cereal::make_nvp("lsp_type", m_lsp_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_encap_control_static_table_key_t& m) {
        uint64_t m_lsp_type;
            archive(::cereal::make_nvp("encap_type", m.encap_type));
            archive(::cereal::make_nvp("lsp_type", m_lsp_type));
        m.lsp_type = m_lsp_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_encap_control_static_table_key_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_encap_control_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_encap_control_static_table_key_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_encap_control_static_table_key_t&);



template<>
class serializer_class<npl_mpls_encap_control_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_encap_control_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_encap_control_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_encap_control_static_table_value_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_encap_control_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_encap_control_static_table_value_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_encap_control_static_table_value_t&);



template<>
class serializer_class<npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_mpls_controls", m.set_mpls_controls));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_mpls_controls", m.set_mpls_controls));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_encap_control_static_table_value_t::npl_mpls_encap_control_static_table_payloads_t&);



template<>
class serializer_class<npl_mpls_forwarding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_forwarding_table_key_t& m) {
        uint64_t m_label = m.label;
            archive(::cereal::make_nvp("label", m_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_forwarding_table_key_t& m) {
        uint64_t m_label;
            archive(::cereal::make_nvp("label", m_label));
        m.label = m_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_forwarding_table_key_t& m)
{
    serializer_class<npl_mpls_forwarding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_forwarding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_forwarding_table_key_t& m)
{
    serializer_class<npl_mpls_forwarding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_forwarding_table_key_t&);



template<>
class serializer_class<npl_mpls_forwarding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_forwarding_table_value_t& m)
{
    serializer_class<npl_mpls_forwarding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_forwarding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_forwarding_table_value_t& m)
{
    serializer_class<npl_mpls_forwarding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_forwarding_table_value_t&);



template<>
class serializer_class<npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("nhlfe", m.nhlfe));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("nhlfe", m.nhlfe));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t& m)
{
    serializer_class<npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t& m)
{
    serializer_class<npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_forwarding_table_value_t::npl_mpls_forwarding_table_payloads_t&);



template<>
class serializer_class<npl_mpls_header_offset_in_bytes_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_header_offset_in_bytes_static_table_key_t& m) {
        uint64_t m_mpls_is_null_labels = m.mpls_is_null_labels;
            archive(::cereal::make_nvp("mpls_is_null_labels", m_mpls_is_null_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_header_offset_in_bytes_static_table_key_t& m) {
        uint64_t m_mpls_is_null_labels;
            archive(::cereal::make_nvp("mpls_is_null_labels", m_mpls_is_null_labels));
        m.mpls_is_null_labels = m_mpls_is_null_labels;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_header_offset_in_bytes_static_table_key_t& m)
{
    serializer_class<npl_mpls_header_offset_in_bytes_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_header_offset_in_bytes_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_header_offset_in_bytes_static_table_key_t& m)
{
    serializer_class<npl_mpls_header_offset_in_bytes_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_header_offset_in_bytes_static_table_key_t&);



template<>
class serializer_class<npl_mpls_header_offset_in_bytes_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_header_offset_in_bytes_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_header_offset_in_bytes_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_header_offset_in_bytes_static_table_value_t& m)
{
    serializer_class<npl_mpls_header_offset_in_bytes_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_header_offset_in_bytes_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_header_offset_in_bytes_static_table_value_t& m)
{
    serializer_class<npl_mpls_header_offset_in_bytes_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_header_offset_in_bytes_static_table_value_t&);



template<>
class serializer_class<npl_mpls_l3_lsp_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_l3_lsp_static_table_key_t& m) {
            archive(::cereal::make_nvp("mpls_encap_control_bits", m.mpls_encap_control_bits));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_l3_lsp_static_table_key_t& m) {
            archive(::cereal::make_nvp("mpls_encap_control_bits", m.mpls_encap_control_bits));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_l3_lsp_static_table_key_t& m)
{
    serializer_class<npl_mpls_l3_lsp_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_l3_lsp_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_l3_lsp_static_table_key_t& m)
{
    serializer_class<npl_mpls_l3_lsp_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_l3_lsp_static_table_key_t&);



template<>
class serializer_class<npl_mpls_l3_lsp_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_l3_lsp_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_l3_lsp_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_l3_lsp_static_table_value_t& m)
{
    serializer_class<npl_mpls_l3_lsp_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_l3_lsp_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_l3_lsp_static_table_value_t& m)
{
    serializer_class<npl_mpls_l3_lsp_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_l3_lsp_static_table_value_t&);



template<>
class serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_labels_1_to_4_jump_offset_static_table_key_t& m) {
        uint64_t m_jump_offset_code = m.jump_offset_code;
            archive(::cereal::make_nvp("jump_offset_code", m_jump_offset_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_labels_1_to_4_jump_offset_static_table_key_t& m) {
        uint64_t m_jump_offset_code;
            archive(::cereal::make_nvp("jump_offset_code", m_jump_offset_code));
        m.jump_offset_code = m_jump_offset_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_labels_1_to_4_jump_offset_static_table_key_t& m)
{
    serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_labels_1_to_4_jump_offset_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_labels_1_to_4_jump_offset_static_table_key_t& m)
{
    serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_labels_1_to_4_jump_offset_static_table_key_t&);



template<>
class serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_labels_1_to_4_jump_offset_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_labels_1_to_4_jump_offset_static_table_value_t& m)
{
    serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_labels_1_to_4_jump_offset_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t& m)
{
    serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t&);



template<>
class serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("jump_offsets", m.jump_offsets));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("jump_offsets", m.jump_offsets));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_labels_1_to_4_jump_offset_static_table_value_t::npl_mpls_labels_1_to_4_jump_offset_static_table_payloads_t&);



template<>
class serializer_class<npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t& m) {
        uint64_t m_num_labels_is_8 = m.num_labels_is_8;
        uint64_t m_outer_transport_labels_exist = m.outer_transport_labels_exist;
        uint64_t m_additional_labels_exist = m.additional_labels_exist;
        uint64_t m_transport_labels_size = m.transport_labels_size;
            archive(::cereal::make_nvp("num_labels_is_8", m_num_labels_is_8));
            archive(::cereal::make_nvp("outer_transport_labels_exist", m_outer_transport_labels_exist));
            archive(::cereal::make_nvp("additional_labels_exist", m_additional_labels_exist));
            archive(::cereal::make_nvp("transport_labels_size", m_transport_labels_size));
            archive(::cereal::make_nvp("second_ene_macro_code", m.second_ene_macro_code));
            archive(::cereal::make_nvp("jump_offset_code", m.jump_offset_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t& m) {
        uint64_t m_num_labels_is_8;
        uint64_t m_outer_transport_labels_exist;
        uint64_t m_additional_labels_exist;
        uint64_t m_transport_labels_size;
            archive(::cereal::make_nvp("num_labels_is_8", m_num_labels_is_8));
            archive(::cereal::make_nvp("outer_transport_labels_exist", m_outer_transport_labels_exist));
            archive(::cereal::make_nvp("additional_labels_exist", m_additional_labels_exist));
            archive(::cereal::make_nvp("transport_labels_size", m_transport_labels_size));
            archive(::cereal::make_nvp("second_ene_macro_code", m.second_ene_macro_code));
            archive(::cereal::make_nvp("jump_offset_code", m.jump_offset_code));
        m.num_labels_is_8 = m_num_labels_is_8;
        m.outer_transport_labels_exist = m_outer_transport_labels_exist;
        m.additional_labels_exist = m_additional_labels_exist;
        m.transport_labels_size = m_transport_labels_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_lsp_labels_config_static_table_set_second_mpls_ene_macro_payload_t&);



template<>
class serializer_class<npl_mpls_lsp_labels_config_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_key_t& m) {
        uint64_t m_inner_transport_labels_exist = m.inner_transport_labels_exist;
            archive(::cereal::make_nvp("inner_transport_labels_exist", m_inner_transport_labels_exist));
            archive(::cereal::make_nvp("num_outer_transport_labels", m.num_outer_transport_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_lsp_labels_config_static_table_key_t& m) {
        uint64_t m_inner_transport_labels_exist;
            archive(::cereal::make_nvp("inner_transport_labels_exist", m_inner_transport_labels_exist));
            archive(::cereal::make_nvp("num_outer_transport_labels", m.num_outer_transport_labels));
        m.inner_transport_labels_exist = m_inner_transport_labels_exist;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_key_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_lsp_labels_config_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_lsp_labels_config_static_table_key_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_lsp_labels_config_static_table_key_t&);



template<>
class serializer_class<npl_mpls_lsp_labels_config_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_lsp_labels_config_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_value_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_lsp_labels_config_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_lsp_labels_config_static_table_value_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_lsp_labels_config_static_table_value_t&);



template<>
class serializer_class<npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_second_mpls_ene_macro", m.set_second_mpls_ene_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_second_mpls_ene_macro", m.set_second_mpls_ene_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_lsp_labels_config_static_table_value_t::npl_mpls_lsp_labels_config_static_table_payloads_t&);



template<>
class serializer_class<npl_mpls_qos_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_qos_mapping_table_key_t& m) {
        uint64_t m_l3_qos_mapping_key = m.l3_qos_mapping_key;
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("l3_qos_mapping_key", m_l3_qos_mapping_key));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_qos_mapping_table_key_t& m) {
        uint64_t m_l3_qos_mapping_key;
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("l3_qos_mapping_key", m_l3_qos_mapping_key));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.l3_qos_mapping_key = m_l3_qos_mapping_key;
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_qos_mapping_table_key_t& m)
{
    serializer_class<npl_mpls_qos_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_qos_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_qos_mapping_table_key_t& m)
{
    serializer_class<npl_mpls_qos_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_qos_mapping_table_key_t&);



template<>
class serializer_class<npl_mpls_qos_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_qos_mapping_table_value_t& m)
{
    serializer_class<npl_mpls_qos_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_qos_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_qos_mapping_table_value_t& m)
{
    serializer_class<npl_mpls_qos_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_qos_mapping_table_value_t&);



template<>
class serializer_class<npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_qos_mapping_result", m.mpls_qos_mapping_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_qos_mapping_result", m.mpls_qos_mapping_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_qos_mapping_table_value_t::npl_mpls_qos_mapping_table_payloads_t&);



template<>
class serializer_class<npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t& m) {
        uint64_t m_vpn_label_exists = m.vpn_label_exists;
        uint64_t m_sizeof_labels = m.sizeof_labels;
            archive(::cereal::make_nvp("vpn_label_exists", m_vpn_label_exists));
            archive(::cereal::make_nvp("sizeof_labels", m_sizeof_labels));
            archive(::cereal::make_nvp("mpls_first_ene_macro_control", m.mpls_first_ene_macro_control));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t& m) {
        uint64_t m_vpn_label_exists;
        uint64_t m_sizeof_labels;
            archive(::cereal::make_nvp("vpn_label_exists", m_vpn_label_exists));
            archive(::cereal::make_nvp("sizeof_labels", m_sizeof_labels));
            archive(::cereal::make_nvp("mpls_first_ene_macro_control", m.mpls_first_ene_macro_control));
        m.vpn_label_exists = m_vpn_label_exists;
        m.sizeof_labels = m_sizeof_labels;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_resolve_service_labels_static_table_set_conditions_payload_t&);



template<>
class serializer_class<npl_mpls_resolve_service_labels_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_key_t& m) {
        uint64_t m_vpn_enabled = m.vpn_enabled;
            archive(::cereal::make_nvp("lsp_flags", m.lsp_flags));
            archive(::cereal::make_nvp("vpn_enabled", m_vpn_enabled));
            archive(::cereal::make_nvp("fwd_hdr_type", m.fwd_hdr_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_resolve_service_labels_static_table_key_t& m) {
        uint64_t m_vpn_enabled;
            archive(::cereal::make_nvp("lsp_flags", m.lsp_flags));
            archive(::cereal::make_nvp("vpn_enabled", m_vpn_enabled));
            archive(::cereal::make_nvp("fwd_hdr_type", m.fwd_hdr_type));
        m.vpn_enabled = m_vpn_enabled;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_key_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_resolve_service_labels_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_resolve_service_labels_static_table_key_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_resolve_service_labels_static_table_key_t&);



template<>
class serializer_class<npl_mpls_resolve_service_labels_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_resolve_service_labels_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_value_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_resolve_service_labels_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_resolve_service_labels_static_table_value_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_resolve_service_labels_static_table_value_t&);



template<>
class serializer_class<npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_conditions", m.set_conditions));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_conditions", m.set_conditions));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_resolve_service_labels_static_table_value_t::npl_mpls_resolve_service_labels_static_table_payloads_t&);



template<>
class serializer_class<npl_mpls_termination_em0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_em0_table_key_t& m) {
        uint64_t m_termination_label = m.termination_label;
            archive(::cereal::make_nvp("termination_label", m_termination_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_em0_table_key_t& m) {
        uint64_t m_termination_label;
            archive(::cereal::make_nvp("termination_label", m_termination_label));
        m.termination_label = m_termination_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_em0_table_key_t& m)
{
    serializer_class<npl_mpls_termination_em0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_em0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_em0_table_key_t& m)
{
    serializer_class<npl_mpls_termination_em0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_em0_table_key_t&);



template<>
class serializer_class<npl_mpls_termination_em0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_em0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_em0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_em0_table_value_t& m)
{
    serializer_class<npl_mpls_termination_em0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_em0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_em0_table_value_t& m)
{
    serializer_class<npl_mpls_termination_em0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_em0_table_value_t&);



template<>
class serializer_class<npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_termination_result", m.mpls_termination_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_termination_result", m.mpls_termination_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t& m)
{
    serializer_class<npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t& m)
{
    serializer_class<npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_em0_table_value_t::npl_mpls_termination_em0_table_payloads_t&);



template<>
class serializer_class<npl_mpls_termination_em1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_em1_table_key_t& m) {
        uint64_t m_termination_label = m.termination_label;
            archive(::cereal::make_nvp("termination_label", m_termination_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_em1_table_key_t& m) {
        uint64_t m_termination_label;
            archive(::cereal::make_nvp("termination_label", m_termination_label));
        m.termination_label = m_termination_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_em1_table_key_t& m)
{
    serializer_class<npl_mpls_termination_em1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_em1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_em1_table_key_t& m)
{
    serializer_class<npl_mpls_termination_em1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_em1_table_key_t&);



template<>
class serializer_class<npl_mpls_termination_em1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_em1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_em1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_em1_table_value_t& m)
{
    serializer_class<npl_mpls_termination_em1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_em1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_em1_table_value_t& m)
{
    serializer_class<npl_mpls_termination_em1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_em1_table_value_t&);



template<>
class serializer_class<npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_termination_result", m.mpls_termination_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_termination_result", m.mpls_termination_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t& m)
{
    serializer_class<npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t& m)
{
    serializer_class<npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_termination_em1_table_value_t::npl_mpls_termination_em1_table_payloads_t&);



template<>
class serializer_class<npl_mpls_vpn_enabled_static_table_set_value_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_vpn_enabled_static_table_set_value_payload_t& m) {
        uint64_t m_is_l2_vpn = m.is_l2_vpn;
        uint64_t m_vpn_enabled = m.vpn_enabled;
            archive(::cereal::make_nvp("is_l2_vpn", m_is_l2_vpn));
            archive(::cereal::make_nvp("vpn_enabled", m_vpn_enabled));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_vpn_enabled_static_table_set_value_payload_t& m) {
        uint64_t m_is_l2_vpn;
        uint64_t m_vpn_enabled;
            archive(::cereal::make_nvp("is_l2_vpn", m_is_l2_vpn));
            archive(::cereal::make_nvp("vpn_enabled", m_vpn_enabled));
        m.is_l2_vpn = m_is_l2_vpn;
        m.vpn_enabled = m_vpn_enabled;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_vpn_enabled_static_table_set_value_payload_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_set_value_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_vpn_enabled_static_table_set_value_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_vpn_enabled_static_table_set_value_payload_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_set_value_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_vpn_enabled_static_table_set_value_payload_t&);



template<>
class serializer_class<npl_mpls_vpn_enabled_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_vpn_enabled_static_table_key_t& m) {
        uint64_t m_is_vpn = m.is_vpn;
        uint64_t m_is_prefix_id = m.is_prefix_id;
            archive(::cereal::make_nvp("is_vpn", m_is_vpn));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("is_prefix_id", m_is_prefix_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_vpn_enabled_static_table_key_t& m) {
        uint64_t m_is_vpn;
        uint64_t m_is_prefix_id;
            archive(::cereal::make_nvp("is_vpn", m_is_vpn));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("is_prefix_id", m_is_prefix_id));
        m.is_vpn = m_is_vpn;
        m.is_prefix_id = m_is_prefix_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_vpn_enabled_static_table_key_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_vpn_enabled_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_vpn_enabled_static_table_key_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_vpn_enabled_static_table_key_t&);



template<>
class serializer_class<npl_mpls_vpn_enabled_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_vpn_enabled_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_vpn_enabled_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_vpn_enabled_static_table_value_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_vpn_enabled_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_vpn_enabled_static_table_value_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_vpn_enabled_static_table_value_t&);



template<>
class serializer_class<npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t& m)
{
    serializer_class<npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_mpls_vpn_enabled_static_table_value_t::npl_mpls_vpn_enabled_static_table_payloads_t&);



template<>
class serializer_class<npl_ms_voq_fabric_context_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_key_t& m) {
            archive(::cereal::make_nvp("calc_msvoq_num_input_fabric_context", m.calc_msvoq_num_input_fabric_context));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ms_voq_fabric_context_offset_table_key_t& m) {
            archive(::cereal::make_nvp("calc_msvoq_num_input_fabric_context", m.calc_msvoq_num_input_fabric_context));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_key_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ms_voq_fabric_context_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ms_voq_fabric_context_offset_table_key_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ms_voq_fabric_context_offset_table_key_t&);



template<>
class serializer_class<npl_ms_voq_fabric_context_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ms_voq_fabric_context_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_value_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ms_voq_fabric_context_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ms_voq_fabric_context_offset_table_value_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ms_voq_fabric_context_offset_table_value_t&);



template<>
class serializer_class<npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("ms_voq_fabric_context_offset_table_result", m.ms_voq_fabric_context_offset_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("ms_voq_fabric_context_offset_table_result", m.ms_voq_fabric_context_offset_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t& m)
{
    serializer_class<npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ms_voq_fabric_context_offset_table_value_t::npl_ms_voq_fabric_context_offset_table_payloads_t&);



template<>
class serializer_class<npl_my_ipv4_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_ipv4_table_key_t& m) {
        uint64_t m_l4_protocol_type_3_2 = m.l4_protocol_type_3_2;
        uint64_t m_dip = m.dip;
            archive(::cereal::make_nvp("l4_protocol_type_3_2", m_l4_protocol_type_3_2));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("dip", m_dip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_ipv4_table_key_t& m) {
        uint64_t m_l4_protocol_type_3_2;
        uint64_t m_dip;
            archive(::cereal::make_nvp("l4_protocol_type_3_2", m_l4_protocol_type_3_2));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("dip", m_dip));
        m.l4_protocol_type_3_2 = m_l4_protocol_type_3_2;
        m.dip = m_dip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_ipv4_table_key_t& m)
{
    serializer_class<npl_my_ipv4_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_ipv4_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_my_ipv4_table_key_t& m)
{
    serializer_class<npl_my_ipv4_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_ipv4_table_key_t&);



template<>
class serializer_class<npl_my_ipv4_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_ipv4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_ipv4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_ipv4_table_value_t& m)
{
    serializer_class<npl_my_ipv4_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_ipv4_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_my_ipv4_table_value_t& m)
{
    serializer_class<npl_my_ipv4_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_ipv4_table_value_t&);



template<>
class serializer_class<npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_tunnel_termination_attr", m.ip_tunnel_termination_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_tunnel_termination_attr", m.ip_tunnel_termination_attr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t& m)
{
    serializer_class<npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t& m)
{
    serializer_class<npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_my_ipv4_table_value_t::npl_my_ipv4_table_payloads_t&);



template<>
class serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_next_header_1_is_l4_over_ipv4_static_table_key_t& m) {
        uint64_t m_is_l4 = m.is_l4;
        uint64_t m_fragmented = m.fragmented;
            archive(::cereal::make_nvp("is_l4", m_is_l4));
            archive(::cereal::make_nvp("fragmented", m_fragmented));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_next_header_1_is_l4_over_ipv4_static_table_key_t& m) {
        uint64_t m_is_l4;
        uint64_t m_fragmented;
            archive(::cereal::make_nvp("is_l4", m_is_l4));
            archive(::cereal::make_nvp("fragmented", m_fragmented));
        m.is_l4 = m_is_l4;
        m.fragmented = m_fragmented;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_next_header_1_is_l4_over_ipv4_static_table_key_t& m)
{
    serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_next_header_1_is_l4_over_ipv4_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_next_header_1_is_l4_over_ipv4_static_table_key_t& m)
{
    serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_next_header_1_is_l4_over_ipv4_static_table_key_t&);



template<>
class serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_next_header_1_is_l4_over_ipv4_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_next_header_1_is_l4_over_ipv4_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_next_header_1_is_l4_over_ipv4_static_table_value_t& m)
{
    serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_next_header_1_is_l4_over_ipv4_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_next_header_1_is_l4_over_ipv4_static_table_value_t& m)
{
    serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_next_header_1_is_l4_over_ipv4_static_table_value_t&);



template<>
class serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_1_is_l4_over_ipv4", m.next_header_1_is_l4_over_ipv4));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_1_is_l4_over_ipv4", m.next_header_1_is_l4_over_ipv4));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t& m)
{
    serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t& m)
{
    serializer_class<npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_next_header_1_is_l4_over_ipv4_static_table_value_t::npl_next_header_1_is_l4_over_ipv4_static_table_payloads_t&);



template<>
class serializer_class<npl_nh_macro_code_to_id_l6_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nh_macro_code_to_id_l6_static_table_key_t& m) {
            archive(::cereal::make_nvp("nh_ene_code", m.nh_ene_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nh_macro_code_to_id_l6_static_table_key_t& m) {
            archive(::cereal::make_nvp("nh_ene_code", m.nh_ene_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nh_macro_code_to_id_l6_static_table_key_t& m)
{
    serializer_class<npl_nh_macro_code_to_id_l6_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nh_macro_code_to_id_l6_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_nh_macro_code_to_id_l6_static_table_key_t& m)
{
    serializer_class<npl_nh_macro_code_to_id_l6_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nh_macro_code_to_id_l6_static_table_key_t&);



template<>
class serializer_class<npl_nh_macro_code_to_id_l6_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nh_macro_code_to_id_l6_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nh_macro_code_to_id_l6_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nh_macro_code_to_id_l6_static_table_value_t& m)
{
    serializer_class<npl_nh_macro_code_to_id_l6_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nh_macro_code_to_id_l6_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_nh_macro_code_to_id_l6_static_table_value_t& m)
{
    serializer_class<npl_nh_macro_code_to_id_l6_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nh_macro_code_to_id_l6_static_table_value_t&);



template<>
class serializer_class<npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("nh_ene_macro_id", m.nh_ene_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("nh_ene_macro_id", m.nh_ene_macro_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t& m)
{
    serializer_class<npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t& m)
{
    serializer_class<npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nh_macro_code_to_id_l6_static_table_value_t::npl_nh_macro_code_to_id_l6_static_table_payloads_t&);



template<>
class serializer_class<npl_nhlfe_type_mapping_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nhlfe_type_mapping_static_table_key_t& m) {
            archive(::cereal::make_nvp("mpls_relay_local_vars_nhlfe_type", m.mpls_relay_local_vars_nhlfe_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nhlfe_type_mapping_static_table_key_t& m) {
            archive(::cereal::make_nvp("mpls_relay_local_vars_nhlfe_type", m.mpls_relay_local_vars_nhlfe_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nhlfe_type_mapping_static_table_key_t& m)
{
    serializer_class<npl_nhlfe_type_mapping_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nhlfe_type_mapping_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_nhlfe_type_mapping_static_table_key_t& m)
{
    serializer_class<npl_nhlfe_type_mapping_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nhlfe_type_mapping_static_table_key_t&);



template<>
class serializer_class<npl_nhlfe_type_mapping_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nhlfe_type_mapping_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nhlfe_type_mapping_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nhlfe_type_mapping_static_table_value_t& m)
{
    serializer_class<npl_nhlfe_type_mapping_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nhlfe_type_mapping_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_nhlfe_type_mapping_static_table_value_t& m)
{
    serializer_class<npl_nhlfe_type_mapping_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nhlfe_type_mapping_static_table_value_t&);



template<>
class serializer_class<npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_relay_local_vars_nhlfe_attributes", m.mpls_relay_local_vars_nhlfe_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("mpls_relay_local_vars_nhlfe_attributes", m.mpls_relay_local_vars_nhlfe_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t& m)
{
    serializer_class<npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t& m)
{
    serializer_class<npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nhlfe_type_mapping_static_table_value_t::npl_nhlfe_type_mapping_static_table_payloads_t&);



template<>
class serializer_class<npl_npp_sgt_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npp_sgt_attributes_table_key_t& m) {
        uint64_t m_npp_attributes_index = m.npp_attributes_index;
            archive(::cereal::make_nvp("npp_attributes_index", m_npp_attributes_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npp_sgt_attributes_table_key_t& m) {
        uint64_t m_npp_attributes_index;
            archive(::cereal::make_nvp("npp_attributes_index", m_npp_attributes_index));
        m.npp_attributes_index = m_npp_attributes_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npp_sgt_attributes_table_key_t& m)
{
    serializer_class<npl_npp_sgt_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npp_sgt_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_npp_sgt_attributes_table_key_t& m)
{
    serializer_class<npl_npp_sgt_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npp_sgt_attributes_table_key_t&);



template<>
class serializer_class<npl_npp_sgt_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npp_sgt_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npp_sgt_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npp_sgt_attributes_table_value_t& m)
{
    serializer_class<npl_npp_sgt_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npp_sgt_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_npp_sgt_attributes_table_value_t& m)
{
    serializer_class<npl_npp_sgt_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npp_sgt_attributes_table_value_t&);



template<>
class serializer_class<npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("npp_sgt_attributes", m.npp_sgt_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("npp_sgt_attributes", m.npp_sgt_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t& m)
{
    serializer_class<npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t& m)
{
    serializer_class<npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_npp_sgt_attributes_table_value_t::npl_npp_sgt_attributes_table_payloads_t&);



template<>
class serializer_class<npl_null_rtf_next_macro_static_table_set_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_null_rtf_next_macro_static_table_set_macro_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_null_rtf_next_macro_static_table_set_macro_payload_t& m) {
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
save(Archive& archive, const npl_null_rtf_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_set_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_null_rtf_next_macro_static_table_set_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_null_rtf_next_macro_static_table_set_macro_payload_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_set_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_null_rtf_next_macro_static_table_set_macro_payload_t&);



template<>
class serializer_class<npl_null_rtf_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_null_rtf_next_macro_static_table_key_t& m) {
        uint64_t m_acl_outer = m.acl_outer;
            archive(::cereal::make_nvp("next_prot_type", m.next_prot_type));
            archive(::cereal::make_nvp("pd_tunnel_ipv4_ipv6_init_rtf_stage", m.pd_tunnel_ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("acl_outer", m_acl_outer));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_null_rtf_next_macro_static_table_key_t& m) {
        uint64_t m_acl_outer;
            archive(::cereal::make_nvp("next_prot_type", m.next_prot_type));
            archive(::cereal::make_nvp("pd_tunnel_ipv4_ipv6_init_rtf_stage", m.pd_tunnel_ipv4_ipv6_init_rtf_stage));
            archive(::cereal::make_nvp("acl_outer", m_acl_outer));
        m.acl_outer = m_acl_outer;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_null_rtf_next_macro_static_table_key_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_null_rtf_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_null_rtf_next_macro_static_table_key_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_null_rtf_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_null_rtf_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_null_rtf_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_null_rtf_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_null_rtf_next_macro_static_table_value_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_null_rtf_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_null_rtf_next_macro_static_table_value_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_null_rtf_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_macro", m.set_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_null_rtf_next_macro_static_table_value_t::npl_null_rtf_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_nw_smcid_threshold_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nw_smcid_threshold_table_key_t& m) {
        uint64_t m_dummy = m.dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nw_smcid_threshold_table_key_t& m) {
        uint64_t m_dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
        m.dummy = m_dummy;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nw_smcid_threshold_table_key_t& m)
{
    serializer_class<npl_nw_smcid_threshold_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nw_smcid_threshold_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_nw_smcid_threshold_table_key_t& m)
{
    serializer_class<npl_nw_smcid_threshold_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nw_smcid_threshold_table_key_t&);



template<>
class serializer_class<npl_nw_smcid_threshold_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nw_smcid_threshold_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nw_smcid_threshold_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nw_smcid_threshold_table_value_t& m)
{
    serializer_class<npl_nw_smcid_threshold_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nw_smcid_threshold_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_nw_smcid_threshold_table_value_t& m)
{
    serializer_class<npl_nw_smcid_threshold_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nw_smcid_threshold_table_value_t&);



template<>
class serializer_class<npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t& m) {
            archive(::cereal::make_nvp("smcid_threshold", m.smcid_threshold));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t& m) {
            archive(::cereal::make_nvp("smcid_threshold", m.smcid_threshold));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t& m)
{
    serializer_class<npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t& m)
{
    serializer_class<npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_nw_smcid_threshold_table_value_t::npl_nw_smcid_threshold_table_payloads_t&);



template<>
class serializer_class<npl_oamp_drop_destination_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_drop_destination_static_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_drop_destination_static_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_drop_destination_static_table_key_t& m)
{
    serializer_class<npl_oamp_drop_destination_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_drop_destination_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_drop_destination_static_table_key_t& m)
{
    serializer_class<npl_oamp_drop_destination_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_drop_destination_static_table_key_t&);



template<>
class serializer_class<npl_oamp_drop_destination_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_drop_destination_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_drop_destination_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_drop_destination_static_table_value_t& m)
{
    serializer_class<npl_oamp_drop_destination_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_drop_destination_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_drop_destination_static_table_value_t& m)
{
    serializer_class<npl_oamp_drop_destination_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_drop_destination_static_table_value_t&);



template<>
class serializer_class<npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("drop_dest", m.drop_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("drop_dest", m.drop_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t& m)
{
    serializer_class<npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t& m)
{
    serializer_class<npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_drop_destination_static_table_value_t::npl_oamp_drop_destination_static_table_payloads_t&);



template<>
class serializer_class<npl_oamp_event_queue_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_event_queue_table_key_t& m) {
        uint64_t m_rmep_id = m.rmep_id;
        uint64_t m_mep_id = m.mep_id;
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("mep_id", m_mep_id));
            archive(::cereal::make_nvp("oamp_event", m.oamp_event));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_event_queue_table_key_t& m) {
        uint64_t m_rmep_id;
        uint64_t m_mep_id;
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("mep_id", m_mep_id));
            archive(::cereal::make_nvp("oamp_event", m.oamp_event));
        m.rmep_id = m_rmep_id;
        m.mep_id = m_mep_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_event_queue_table_key_t& m)
{
    serializer_class<npl_oamp_event_queue_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_event_queue_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_event_queue_table_key_t& m)
{
    serializer_class<npl_oamp_event_queue_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_event_queue_table_key_t&);



template<>
class serializer_class<npl_oamp_event_queue_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_event_queue_table_value_t& m)
{
    serializer_class<npl_oamp_event_queue_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_event_queue_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_event_queue_table_value_t& m)
{
    serializer_class<npl_oamp_event_queue_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_event_queue_table_value_t&);



template<>
class serializer_class<npl_oamp_redirect_get_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_get_counter_table_key_t& m) {
        uint64_t m_redirect_code = m.redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_get_counter_table_key_t& m) {
        uint64_t m_redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
        m.redirect_code = m_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_get_counter_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_get_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_get_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_get_counter_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_get_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_get_counter_table_key_t&);



template<>
class serializer_class<npl_oamp_redirect_get_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_get_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_get_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_get_counter_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_get_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_get_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_get_counter_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_get_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_get_counter_table_value_t&);



template<>
class serializer_class<npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_get_counter_table_value_t::npl_oamp_redirect_get_counter_table_payloads_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t& m) {
        uint64_t m_da = m.da;
            archive(::cereal::make_nvp("da", m_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t& m) {
        uint64_t m_da;
            archive(::cereal::make_nvp("da", m_da));
        m.da = m_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_1_table_set_inject_eth_payload_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_key_t& m) {
        uint64_t m_encap_selector = m.encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_key_t& m) {
        uint64_t m_encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
        m.encap_selector = m_encap_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_1_table_key_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_1_table_value_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_1_table_value_t::npl_oamp_redirect_punt_eth_hdr_1_table_payloads_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t& m) {
        uint64_t m_da = m.da;
        uint64_t m_sa = m.sa;
            archive(::cereal::make_nvp("da", m_da));
            archive(::cereal::make_nvp("sa", m_sa));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t& m) {
        uint64_t m_da;
        uint64_t m_sa;
            archive(::cereal::make_nvp("da", m_da));
            archive(::cereal::make_nvp("sa", m_sa));
        m.da = m_da;
        m.sa = m_sa;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_2_table_set_inject_eth_payload_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_key_t& m) {
        uint64_t m_encap_selector = m.encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_key_t& m) {
        uint64_t m_encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
        m.encap_selector = m_encap_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_2_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_2_table_key_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_2_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_2_table_value_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_2_table_value_t::npl_oamp_redirect_punt_eth_hdr_2_table_payloads_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t& m) {
        uint64_t m_sa = m.sa;
            archive(::cereal::make_nvp("sa", m_sa));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t& m) {
        uint64_t m_sa;
            archive(::cereal::make_nvp("sa", m_sa));
        m.sa = m_sa;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_3_table_set_inject_eth_payload_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_key_t& m) {
        uint64_t m_encap_selector = m.encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_key_t& m) {
        uint64_t m_encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
        m.encap_selector = m_encap_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_3_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_3_table_key_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_3_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_3_table_value_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_3_table_value_t::npl_oamp_redirect_punt_eth_hdr_3_table_payloads_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t& m) {
        uint64_t m_dei_vid = m.dei_vid;
            archive(::cereal::make_nvp("dei_vid", m_dei_vid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t& m) {
        uint64_t m_dei_vid;
            archive(::cereal::make_nvp("dei_vid", m_dei_vid));
        m.dei_vid = m_dei_vid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_4_table_set_inject_eth_payload_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_key_t& m) {
        uint64_t m_encap_selector = m.encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_key_t& m) {
        uint64_t m_encap_selector;
            archive(::cereal::make_nvp("encap_selector", m_encap_selector));
        m.encap_selector = m_encap_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_4_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_4_table_key_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_4_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_4_table_value_t&);



template<>
class serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_eth", m.set_inject_eth));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_punt_eth_hdr_4_table_value_t::npl_oamp_redirect_punt_eth_hdr_4_table_payloads_t&);



template<>
class serializer_class<npl_oamp_redirect_table_oamp_redirect_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_table_oamp_redirect_action_payload_t& m) {
        uint64_t m_encap_ptr = m.encap_ptr;
        uint64_t m_keep_counter = m.keep_counter;
        uint64_t m_drop = m.drop;
        uint64_t m_ifg = m.ifg;
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("encap_ptr", m_encap_ptr));
            archive(::cereal::make_nvp("keep_counter", m_keep_counter));
            archive(::cereal::make_nvp("drop", m_drop));
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("ifg", m_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_table_oamp_redirect_action_payload_t& m) {
        uint64_t m_encap_ptr;
        uint64_t m_keep_counter;
        uint64_t m_drop;
        uint64_t m_ifg;
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("encap_ptr", m_encap_ptr));
            archive(::cereal::make_nvp("keep_counter", m_keep_counter));
            archive(::cereal::make_nvp("drop", m_drop));
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("ifg", m_ifg));
        m.encap_ptr = m_encap_ptr;
        m.keep_counter = m_keep_counter;
        m.drop = m_drop;
        m.ifg = m_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_table_oamp_redirect_action_payload_t& m)
{
    serializer_class<npl_oamp_redirect_table_oamp_redirect_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_table_oamp_redirect_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_table_oamp_redirect_action_payload_t& m)
{
    serializer_class<npl_oamp_redirect_table_oamp_redirect_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_table_oamp_redirect_action_payload_t&);



template<>
class serializer_class<npl_oamp_redirect_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_table_key_t& m) {
        uint64_t m_redirect_code = m.redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_table_key_t& m) {
        uint64_t m_redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
        m.redirect_code = m_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_table_key_t& m)
{
    serializer_class<npl_oamp_redirect_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_table_key_t&);



template<>
class serializer_class<npl_oamp_redirect_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_table_value_t& m)
{
    serializer_class<npl_oamp_redirect_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_table_value_t&);



template<>
class serializer_class<npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t& m) {
            archive(::cereal::make_nvp("oamp_redirect_action", m.oamp_redirect_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t& m) {
            archive(::cereal::make_nvp("oamp_redirect_action", m.oamp_redirect_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t& m)
{
    serializer_class<npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_oamp_redirect_table_value_t::npl_oamp_redirect_table_payloads_t&);



template<>
class serializer_class<npl_obm_next_macro_static_table_update_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_obm_next_macro_static_table_update_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_obm_next_macro_static_table_update_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_obm_next_macro_static_table_update_next_macro_action_payload_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_update_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_obm_next_macro_static_table_update_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_obm_next_macro_static_table_update_next_macro_action_payload_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_update_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_obm_next_macro_static_table_update_next_macro_action_payload_t&);



template<>
class serializer_class<npl_obm_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_obm_next_macro_static_table_key_t& m) {
        uint64_t m_rcy_data_suffix = m.rcy_data_suffix;
            archive(::cereal::make_nvp("rcy_data_suffix", m_rcy_data_suffix));
            archive(::cereal::make_nvp("has_punt_header", m.has_punt_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_obm_next_macro_static_table_key_t& m) {
        uint64_t m_rcy_data_suffix;
            archive(::cereal::make_nvp("rcy_data_suffix", m_rcy_data_suffix));
            archive(::cereal::make_nvp("has_punt_header", m.has_punt_header));
        m.rcy_data_suffix = m_rcy_data_suffix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_obm_next_macro_static_table_key_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_obm_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_obm_next_macro_static_table_key_t& m)
{
    serializer_class<npl_obm_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_obm_next_macro_static_table_key_t&);



}

