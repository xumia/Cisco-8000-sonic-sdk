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

template <class Archive> void save(Archive&, const npl_common_cntr_offset_and_padding_t&);
template <class Archive> void load(Archive&, npl_common_cntr_offset_and_padding_t&);

template <class Archive> void save(Archive&, const npl_db_access_lu_data_t&);
template <class Archive> void load(Archive&, npl_db_access_lu_data_t&);

template <class Archive> void save(Archive&, const npl_db_access_splitter_action_t&);
template <class Archive> void load(Archive&, npl_db_access_splitter_action_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_em_common_data_t&);
template <class Archive> void load(Archive&, npl_em_common_data_t&);

template <class Archive> void save(Archive&, const npl_l3_slp_id_t&);
template <class Archive> void load(Archive&, npl_l3_slp_id_t&);

template <class Archive> void save(Archive&, const npl_lsp_encap_mapping_data_payload_t&);
template <class Archive> void load(Archive&, npl_lsp_encap_mapping_data_payload_t&);

template <class Archive> void save(Archive&, const npl_my_one_bit_result_t&);
template <class Archive> void load(Archive&, npl_my_one_bit_result_t&);

template <class Archive> void save(Archive&, const npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t&);
template <class Archive> void load(Archive&, npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t&);

template <class Archive> void save(Archive&, const npl_pd_svl_attributes_t&);
template <class Archive> void load(Archive&, npl_pd_svl_attributes_t&);

template <class Archive> void save(Archive&, const npl_resolution_entry_type_decoding_table_result_t&);
template <class Archive> void load(Archive&, npl_resolution_entry_type_decoding_table_result_t&);

template <class Archive> void save(Archive&, const npl_resolution_lb_size_table_result_t&);
template <class Archive> void load(Archive&, npl_resolution_lb_size_table_result_t&);

template <class Archive> void save(Archive&, const npl_resolution_protection_result_t&);
template <class Archive> void load(Archive&, npl_resolution_protection_result_t&);

template <class Archive> void save(Archive&, const npl_resolution_stage_assoc_data_result_t&);
template <class Archive> void load(Archive&, npl_resolution_stage_assoc_data_result_t&);

template <class Archive> void save(Archive&, const npl_resolution_stage_em_table_raw_key_t&);
template <class Archive> void load(Archive&, npl_resolution_stage_em_table_raw_key_t&);

template <class Archive> void save(Archive&, const npl_sgacl_payload_t&);
template <class Archive> void load(Archive&, npl_sgacl_payload_t&);

template <class Archive> void save(Archive&, const npl_sgt_matrix_result_t&);
template <class Archive> void load(Archive&, npl_sgt_matrix_result_t&);

template <class Archive> void save(Archive&, const npl_slp_fwd_result_t&);
template <class Archive> void load(Archive&, npl_slp_fwd_result_t&);

template <class Archive> void save(Archive&, const npl_snoop_code_t&);
template <class Archive> void load(Archive&, npl_snoop_code_t&);

template <class Archive> void save(Archive&, const npl_svl_mirror_remote_dsp_t&);
template <class Archive> void load(Archive&, npl_svl_mirror_remote_dsp_t&);

template <class Archive> void save(Archive&, const npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t&);
template <class Archive> void load(Archive&, npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t&);

template <class Archive> void save(Archive&, const npl_trap_conditions_t&);
template <class Archive> void load(Archive&, npl_trap_conditions_t&);

template <class Archive> void save(Archive&, const npl_traps_t&);
template <class Archive> void load(Archive&, npl_traps_t&);

template<>
class serializer_class<npl_sgacl_table_value_t::npl_sgacl_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_table_value_t::npl_sgacl_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgacl_payload", m.sgacl_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_table_value_t::npl_sgacl_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgacl_payload", m.sgacl_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_table_value_t::npl_sgacl_table_payloads_t& m)
{
    serializer_class<npl_sgacl_table_value_t::npl_sgacl_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_table_value_t::npl_sgacl_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_table_value_t::npl_sgacl_table_payloads_t& m)
{
    serializer_class<npl_sgacl_table_value_t::npl_sgacl_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_table_value_t::npl_sgacl_table_payloads_t&);



template<>
class serializer_class<npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
        uint64_t m_stage = m.stage;
        uint64_t m_next_macro_is_sgacl = m.next_macro_is_sgacl;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
            archive(::cereal::make_nvp("stage", m_stage));
            archive(::cereal::make_nvp("next_macro_is_sgacl", m_next_macro_is_sgacl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
        uint64_t m_stage;
        uint64_t m_next_macro_is_sgacl;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
            archive(::cereal::make_nvp("stage", m_stage));
            archive(::cereal::make_nvp("next_macro_is_sgacl", m_next_macro_is_sgacl));
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
        m.stage = m_stage;
        m.next_macro_is_sgacl = m_next_macro_is_sgacl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_derivation_macro_static_table_sgt_derivation_next_macro_action_payload_t&);



template<>
class serializer_class<npl_sgt_derivation_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_derivation_macro_static_table_key_t& m) {
        uint64_t m_enforcement = m.enforcement;
        uint64_t m_valid_ip_sgt_derived = m.valid_ip_sgt_derived;
        uint64_t m_macro_stage_vxlan_svl_pack = m.macro_stage_vxlan_svl_pack;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("enforcement", m_enforcement));
            archive(::cereal::make_nvp("valid_ip_sgt_derived", m_valid_ip_sgt_derived));
            archive(::cereal::make_nvp("macro_stage_vxlan_svl_pack", m_macro_stage_vxlan_svl_pack));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_derivation_macro_static_table_key_t& m) {
        uint64_t m_enforcement;
        uint64_t m_valid_ip_sgt_derived;
        uint64_t m_macro_stage_vxlan_svl_pack;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("enforcement", m_enforcement));
            archive(::cereal::make_nvp("valid_ip_sgt_derived", m_valid_ip_sgt_derived));
            archive(::cereal::make_nvp("macro_stage_vxlan_svl_pack", m_macro_stage_vxlan_svl_pack));
        m.enforcement = m_enforcement;
        m.valid_ip_sgt_derived = m_valid_ip_sgt_derived;
        m.macro_stage_vxlan_svl_pack = m_macro_stage_vxlan_svl_pack;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_derivation_macro_static_table_key_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_derivation_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_derivation_macro_static_table_key_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_derivation_macro_static_table_key_t&);



template<>
class serializer_class<npl_sgt_derivation_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_derivation_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_derivation_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_derivation_macro_static_table_value_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_derivation_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_derivation_macro_static_table_value_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_derivation_macro_static_table_value_t&);



template<>
class serializer_class<npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_derivation_next_macro_action", m.sgt_derivation_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_derivation_next_macro_action", m.sgt_derivation_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t& m)
{
    serializer_class<npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_derivation_macro_static_table_value_t::npl_sgt_derivation_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_sgt_matrix_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_matrix_table_key_t& m) {
        uint64_t m_src_sgt = m.src_sgt;
        uint64_t m_dst_sgt = m.dst_sgt;
        uint64_t m_ip_version = m.ip_version;
            archive(::cereal::make_nvp("src_sgt", m_src_sgt));
            archive(::cereal::make_nvp("dst_sgt", m_dst_sgt));
            archive(::cereal::make_nvp("ip_version", m_ip_version));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_matrix_table_key_t& m) {
        uint64_t m_src_sgt;
        uint64_t m_dst_sgt;
        uint64_t m_ip_version;
            archive(::cereal::make_nvp("src_sgt", m_src_sgt));
            archive(::cereal::make_nvp("dst_sgt", m_dst_sgt));
            archive(::cereal::make_nvp("ip_version", m_ip_version));
        m.src_sgt = m_src_sgt;
        m.dst_sgt = m_dst_sgt;
        m.ip_version = m_ip_version;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_matrix_table_key_t& m)
{
    serializer_class<npl_sgt_matrix_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_matrix_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_matrix_table_key_t& m)
{
    serializer_class<npl_sgt_matrix_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_matrix_table_key_t&);



template<>
class serializer_class<npl_sgt_matrix_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_matrix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_matrix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_matrix_table_value_t& m)
{
    serializer_class<npl_sgt_matrix_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_matrix_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_matrix_table_value_t& m)
{
    serializer_class<npl_sgt_matrix_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_matrix_table_value_t&);



template<>
class serializer_class<npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_matrix_em_result", m.sgt_matrix_em_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_matrix_em_result", m.sgt_matrix_em_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t& m)
{
    serializer_class<npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t& m)
{
    serializer_class<npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_matrix_table_value_t::npl_sgt_matrix_table_payloads_t&);



template<>
class serializer_class<npl_sgt_vxlan_termination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_vxlan_termination_table_key_t& m) {
        uint64_t m_policy_flag = m.policy_flag;
            archive(::cereal::make_nvp("hdr_type_2", m.hdr_type_2));
            archive(::cereal::make_nvp("policy_flag", m_policy_flag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_vxlan_termination_table_key_t& m) {
        uint64_t m_policy_flag;
            archive(::cereal::make_nvp("hdr_type_2", m.hdr_type_2));
            archive(::cereal::make_nvp("policy_flag", m_policy_flag));
        m.policy_flag = m_policy_flag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_vxlan_termination_table_key_t& m)
{
    serializer_class<npl_sgt_vxlan_termination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_vxlan_termination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_vxlan_termination_table_key_t& m)
{
    serializer_class<npl_sgt_vxlan_termination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_vxlan_termination_table_key_t&);



template<>
class serializer_class<npl_sgt_vxlan_termination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_vxlan_termination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_vxlan_termination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_vxlan_termination_table_value_t& m)
{
    serializer_class<npl_sgt_vxlan_termination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_vxlan_termination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_vxlan_termination_table_value_t& m)
{
    serializer_class<npl_sgt_vxlan_termination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_vxlan_termination_table_value_t&);



template<>
class serializer_class<npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t& m) {
        uint64_t m_vxlan_terminated = m.vxlan_terminated;
            archive(::cereal::make_nvp("vxlan_terminated", m_vxlan_terminated));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t& m) {
        uint64_t m_vxlan_terminated;
            archive(::cereal::make_nvp("vxlan_terminated", m_vxlan_terminated));
        m.vxlan_terminated = m_vxlan_terminated;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t& m)
{
    serializer_class<npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t& m)
{
    serializer_class<npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgt_vxlan_termination_table_value_t::npl_sgt_vxlan_termination_table_payloads_t&);



template<>
class serializer_class<npl_sip_index_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sip_index_table_key_t& m) {
        uint64_t m_sip_index = m.sip_index;
            archive(::cereal::make_nvp("sip_index", m_sip_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sip_index_table_key_t& m) {
        uint64_t m_sip_index;
            archive(::cereal::make_nvp("sip_index", m_sip_index));
        m.sip_index = m_sip_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sip_index_table_key_t& m)
{
    serializer_class<npl_sip_index_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sip_index_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sip_index_table_key_t& m)
{
    serializer_class<npl_sip_index_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sip_index_table_key_t&);



template<>
class serializer_class<npl_sip_index_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sip_index_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sip_index_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sip_index_table_value_t& m)
{
    serializer_class<npl_sip_index_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sip_index_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sip_index_table_value_t& m)
{
    serializer_class<npl_sip_index_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sip_index_table_value_t&);



template<>
class serializer_class<npl_sip_index_table_value_t::npl_sip_index_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sip_index_table_value_t::npl_sip_index_table_payloads_t& m) {
        uint64_t m_sip = m.sip;
            archive(::cereal::make_nvp("sip", m_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sip_index_table_value_t::npl_sip_index_table_payloads_t& m) {
        uint64_t m_sip;
            archive(::cereal::make_nvp("sip", m_sip));
        m.sip = m_sip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sip_index_table_value_t::npl_sip_index_table_payloads_t& m)
{
    serializer_class<npl_sip_index_table_value_t::npl_sip_index_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sip_index_table_value_t::npl_sip_index_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sip_index_table_value_t::npl_sip_index_table_payloads_t& m)
{
    serializer_class<npl_sip_index_table_value_t::npl_sip_index_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sip_index_table_value_t::npl_sip_index_table_payloads_t&);



template<>
class serializer_class<npl_slice_modes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slice_modes_table_key_t& m) {
        uint64_t m_slice_id = m.slice_id;
            archive(::cereal::make_nvp("slice_id", m_slice_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slice_modes_table_key_t& m) {
        uint64_t m_slice_id;
            archive(::cereal::make_nvp("slice_id", m_slice_id));
        m.slice_id = m_slice_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slice_modes_table_key_t& m)
{
    serializer_class<npl_slice_modes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slice_modes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_slice_modes_table_key_t& m)
{
    serializer_class<npl_slice_modes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slice_modes_table_key_t&);



template<>
class serializer_class<npl_slice_modes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slice_modes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slice_modes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slice_modes_table_value_t& m)
{
    serializer_class<npl_slice_modes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slice_modes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_slice_modes_table_value_t& m)
{
    serializer_class<npl_slice_modes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slice_modes_table_value_t&);



template<>
class serializer_class<npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t& m) {
            archive(::cereal::make_nvp("slice_modes_table_in_out_vars_slice_mode", m.slice_modes_table_in_out_vars_slice_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t& m) {
            archive(::cereal::make_nvp("slice_modes_table_in_out_vars_slice_mode", m.slice_modes_table_in_out_vars_slice_mode));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t& m)
{
    serializer_class<npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t& m)
{
    serializer_class<npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slice_modes_table_value_t::npl_slice_modes_table_payloads_t&);



template<>
class serializer_class<npl_slp_based_forwarding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slp_based_forwarding_table_key_t& m) {
            archive(::cereal::make_nvp("slp_id", m.slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slp_based_forwarding_table_key_t& m) {
            archive(::cereal::make_nvp("slp_id", m.slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slp_based_forwarding_table_key_t& m)
{
    serializer_class<npl_slp_based_forwarding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slp_based_forwarding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_slp_based_forwarding_table_key_t& m)
{
    serializer_class<npl_slp_based_forwarding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slp_based_forwarding_table_key_t&);



template<>
class serializer_class<npl_slp_based_forwarding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slp_based_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slp_based_forwarding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slp_based_forwarding_table_value_t& m)
{
    serializer_class<npl_slp_based_forwarding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slp_based_forwarding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_slp_based_forwarding_table_value_t& m)
{
    serializer_class<npl_slp_based_forwarding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slp_based_forwarding_table_value_t&);



template<>
class serializer_class<npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("slp_fwd_result", m.slp_fwd_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t& m) {
            archive(::cereal::make_nvp("slp_fwd_result", m.slp_fwd_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t& m)
{
    serializer_class<npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t& m)
{
    serializer_class<npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_slp_based_forwarding_table_value_t::npl_slp_based_forwarding_table_payloads_t&);



template<>
class serializer_class<npl_small_em_key_lsb_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_em_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_em_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_em_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_small_em_key_lsb_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_em_key_lsb_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_small_em_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_small_em_key_lsb_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_em_key_lsb_mapping_table_key_t&);



template<>
class serializer_class<npl_small_em_key_lsb_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_em_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_em_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_em_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_small_em_key_lsb_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_em_key_lsb_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_small_em_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_small_em_key_lsb_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_em_key_lsb_mapping_table_value_t&);



template<>
class serializer_class<npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("small_em_key_lsb", m.small_em_key_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("small_em_key_lsb", m.small_em_key_lsb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_em_key_lsb_mapping_table_value_t::npl_small_em_key_lsb_mapping_table_payloads_t&);



template<>
class serializer_class<npl_small_encap_mpls_he_asbr_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_encap_mpls_he_asbr_table_key_t& m) {
        uint64_t m_asbr = m.asbr;
        uint64_t m_nh_ptr = m.nh_ptr;
            archive(::cereal::make_nvp("asbr", m_asbr));
            archive(::cereal::make_nvp("nh_ptr", m_nh_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_encap_mpls_he_asbr_table_key_t& m) {
        uint64_t m_asbr;
        uint64_t m_nh_ptr;
            archive(::cereal::make_nvp("asbr", m_asbr));
            archive(::cereal::make_nvp("nh_ptr", m_nh_ptr));
        m.asbr = m_asbr;
        m.nh_ptr = m_nh_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_encap_mpls_he_asbr_table_key_t& m)
{
    serializer_class<npl_small_encap_mpls_he_asbr_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_encap_mpls_he_asbr_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_small_encap_mpls_he_asbr_table_key_t& m)
{
    serializer_class<npl_small_encap_mpls_he_asbr_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_encap_mpls_he_asbr_table_key_t&);



template<>
class serializer_class<npl_small_encap_mpls_he_asbr_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_encap_mpls_he_asbr_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_encap_mpls_he_asbr_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_encap_mpls_he_asbr_table_value_t& m)
{
    serializer_class<npl_small_encap_mpls_he_asbr_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_encap_mpls_he_asbr_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_small_encap_mpls_he_asbr_table_value_t& m)
{
    serializer_class<npl_small_encap_mpls_he_asbr_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_encap_mpls_he_asbr_table_value_t&);



template<>
class serializer_class<npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload_asbr", m.lsp_encap_mapping_data_payload_asbr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload_asbr", m.lsp_encap_mapping_data_payload_asbr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t& m)
{
    serializer_class<npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t& m)
{
    serializer_class<npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_encap_mpls_he_asbr_table_value_t::npl_small_encap_mpls_he_asbr_table_payloads_t&);



template<>
class serializer_class<npl_small_encap_mpls_he_te_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_encap_mpls_he_te_table_key_t& m) {
        uint64_t m_te_tunnel = m.te_tunnel;
        uint64_t m_nh_ptr = m.nh_ptr;
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
            archive(::cereal::make_nvp("nh_ptr", m_nh_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_encap_mpls_he_te_table_key_t& m) {
        uint64_t m_te_tunnel;
        uint64_t m_nh_ptr;
            archive(::cereal::make_nvp("te_tunnel", m_te_tunnel));
            archive(::cereal::make_nvp("nh_ptr", m_nh_ptr));
        m.te_tunnel = m_te_tunnel;
        m.nh_ptr = m_nh_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_encap_mpls_he_te_table_key_t& m)
{
    serializer_class<npl_small_encap_mpls_he_te_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_encap_mpls_he_te_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_small_encap_mpls_he_te_table_key_t& m)
{
    serializer_class<npl_small_encap_mpls_he_te_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_encap_mpls_he_te_table_key_t&);



template<>
class serializer_class<npl_small_encap_mpls_he_te_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_encap_mpls_he_te_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_encap_mpls_he_te_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_encap_mpls_he_te_table_value_t& m)
{
    serializer_class<npl_small_encap_mpls_he_te_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_encap_mpls_he_te_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_small_encap_mpls_he_te_table_value_t& m)
{
    serializer_class<npl_small_encap_mpls_he_te_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_encap_mpls_he_te_table_value_t&);



template<>
class serializer_class<npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload_asbr", m.lsp_encap_mapping_data_payload_asbr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t& m) {
            archive(::cereal::make_nvp("lsp_encap_mapping_data_payload_asbr", m.lsp_encap_mapping_data_payload_asbr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t& m)
{
    serializer_class<npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t& m)
{
    serializer_class<npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_small_encap_mpls_he_te_table_value_t::npl_small_encap_mpls_he_te_table_payloads_t&);



template<>
class serializer_class<npl_snoop_code_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_code_hw_table_key_t& m) {
        uint64_t m_pd_common_leaba_fields_snoop_code = m.pd_common_leaba_fields_snoop_code;
            archive(::cereal::make_nvp("pd_common_leaba_fields_snoop_code", m_pd_common_leaba_fields_snoop_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_code_hw_table_key_t& m) {
        uint64_t m_pd_common_leaba_fields_snoop_code;
            archive(::cereal::make_nvp("pd_common_leaba_fields_snoop_code", m_pd_common_leaba_fields_snoop_code));
        m.pd_common_leaba_fields_snoop_code = m_pd_common_leaba_fields_snoop_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_code_hw_table_key_t& m)
{
    serializer_class<npl_snoop_code_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_code_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_code_hw_table_key_t& m)
{
    serializer_class<npl_snoop_code_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_code_hw_table_key_t&);



template<>
class serializer_class<npl_snoop_code_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_code_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_code_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_code_hw_table_value_t& m)
{
    serializer_class<npl_snoop_code_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_code_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_code_hw_table_value_t& m)
{
    serializer_class<npl_snoop_code_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_code_hw_table_value_t&);



template<>
class serializer_class<npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t& m) {
        uint64_t m_rxpp_pd_in_mirror_cmd0 = m.rxpp_pd_in_mirror_cmd0;
            archive(::cereal::make_nvp("rxpp_pd_in_mirror_cmd0", m_rxpp_pd_in_mirror_cmd0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t& m) {
        uint64_t m_rxpp_pd_in_mirror_cmd0;
            archive(::cereal::make_nvp("rxpp_pd_in_mirror_cmd0", m_rxpp_pd_in_mirror_cmd0));
        m.rxpp_pd_in_mirror_cmd0 = m_rxpp_pd_in_mirror_cmd0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t& m)
{
    serializer_class<npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t& m)
{
    serializer_class<npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_code_hw_table_value_t::npl_snoop_code_hw_table_payloads_t&);



template<>
class serializer_class<npl_snoop_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_table_key_t& m) {
            archive(::cereal::make_nvp("traps", m.traps));
            archive(::cereal::make_nvp("trap_conditions", m.trap_conditions));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_table_key_t& m) {
            archive(::cereal::make_nvp("traps", m.traps));
            archive(::cereal::make_nvp("trap_conditions", m.trap_conditions));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_table_key_t& m)
{
    serializer_class<npl_snoop_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_table_key_t& m)
{
    serializer_class<npl_snoop_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_table_key_t&);



template<>
class serializer_class<npl_snoop_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_table_value_t& m)
{
    serializer_class<npl_snoop_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_table_value_t& m)
{
    serializer_class<npl_snoop_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_table_value_t&);



template<>
class serializer_class<npl_snoop_table_value_t::npl_snoop_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_table_value_t::npl_snoop_table_payloads_t& m) {
            archive(::cereal::make_nvp("snoop_code", m.snoop_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_table_value_t::npl_snoop_table_payloads_t& m) {
            archive(::cereal::make_nvp("snoop_code", m.snoop_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_table_value_t::npl_snoop_table_payloads_t& m)
{
    serializer_class<npl_snoop_table_value_t::npl_snoop_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_table_value_t::npl_snoop_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_table_value_t::npl_snoop_table_payloads_t& m)
{
    serializer_class<npl_snoop_table_value_t::npl_snoop_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_table_value_t::npl_snoop_table_payloads_t&);



template<>
class serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_to_dsp_in_npu_soft_header_table_key_t& m) {
        uint64_t m_device_snoop_code = m.device_snoop_code;
            archive(::cereal::make_nvp("device_snoop_code", m_device_snoop_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_to_dsp_in_npu_soft_header_table_key_t& m) {
        uint64_t m_device_snoop_code;
            archive(::cereal::make_nvp("device_snoop_code", m_device_snoop_code));
        m.device_snoop_code = m_device_snoop_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_to_dsp_in_npu_soft_header_table_key_t& m)
{
    serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_to_dsp_in_npu_soft_header_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_to_dsp_in_npu_soft_header_table_key_t& m)
{
    serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_to_dsp_in_npu_soft_header_table_key_t&);



template<>
class serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_to_dsp_in_npu_soft_header_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_to_dsp_in_npu_soft_header_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_to_dsp_in_npu_soft_header_table_value_t& m)
{
    serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_to_dsp_in_npu_soft_header_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_to_dsp_in_npu_soft_header_table_value_t& m)
{
    serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_to_dsp_in_npu_soft_header_table_value_t&);



template<>
class serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t& m) {
        uint64_t m_update_dsp_in_npu_soft_header = m.update_dsp_in_npu_soft_header;
            archive(::cereal::make_nvp("update_dsp_in_npu_soft_header", m_update_dsp_in_npu_soft_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t& m) {
        uint64_t m_update_dsp_in_npu_soft_header;
            archive(::cereal::make_nvp("update_dsp_in_npu_soft_header", m_update_dsp_in_npu_soft_header));
        m.update_dsp_in_npu_soft_header = m_update_dsp_in_npu_soft_header;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t& m)
{
    serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t& m)
{
    serializer_class<npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_snoop_to_dsp_in_npu_soft_header_table_value_t::npl_snoop_to_dsp_in_npu_soft_header_table_payloads_t&);



template<>
class serializer_class<npl_source_pif_hw_table_init_rx_data_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_pif_hw_table_init_rx_data_payload_t& m) {
        uint64_t m_initial_layer_index = m.initial_layer_index;
        uint64_t m_first_header_type = m.first_header_type;
        uint64_t m_first_header_is_layer = m.first_header_is_layer;
        uint64_t m_np_macro_id = m.np_macro_id;
        uint64_t m_fi_macro_id = m.fi_macro_id;
            archive(::cereal::make_nvp("initial_layer_index", m_initial_layer_index));
            archive(::cereal::make_nvp("first_header_type", m_first_header_type));
            archive(::cereal::make_nvp("first_header_is_layer", m_first_header_is_layer));
            archive(::cereal::make_nvp("initial_rx_data", m.initial_rx_data));
            archive(::cereal::make_nvp("tag_swap_cmd", m.tag_swap_cmd));
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
            archive(::cereal::make_nvp("fi_macro_id", m_fi_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_pif_hw_table_init_rx_data_payload_t& m) {
        uint64_t m_initial_layer_index;
        uint64_t m_first_header_type;
        uint64_t m_first_header_is_layer;
        uint64_t m_np_macro_id;
        uint64_t m_fi_macro_id;
            archive(::cereal::make_nvp("initial_layer_index", m_initial_layer_index));
            archive(::cereal::make_nvp("first_header_type", m_first_header_type));
            archive(::cereal::make_nvp("first_header_is_layer", m_first_header_is_layer));
            archive(::cereal::make_nvp("initial_rx_data", m.initial_rx_data));
            archive(::cereal::make_nvp("tag_swap_cmd", m.tag_swap_cmd));
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
            archive(::cereal::make_nvp("fi_macro_id", m_fi_macro_id));
        m.initial_layer_index = m_initial_layer_index;
        m.first_header_type = m_first_header_type;
        m.first_header_is_layer = m_first_header_is_layer;
        m.np_macro_id = m_np_macro_id;
        m.fi_macro_id = m_fi_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_pif_hw_table_init_rx_data_payload_t& m)
{
    serializer_class<npl_source_pif_hw_table_init_rx_data_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_pif_hw_table_init_rx_data_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_source_pif_hw_table_init_rx_data_payload_t& m)
{
    serializer_class<npl_source_pif_hw_table_init_rx_data_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_pif_hw_table_init_rx_data_payload_t&);



template<>
class serializer_class<npl_source_pif_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_pif_hw_table_key_t& m) {
        uint64_t m_rxpp_npu_input_ifg_rx_fd_source_pif = m.rxpp_npu_input_ifg_rx_fd_source_pif;
        uint64_t m_rxpp_npu_input_ifg = m.rxpp_npu_input_ifg;
            archive(::cereal::make_nvp("rxpp_npu_input_ifg_rx_fd_source_pif", m_rxpp_npu_input_ifg_rx_fd_source_pif));
            archive(::cereal::make_nvp("rxpp_npu_input_ifg", m_rxpp_npu_input_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_pif_hw_table_key_t& m) {
        uint64_t m_rxpp_npu_input_ifg_rx_fd_source_pif;
        uint64_t m_rxpp_npu_input_ifg;
            archive(::cereal::make_nvp("rxpp_npu_input_ifg_rx_fd_source_pif", m_rxpp_npu_input_ifg_rx_fd_source_pif));
            archive(::cereal::make_nvp("rxpp_npu_input_ifg", m_rxpp_npu_input_ifg));
        m.rxpp_npu_input_ifg_rx_fd_source_pif = m_rxpp_npu_input_ifg_rx_fd_source_pif;
        m.rxpp_npu_input_ifg = m_rxpp_npu_input_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_pif_hw_table_key_t& m)
{
    serializer_class<npl_source_pif_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_pif_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_source_pif_hw_table_key_t& m)
{
    serializer_class<npl_source_pif_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_pif_hw_table_key_t&);



template<>
class serializer_class<npl_source_pif_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_pif_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_pif_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_pif_hw_table_value_t& m)
{
    serializer_class<npl_source_pif_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_pif_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_source_pif_hw_table_value_t& m)
{
    serializer_class<npl_source_pif_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_pif_hw_table_value_t&);



template<>
class serializer_class<npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_rx_data", m.init_rx_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_rx_data", m.init_rx_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t& m)
{
    serializer_class<npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t& m)
{
    serializer_class<npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_pif_hw_table_value_t::npl_source_pif_hw_table_payloads_t&);



template<>
class serializer_class<npl_source_port_to_link_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_port_to_link_table_key_t& m) {
        uint64_t m_rxpp_pd_source_if_7_2_ = m.rxpp_pd_source_if_7_2_;
            archive(::cereal::make_nvp("rxpp_pd_source_if_7_2_", m_rxpp_pd_source_if_7_2_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_port_to_link_table_key_t& m) {
        uint64_t m_rxpp_pd_source_if_7_2_;
            archive(::cereal::make_nvp("rxpp_pd_source_if_7_2_", m_rxpp_pd_source_if_7_2_));
        m.rxpp_pd_source_if_7_2_ = m_rxpp_pd_source_if_7_2_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_port_to_link_table_key_t& m)
{
    serializer_class<npl_source_port_to_link_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_port_to_link_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_source_port_to_link_table_key_t& m)
{
    serializer_class<npl_source_port_to_link_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_port_to_link_table_key_t&);



template<>
class serializer_class<npl_source_port_to_link_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_port_to_link_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_port_to_link_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_port_to_link_table_value_t& m)
{
    serializer_class<npl_source_port_to_link_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_port_to_link_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_source_port_to_link_table_value_t& m)
{
    serializer_class<npl_source_port_to_link_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_port_to_link_table_value_t&);



template<>
class serializer_class<npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t& m) {
        uint64_t m_cmnlv_fabric_port_id_in_slice = m.cmnlv_fabric_port_id_in_slice;
            archive(::cereal::make_nvp("cmnlv_fabric_port_id_in_slice", m_cmnlv_fabric_port_id_in_slice));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t& m) {
        uint64_t m_cmnlv_fabric_port_id_in_slice;
            archive(::cereal::make_nvp("cmnlv_fabric_port_id_in_slice", m_cmnlv_fabric_port_id_in_slice));
        m.cmnlv_fabric_port_id_in_slice = m_cmnlv_fabric_port_id_in_slice;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t& m)
{
    serializer_class<npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t& m)
{
    serializer_class<npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_source_port_to_link_table_value_t::npl_source_port_to_link_table_payloads_t&);



template<>
class serializer_class<npl_splitter_lu_b_key_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_splitter_lu_b_key_selector_key_t& m) {
            archive(::cereal::make_nvp("lu_b_dest", m.lu_b_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_splitter_lu_b_key_selector_key_t& m) {
            archive(::cereal::make_nvp("lu_b_dest", m.lu_b_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_splitter_lu_b_key_selector_key_t& m)
{
    serializer_class<npl_splitter_lu_b_key_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_splitter_lu_b_key_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_splitter_lu_b_key_selector_key_t& m)
{
    serializer_class<npl_splitter_lu_b_key_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_splitter_lu_b_key_selector_key_t&);



template<>
class serializer_class<npl_splitter_lu_b_key_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_splitter_lu_b_key_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_splitter_lu_b_key_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_splitter_lu_b_key_selector_value_t& m)
{
    serializer_class<npl_splitter_lu_b_key_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_splitter_lu_b_key_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_splitter_lu_b_key_selector_value_t& m)
{
    serializer_class<npl_splitter_lu_b_key_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_splitter_lu_b_key_selector_value_t&);



template<>
class serializer_class<npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t& m) {
            archive(::cereal::make_nvp("lu_b_splitter_action", m.lu_b_splitter_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t& m) {
            archive(::cereal::make_nvp("lu_b_splitter_action", m.lu_b_splitter_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t& m)
{
    serializer_class<npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t& m)
{
    serializer_class<npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_splitter_lu_b_key_selector_value_t::npl_splitter_lu_b_key_selector_payloads_t&);



template<>
class serializer_class<npl_splitter_lu_d_key_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_splitter_lu_d_key_selector_key_t& m) {
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_splitter_lu_d_key_selector_key_t& m) {
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_splitter_lu_d_key_selector_key_t& m)
{
    serializer_class<npl_splitter_lu_d_key_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_splitter_lu_d_key_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_splitter_lu_d_key_selector_key_t& m)
{
    serializer_class<npl_splitter_lu_d_key_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_splitter_lu_d_key_selector_key_t&);



template<>
class serializer_class<npl_splitter_lu_d_key_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_splitter_lu_d_key_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_splitter_lu_d_key_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_splitter_lu_d_key_selector_value_t& m)
{
    serializer_class<npl_splitter_lu_d_key_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_splitter_lu_d_key_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_splitter_lu_d_key_selector_value_t& m)
{
    serializer_class<npl_splitter_lu_d_key_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_splitter_lu_d_key_selector_value_t&);



template<>
class serializer_class<npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t& m) {
            archive(::cereal::make_nvp("lu_d_splitter_action", m.lu_d_splitter_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t& m) {
            archive(::cereal::make_nvp("lu_d_splitter_action", m.lu_d_splitter_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t& m)
{
    serializer_class<npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t& m)
{
    serializer_class<npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_splitter_lu_d_key_selector_value_t::npl_splitter_lu_d_key_selector_payloads_t&);



template<>
class serializer_class<npl_stage0_assoc_data_table_line_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_line_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_assoc_data_table_line_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_line_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_assoc_data_table_line_payload_t&);



template<>
class serializer_class<npl_stage0_assoc_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_assoc_data_table_key_t& m) {
        uint64_t m_addr = m.addr;
            archive(::cereal::make_nvp("addr", m_addr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_assoc_data_table_key_t& m) {
        uint64_t m_addr;
            archive(::cereal::make_nvp("addr", m_addr));
        m.addr = m_addr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_assoc_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_assoc_data_table_key_t&);



template<>
class serializer_class<npl_stage0_assoc_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_assoc_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_assoc_data_table_value_t&);



template<>
class serializer_class<npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_assoc_data_table_value_t::npl_stage0_assoc_data_table_payloads_t&);



template<>
class serializer_class<npl_stage0_em_table_entry_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_em_table_entry_payload_t& m) {
        uint64_t m_addr = m.addr;
        uint64_t m_entry_select = m.entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_em_table_entry_payload_t& m) {
        uint64_t m_addr;
        uint64_t m_entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
        m.addr = m_addr;
        m.entry_select = m_entry_select;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage0_em_table_entry_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_em_table_entry_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage0_em_table_entry_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_em_table_entry_payload_t&);



template<>
class serializer_class<npl_stage0_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_em_table_key_t& m)
{
    serializer_class<npl_stage0_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_em_table_key_t& m)
{
    serializer_class<npl_stage0_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_em_table_key_t&);



template<>
class serializer_class<npl_stage0_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_em_table_value_t& m)
{
    serializer_class<npl_stage0_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_em_table_value_t& m)
{
    serializer_class<npl_stage0_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_em_table_value_t&);



template<>
class serializer_class<npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t& m)
{
    serializer_class<npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t& m)
{
    serializer_class<npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_em_table_value_t::npl_stage0_em_table_payloads_t&);



template<>
class serializer_class<npl_stage0_group_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_group_size_table_key_t& m) {
        uint64_t m_group_id = m.group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_group_size_table_key_t& m) {
        uint64_t m_group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
        m.group_id = m_group_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_group_size_table_key_t& m)
{
    serializer_class<npl_stage0_group_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_group_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_group_size_table_key_t& m)
{
    serializer_class<npl_stage0_group_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_group_size_table_key_t&);



template<>
class serializer_class<npl_stage0_group_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_group_size_table_value_t& m)
{
    serializer_class<npl_stage0_group_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_group_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_group_size_table_value_t& m)
{
    serializer_class<npl_stage0_group_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_group_size_table_value_t&);



template<>
class serializer_class<npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_group_size_table_value_t::npl_stage0_group_size_table_payloads_t&);



template<>
class serializer_class<npl_stage0_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_protection_table_key_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_protection_table_key_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_protection_table_key_t& m)
{
    serializer_class<npl_stage0_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_protection_table_key_t& m)
{
    serializer_class<npl_stage0_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_protection_table_key_t&);



template<>
class serializer_class<npl_stage0_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_protection_table_value_t& m)
{
    serializer_class<npl_stage0_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_protection_table_value_t& m)
{
    serializer_class<npl_stage0_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_protection_table_value_t&);



template<>
class serializer_class<npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t& m)
{
    serializer_class<npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t& m)
{
    serializer_class<npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_protection_table_value_t::npl_stage0_protection_table_payloads_t&);



template<>
class serializer_class<npl_stage0_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage0_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage0_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_type_decoding_table_key_t&);



template<>
class serializer_class<npl_stage0_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage0_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage0_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_type_decoding_table_value_t&);



template<>
class serializer_class<npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage0_type_decoding_table_value_t::npl_stage0_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_stage1_assoc_data_table_line_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_line_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_assoc_data_table_line_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_line_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_assoc_data_table_line_payload_t&);



template<>
class serializer_class<npl_stage1_assoc_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_assoc_data_table_key_t& m) {
        uint64_t m_addr = m.addr;
            archive(::cereal::make_nvp("addr", m_addr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_assoc_data_table_key_t& m) {
        uint64_t m_addr;
            archive(::cereal::make_nvp("addr", m_addr));
        m.addr = m_addr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_assoc_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_assoc_data_table_key_t&);



template<>
class serializer_class<npl_stage1_assoc_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_assoc_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_assoc_data_table_value_t&);



template<>
class serializer_class<npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_assoc_data_table_value_t::npl_stage1_assoc_data_table_payloads_t&);



template<>
class serializer_class<npl_stage1_em_table_entry_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_em_table_entry_payload_t& m) {
        uint64_t m_addr = m.addr;
        uint64_t m_entry_select = m.entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_em_table_entry_payload_t& m) {
        uint64_t m_addr;
        uint64_t m_entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
        m.addr = m_addr;
        m.entry_select = m_entry_select;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage1_em_table_entry_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_em_table_entry_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage1_em_table_entry_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_em_table_entry_payload_t&);



template<>
class serializer_class<npl_stage1_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_em_table_key_t& m)
{
    serializer_class<npl_stage1_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_em_table_key_t& m)
{
    serializer_class<npl_stage1_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_em_table_key_t&);



template<>
class serializer_class<npl_stage1_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_em_table_value_t& m)
{
    serializer_class<npl_stage1_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_em_table_value_t& m)
{
    serializer_class<npl_stage1_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_em_table_value_t&);



template<>
class serializer_class<npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t& m)
{
    serializer_class<npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t& m)
{
    serializer_class<npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_em_table_value_t::npl_stage1_em_table_payloads_t&);



template<>
class serializer_class<npl_stage1_group_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_group_size_table_key_t& m) {
        uint64_t m_group_id = m.group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_group_size_table_key_t& m) {
        uint64_t m_group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
        m.group_id = m_group_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_group_size_table_key_t& m)
{
    serializer_class<npl_stage1_group_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_group_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_group_size_table_key_t& m)
{
    serializer_class<npl_stage1_group_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_group_size_table_key_t&);



template<>
class serializer_class<npl_stage1_group_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_group_size_table_value_t& m)
{
    serializer_class<npl_stage1_group_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_group_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_group_size_table_value_t& m)
{
    serializer_class<npl_stage1_group_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_group_size_table_value_t&);



template<>
class serializer_class<npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_group_size_table_value_t::npl_stage1_group_size_table_payloads_t&);



template<>
class serializer_class<npl_stage1_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_protection_table_key_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_protection_table_key_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_protection_table_key_t& m)
{
    serializer_class<npl_stage1_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_protection_table_key_t& m)
{
    serializer_class<npl_stage1_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_protection_table_key_t&);



template<>
class serializer_class<npl_stage1_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_protection_table_value_t& m)
{
    serializer_class<npl_stage1_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_protection_table_value_t& m)
{
    serializer_class<npl_stage1_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_protection_table_value_t&);



template<>
class serializer_class<npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t& m)
{
    serializer_class<npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t& m)
{
    serializer_class<npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_protection_table_value_t::npl_stage1_protection_table_payloads_t&);



template<>
class serializer_class<npl_stage1_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage1_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage1_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_type_decoding_table_key_t&);



template<>
class serializer_class<npl_stage1_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage1_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage1_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_type_decoding_table_value_t&);



template<>
class serializer_class<npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage1_type_decoding_table_value_t::npl_stage1_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_stage2_assoc_data_table_line_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_line_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_assoc_data_table_line_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_line_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_assoc_data_table_line_payload_t&);



template<>
class serializer_class<npl_stage2_assoc_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_assoc_data_table_key_t& m) {
        uint64_t m_addr = m.addr;
            archive(::cereal::make_nvp("addr", m_addr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_assoc_data_table_key_t& m) {
        uint64_t m_addr;
            archive(::cereal::make_nvp("addr", m_addr));
        m.addr = m_addr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_assoc_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_assoc_data_table_key_t&);



template<>
class serializer_class<npl_stage2_assoc_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_assoc_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_assoc_data_table_value_t&);



template<>
class serializer_class<npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_assoc_data_table_value_t::npl_stage2_assoc_data_table_payloads_t&);



template<>
class serializer_class<npl_stage2_em_table_entry_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_em_table_entry_payload_t& m) {
        uint64_t m_addr = m.addr;
        uint64_t m_entry_select = m.entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_em_table_entry_payload_t& m) {
        uint64_t m_addr;
        uint64_t m_entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
        m.addr = m_addr;
        m.entry_select = m_entry_select;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage2_em_table_entry_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_em_table_entry_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage2_em_table_entry_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_em_table_entry_payload_t&);



template<>
class serializer_class<npl_stage2_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_em_table_key_t& m)
{
    serializer_class<npl_stage2_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_em_table_key_t& m)
{
    serializer_class<npl_stage2_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_em_table_key_t&);



template<>
class serializer_class<npl_stage2_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_em_table_value_t& m)
{
    serializer_class<npl_stage2_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_em_table_value_t& m)
{
    serializer_class<npl_stage2_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_em_table_value_t&);



template<>
class serializer_class<npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t& m)
{
    serializer_class<npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t& m)
{
    serializer_class<npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_em_table_value_t::npl_stage2_em_table_payloads_t&);



template<>
class serializer_class<npl_stage2_group_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_group_size_table_key_t& m) {
        uint64_t m_group_id = m.group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_group_size_table_key_t& m) {
        uint64_t m_group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
        m.group_id = m_group_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_group_size_table_key_t& m)
{
    serializer_class<npl_stage2_group_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_group_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_group_size_table_key_t& m)
{
    serializer_class<npl_stage2_group_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_group_size_table_key_t&);



template<>
class serializer_class<npl_stage2_group_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_group_size_table_value_t& m)
{
    serializer_class<npl_stage2_group_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_group_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_group_size_table_value_t& m)
{
    serializer_class<npl_stage2_group_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_group_size_table_value_t&);



template<>
class serializer_class<npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_group_size_table_value_t::npl_stage2_group_size_table_payloads_t&);



template<>
class serializer_class<npl_stage2_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_protection_table_key_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_protection_table_key_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_protection_table_key_t& m)
{
    serializer_class<npl_stage2_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_protection_table_key_t& m)
{
    serializer_class<npl_stage2_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_protection_table_key_t&);



template<>
class serializer_class<npl_stage2_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_protection_table_value_t& m)
{
    serializer_class<npl_stage2_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_protection_table_value_t& m)
{
    serializer_class<npl_stage2_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_protection_table_value_t&);



template<>
class serializer_class<npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t& m)
{
    serializer_class<npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t& m)
{
    serializer_class<npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_protection_table_value_t::npl_stage2_protection_table_payloads_t&);



template<>
class serializer_class<npl_stage2_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_type_decoding_table_key_t& m) {
        uint64_t m_type = m.type;
            archive(::cereal::make_nvp("type", m_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_type_decoding_table_key_t& m) {
        uint64_t m_type;
            archive(::cereal::make_nvp("type", m_type));
        m.type = m_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage2_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage2_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_type_decoding_table_key_t&);



template<>
class serializer_class<npl_stage2_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage2_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage2_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_type_decoding_table_value_t&);



template<>
class serializer_class<npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_type_decoding_table_value_t::npl_stage2_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_stage3_assoc_data_table_line_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_assoc_data_table_line_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_line_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_assoc_data_table_line_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_assoc_data_table_line_payload_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_line_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_assoc_data_table_line_payload_t&);



template<>
class serializer_class<npl_stage3_assoc_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_assoc_data_table_key_t& m) {
        uint64_t m_addr = m.addr;
            archive(::cereal::make_nvp("addr", m_addr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_assoc_data_table_key_t& m) {
        uint64_t m_addr;
            archive(::cereal::make_nvp("addr", m_addr));
        m.addr = m_addr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_assoc_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_assoc_data_table_key_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_assoc_data_table_key_t&);



template<>
class serializer_class<npl_stage3_assoc_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_assoc_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_assoc_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_assoc_data_table_value_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_assoc_data_table_value_t&);



template<>
class serializer_class<npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("line", m.line));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t& m)
{
    serializer_class<npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_assoc_data_table_value_t::npl_stage3_assoc_data_table_payloads_t&);



template<>
class serializer_class<npl_stage3_em_table_entry_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_em_table_entry_payload_t& m) {
        uint64_t m_addr = m.addr;
        uint64_t m_entry_select = m.entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_em_table_entry_payload_t& m) {
        uint64_t m_addr;
        uint64_t m_entry_select;
            archive(::cereal::make_nvp("addr", m_addr));
            archive(::cereal::make_nvp("entry_select", m_entry_select));
            archive(::cereal::make_nvp("common_data", m.common_data));
        m.addr = m_addr;
        m.entry_select = m_entry_select;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage3_em_table_entry_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_em_table_entry_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_em_table_entry_payload_t& m)
{
    serializer_class<npl_stage3_em_table_entry_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_em_table_entry_payload_t&);



template<>
class serializer_class<npl_stage3_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_em_table_key_t& m) {
            archive(::cereal::make_nvp("key", m.key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_em_table_key_t& m)
{
    serializer_class<npl_stage3_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_em_table_key_t& m)
{
    serializer_class<npl_stage3_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_em_table_key_t&);



template<>
class serializer_class<npl_stage3_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_em_table_value_t& m)
{
    serializer_class<npl_stage3_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_em_table_value_t& m)
{
    serializer_class<npl_stage3_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_em_table_value_t&);



template<>
class serializer_class<npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t& m)
{
    serializer_class<npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t& m)
{
    serializer_class<npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_em_table_value_t::npl_stage3_em_table_payloads_t&);



template<>
class serializer_class<npl_stage3_group_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_group_size_table_key_t& m) {
        uint64_t m_group_id = m.group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_group_size_table_key_t& m) {
        uint64_t m_group_id;
            archive(::cereal::make_nvp("group_id", m_group_id));
        m.group_id = m_group_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_group_size_table_key_t& m)
{
    serializer_class<npl_stage3_group_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_group_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_group_size_table_key_t& m)
{
    serializer_class<npl_stage3_group_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_group_size_table_key_t&);



template<>
class serializer_class<npl_stage3_group_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_group_size_table_value_t& m)
{
    serializer_class<npl_stage3_group_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_group_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_group_size_table_value_t& m)
{
    serializer_class<npl_stage3_group_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_group_size_table_value_t&);



template<>
class serializer_class<npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_lb_size_table_result", m.resolution_lb_size_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_group_size_table_value_t::npl_stage3_group_size_table_payloads_t&);



template<>
class serializer_class<npl_stage3_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_protection_table_key_t& m) {
        uint64_t m_id = m.id;
            archive(::cereal::make_nvp("id", m_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_protection_table_key_t& m) {
        uint64_t m_id;
            archive(::cereal::make_nvp("id", m_id));
        m.id = m_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_protection_table_key_t& m)
{
    serializer_class<npl_stage3_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_protection_table_key_t& m)
{
    serializer_class<npl_stage3_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_protection_table_key_t&);



template<>
class serializer_class<npl_stage3_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_protection_table_value_t& m)
{
    serializer_class<npl_stage3_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_protection_table_value_t& m)
{
    serializer_class<npl_stage3_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_protection_table_value_t&);



template<>
class serializer_class<npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_protection_result", m.resolution_protection_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t& m)
{
    serializer_class<npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t& m)
{
    serializer_class<npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_protection_table_value_t::npl_stage3_protection_table_payloads_t&);



template<>
class serializer_class<npl_stage3_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage3_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage3_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_type_decoding_table_key_t&);



template<>
class serializer_class<npl_stage3_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage3_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage3_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_type_decoding_table_value_t&);



template<>
class serializer_class<npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("resolution_type_decoding_table_result", m.resolution_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_type_decoding_table_value_t::npl_stage3_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_svl_dspa_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_dspa_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_dspa_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_dspa_table_key_t& m)
{
    serializer_class<npl_svl_dspa_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_dspa_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_dspa_table_key_t& m)
{
    serializer_class<npl_svl_dspa_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_dspa_table_key_t&);



template<>
class serializer_class<npl_svl_dspa_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_dspa_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_dspa_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_dspa_table_value_t& m)
{
    serializer_class<npl_svl_dspa_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_dspa_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_dspa_table_value_t& m)
{
    serializer_class<npl_svl_dspa_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_dspa_table_value_t&);



template<>
class serializer_class<npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_dspa", m.svl_dspa));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_dspa", m.svl_dspa));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t& m)
{
    serializer_class<npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t& m)
{
    serializer_class<npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_dspa_table_value_t::npl_svl_dspa_table_payloads_t&);



template<>
class serializer_class<npl_svl_is_dsp_remote_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_is_dsp_remote_key_t& m) {
        uint64_t m_destmsb = m.destmsb;
            archive(::cereal::make_nvp("destmsb", m_destmsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_is_dsp_remote_key_t& m) {
        uint64_t m_destmsb;
            archive(::cereal::make_nvp("destmsb", m_destmsb));
        m.destmsb = m_destmsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_is_dsp_remote_key_t& m)
{
    serializer_class<npl_svl_is_dsp_remote_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_is_dsp_remote_key_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_is_dsp_remote_key_t& m)
{
    serializer_class<npl_svl_is_dsp_remote_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_is_dsp_remote_key_t&);



template<>
class serializer_class<npl_svl_is_dsp_remote_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_is_dsp_remote_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_is_dsp_remote_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_is_dsp_remote_value_t& m)
{
    serializer_class<npl_svl_is_dsp_remote_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_is_dsp_remote_value_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_is_dsp_remote_value_t& m)
{
    serializer_class<npl_svl_is_dsp_remote_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_is_dsp_remote_value_t&);



template<>
class serializer_class<npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t& m) {
            archive(::cereal::make_nvp("svl_local_resolve_data", m.svl_local_resolve_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t& m) {
            archive(::cereal::make_nvp("svl_local_resolve_data", m.svl_local_resolve_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t& m)
{
    serializer_class<npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t& m)
{
    serializer_class<npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_is_dsp_remote_value_t::npl_svl_is_dsp_remote_payloads_t&);



template<>
class serializer_class<npl_svl_mirror_cmd_remote_dsp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_mirror_cmd_remote_dsp_table_key_t& m) {
        uint64_t m_ibm_cmd = m.ibm_cmd;
            archive(::cereal::make_nvp("ibm_cmd", m_ibm_cmd));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_mirror_cmd_remote_dsp_table_key_t& m) {
        uint64_t m_ibm_cmd;
            archive(::cereal::make_nvp("ibm_cmd", m_ibm_cmd));
        m.ibm_cmd = m_ibm_cmd;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_mirror_cmd_remote_dsp_table_key_t& m)
{
    serializer_class<npl_svl_mirror_cmd_remote_dsp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_mirror_cmd_remote_dsp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_mirror_cmd_remote_dsp_table_key_t& m)
{
    serializer_class<npl_svl_mirror_cmd_remote_dsp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_mirror_cmd_remote_dsp_table_key_t&);



template<>
class serializer_class<npl_svl_mirror_cmd_remote_dsp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_mirror_cmd_remote_dsp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_mirror_cmd_remote_dsp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_mirror_cmd_remote_dsp_table_value_t& m)
{
    serializer_class<npl_svl_mirror_cmd_remote_dsp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_mirror_cmd_remote_dsp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_mirror_cmd_remote_dsp_table_value_t& m)
{
    serializer_class<npl_svl_mirror_cmd_remote_dsp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_mirror_cmd_remote_dsp_table_value_t&);



template<>
class serializer_class<npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_mirror_dsp", m.svl_mirror_dsp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_mirror_dsp", m.svl_mirror_dsp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t& m)
{
    serializer_class<npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t& m)
{
    serializer_class<npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_mirror_cmd_remote_dsp_table_value_t::npl_svl_mirror_cmd_remote_dsp_table_payloads_t&);



template<>
class serializer_class<npl_svl_mode_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_mode_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_mode_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_mode_table_key_t& m)
{
    serializer_class<npl_svl_mode_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_mode_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_mode_table_key_t& m)
{
    serializer_class<npl_svl_mode_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_mode_table_key_t&);



template<>
class serializer_class<npl_svl_mode_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_mode_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_mode_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_mode_table_value_t& m)
{
    serializer_class<npl_svl_mode_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_mode_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_mode_table_value_t& m)
{
    serializer_class<npl_svl_mode_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_mode_table_value_t&);



template<>
class serializer_class<npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_mode", m.svl_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_mode", m.svl_mode));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t& m)
{
    serializer_class<npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t& m)
{
    serializer_class<npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_mode_table_value_t::npl_svl_mode_table_payloads_t&);



template<>
class serializer_class<npl_svl_next_macro_static_table_svl_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_next_macro_static_table_svl_next_macro_action_payload_t& m) {
        uint64_t m_ipc_trap = m.ipc_trap;
        uint64_t m_protocol_trap = m.protocol_trap;
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("ipc_trap", m_ipc_trap));
            archive(::cereal::make_nvp("protocol_trap", m_protocol_trap));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_next_macro_static_table_svl_next_macro_action_payload_t& m) {
        uint64_t m_ipc_trap;
        uint64_t m_protocol_trap;
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("ipc_trap", m_ipc_trap));
            archive(::cereal::make_nvp("protocol_trap", m_protocol_trap));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.ipc_trap = m_ipc_trap;
        m.protocol_trap = m_protocol_trap;
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_next_macro_static_table_svl_next_macro_action_payload_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_svl_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_next_macro_static_table_svl_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_next_macro_static_table_svl_next_macro_action_payload_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_svl_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_next_macro_static_table_svl_next_macro_action_payload_t&);



template<>
class serializer_class<npl_svl_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_next_macro_static_table_key_t& m) {
        uint64_t m_mac_da_prefix = m.mac_da_prefix;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("mac_da_prefix", m_mac_da_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_next_macro_static_table_key_t& m) {
        uint64_t m_mac_da_prefix;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("mac_da_prefix", m_mac_da_prefix));
        m.mac_da_prefix = m_mac_da_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_next_macro_static_table_key_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_next_macro_static_table_key_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_svl_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_next_macro_static_table_value_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_next_macro_static_table_value_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_next_macro_action", m.svl_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_next_macro_action", m.svl_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_next_macro_static_table_value_t::npl_svl_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t& m) {
        uint64_t m_sgt_macro_enabled = m.sgt_macro_enabled;
            archive(::cereal::make_nvp("sgt_macro_enabled", m_sgt_macro_enabled));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t& m) {
        uint64_t m_sgt_macro_enabled;
            archive(::cereal::make_nvp("sgt_macro_enabled", m_sgt_macro_enabled));
        m.sgt_macro_enabled = m_sgt_macro_enabled;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_enable_static_table_svl_sgacl_enable_static_table_action_payload_t&);



template<>
class serializer_class<npl_svl_sgacl_enable_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_enable_static_table_key_t& m) {
        uint64_t m_sda_fabric_enable = m.sda_fabric_enable;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("sda_fabric_enable", m_sda_fabric_enable));
            archive(::cereal::make_nvp("next_header", m.next_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_enable_static_table_key_t& m) {
        uint64_t m_sda_fabric_enable;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("sda_fabric_enable", m_sda_fabric_enable));
            archive(::cereal::make_nvp("next_header", m.next_header));
        m.sda_fabric_enable = m_sda_fabric_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_sgacl_enable_static_table_key_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_enable_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_enable_static_table_key_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_enable_static_table_key_t&);



template<>
class serializer_class<npl_svl_sgacl_enable_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_enable_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_enable_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_sgacl_enable_static_table_value_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_enable_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_enable_static_table_value_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_enable_static_table_value_t&);



template<>
class serializer_class<npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_sgacl_enable_static_table_action", m.svl_sgacl_enable_static_table_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_sgacl_enable_static_table_action", m.svl_sgacl_enable_static_table_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t& m)
{
    serializer_class<npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_enable_static_table_value_t::npl_svl_sgacl_enable_static_table_payloads_t&);



template<>
class serializer_class<npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t& m) {
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
save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_next_macro_static_table_svl_sgacl_next_macro_static_table_action_payload_t&);



template<>
class serializer_class<npl_svl_sgacl_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_key_t& m) {
        uint64_t m_sda_fabric_enable = m.sda_fabric_enable;
        uint64_t m_svl_dest = m.svl_dest;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("sda_fabric_enable", m_sda_fabric_enable));
            archive(::cereal::make_nvp("next_header", m.next_header));
            archive(::cereal::make_nvp("svl_dest", m_svl_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_next_macro_static_table_key_t& m) {
        uint64_t m_sda_fabric_enable;
        uint64_t m_svl_dest;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("sda_fabric_enable", m_sda_fabric_enable));
            archive(::cereal::make_nvp("next_header", m.next_header));
            archive(::cereal::make_nvp("svl_dest", m_svl_dest));
        m.sda_fabric_enable = m_sda_fabric_enable;
        m.svl_dest = m_svl_dest;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_key_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_next_macro_static_table_key_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_svl_sgacl_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_value_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_next_macro_static_table_value_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_sgacl_next_macro_static_table_action", m.svl_sgacl_next_macro_static_table_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("svl_sgacl_next_macro_static_table_action", m.svl_sgacl_next_macro_static_table_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_svl_sgacl_next_macro_static_table_value_t::npl_svl_sgacl_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_te_headend_lsp_counter_offset_table_offsets_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_offsets_payload_t& m) {
            archive(::cereal::make_nvp("lsp_counter_offset", m.lsp_counter_offset));
            archive(::cereal::make_nvp("php_counter_offset", m.php_counter_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_te_headend_lsp_counter_offset_table_offsets_payload_t& m) {
            archive(::cereal::make_nvp("lsp_counter_offset", m.lsp_counter_offset));
            archive(::cereal::make_nvp("php_counter_offset", m.php_counter_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_offsets_payload_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_offsets_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_te_headend_lsp_counter_offset_table_offsets_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_te_headend_lsp_counter_offset_table_offsets_payload_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_offsets_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_te_headend_lsp_counter_offset_table_offsets_payload_t&);



template<>
class serializer_class<npl_te_headend_lsp_counter_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_key_t& m) {
        uint64_t m_is_mc = m.is_mc;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_te_headend_lsp_counter_offset_table_key_t& m) {
        uint64_t m_is_mc;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
        m.is_mc = m_is_mc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_key_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_te_headend_lsp_counter_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_te_headend_lsp_counter_offset_table_key_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_te_headend_lsp_counter_offset_table_key_t&);



template<>
class serializer_class<npl_te_headend_lsp_counter_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_te_headend_lsp_counter_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_value_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_te_headend_lsp_counter_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_te_headend_lsp_counter_offset_table_value_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_te_headend_lsp_counter_offset_table_value_t&);



template<>
class serializer_class<npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("offsets", m.offsets));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("offsets", m.offsets));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t& m)
{
    serializer_class<npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_te_headend_lsp_counter_offset_table_value_t::npl_te_headend_lsp_counter_offset_table_payloads_t&);



template<>
class serializer_class<npl_term_bucket_a_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_a_lu_data_selector_key_t& m) {
        uint64_t m_lu_a_key_index = m.lu_a_key_index;
            archive(::cereal::make_nvp("lu_a_dest", m.lu_a_dest));
            archive(::cereal::make_nvp("lu_a_key_index", m_lu_a_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_a_lu_data_selector_key_t& m) {
        uint64_t m_lu_a_key_index;
            archive(::cereal::make_nvp("lu_a_dest", m.lu_a_dest));
            archive(::cereal::make_nvp("lu_a_key_index", m_lu_a_key_index));
        m.lu_a_key_index = m_lu_a_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_a_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_a_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_a_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_a_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_a_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_a_lu_data_selector_key_t&);



template<>
class serializer_class<npl_term_bucket_a_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_a_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_a_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_a_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_a_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_a_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_a_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_a_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_a_lu_data_selector_value_t&);



template<>
class serializer_class<npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_a_lu_data", m.term_bucket_a_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_a_lu_data", m.term_bucket_a_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_a_lu_data_selector_value_t::npl_term_bucket_a_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_term_bucket_b_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_b_lu_data_selector_key_t& m) {
        uint64_t m_lu_b_key_index = m.lu_b_key_index;
            archive(::cereal::make_nvp("lu_b_dest", m.lu_b_dest));
            archive(::cereal::make_nvp("lu_b_key_index", m_lu_b_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_b_lu_data_selector_key_t& m) {
        uint64_t m_lu_b_key_index;
            archive(::cereal::make_nvp("lu_b_dest", m.lu_b_dest));
            archive(::cereal::make_nvp("lu_b_key_index", m_lu_b_key_index));
        m.lu_b_key_index = m_lu_b_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_b_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_b_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_b_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_b_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_b_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_b_lu_data_selector_key_t&);



template<>
class serializer_class<npl_term_bucket_b_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_b_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_b_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_b_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_b_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_b_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_b_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_b_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_b_lu_data_selector_value_t&);



template<>
class serializer_class<npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_b_lu_data", m.term_bucket_b_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_b_lu_data", m.term_bucket_b_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_b_lu_data_selector_value_t::npl_term_bucket_b_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_term_bucket_c_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_c_lu_data_selector_key_t& m) {
        uint64_t m_lu_c_key_index = m.lu_c_key_index;
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_c_key_index", m_lu_c_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_c_lu_data_selector_key_t& m) {
        uint64_t m_lu_c_key_index;
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_c_key_index", m_lu_c_key_index));
        m.lu_c_key_index = m_lu_c_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_c_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_c_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_c_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_c_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_c_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_c_lu_data_selector_key_t&);



template<>
class serializer_class<npl_term_bucket_c_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_c_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_c_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_c_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_c_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_c_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_c_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_c_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_c_lu_data_selector_value_t&);



template<>
class serializer_class<npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_c_lu_data", m.term_bucket_c_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_c_lu_data", m.term_bucket_c_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_c_lu_data_selector_value_t::npl_term_bucket_c_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_term_bucket_d_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_d_lu_data_selector_key_t& m) {
        uint64_t m_lu_d_key_index = m.lu_d_key_index;
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
            archive(::cereal::make_nvp("lu_d_key_index", m_lu_d_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_d_lu_data_selector_key_t& m) {
        uint64_t m_lu_d_key_index;
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
            archive(::cereal::make_nvp("lu_d_key_index", m_lu_d_key_index));
        m.lu_d_key_index = m_lu_d_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_d_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_d_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_d_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_d_lu_data_selector_key_t& m)
{
    serializer_class<npl_term_bucket_d_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_d_lu_data_selector_key_t&);



template<>
class serializer_class<npl_term_bucket_d_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_d_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_d_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_d_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_d_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_d_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_d_lu_data_selector_value_t& m)
{
    serializer_class<npl_term_bucket_d_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_d_lu_data_selector_value_t&);



template<>
class serializer_class<npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_d_lu_data", m.term_bucket_d_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("term_bucket_d_lu_data", m.term_bucket_d_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_bucket_d_lu_data_selector_value_t::npl_term_bucket_d_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_term_to_fwd_hdr_shift_table_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_update_payload_t& m) {
        uint64_t m_highest_header_to_update = m.highest_header_to_update;
        uint64_t m_header_shift_disable_offset_recalc = m.header_shift_disable_offset_recalc;
        uint64_t m_enable_header_shift = m.enable_header_shift;
            archive(::cereal::make_nvp("highest_header_to_update", m_highest_header_to_update));
            archive(::cereal::make_nvp("header_shift_disable_offset_recalc", m_header_shift_disable_offset_recalc));
            archive(::cereal::make_nvp("enable_header_shift", m_enable_header_shift));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_to_fwd_hdr_shift_table_update_payload_t& m) {
        uint64_t m_highest_header_to_update;
        uint64_t m_header_shift_disable_offset_recalc;
        uint64_t m_enable_header_shift;
            archive(::cereal::make_nvp("highest_header_to_update", m_highest_header_to_update));
            archive(::cereal::make_nvp("header_shift_disable_offset_recalc", m_header_shift_disable_offset_recalc));
            archive(::cereal::make_nvp("enable_header_shift", m_enable_header_shift));
        m.highest_header_to_update = m_highest_header_to_update;
        m.header_shift_disable_offset_recalc = m_header_shift_disable_offset_recalc;
        m.enable_header_shift = m_enable_header_shift;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_update_payload_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_to_fwd_hdr_shift_table_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_term_to_fwd_hdr_shift_table_update_payload_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_to_fwd_hdr_shift_table_update_payload_t&);



template<>
class serializer_class<npl_term_to_fwd_hdr_shift_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_to_fwd_hdr_shift_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_key_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_to_fwd_hdr_shift_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_term_to_fwd_hdr_shift_table_key_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_to_fwd_hdr_shift_table_key_t&);



template<>
class serializer_class<npl_term_to_fwd_hdr_shift_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_to_fwd_hdr_shift_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_value_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_to_fwd_hdr_shift_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_term_to_fwd_hdr_shift_table_value_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_to_fwd_hdr_shift_table_value_t&);



template<>
class serializer_class<npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t& m)
{
    serializer_class<npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_term_to_fwd_hdr_shift_table_value_t::npl_term_to_fwd_hdr_shift_table_payloads_t&);



template<>
class serializer_class<npl_termination_to_forwarding_fi_hardwired_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_termination_to_forwarding_fi_hardwired_table_key_t& m) {
            archive(::cereal::make_nvp("packet_protocol_layer_current__header_0__header_info_type", m.packet_protocol_layer_current__header_0__header_info_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_termination_to_forwarding_fi_hardwired_table_key_t& m) {
            archive(::cereal::make_nvp("packet_protocol_layer_current__header_0__header_info_type", m.packet_protocol_layer_current__header_0__header_info_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_termination_to_forwarding_fi_hardwired_table_key_t& m)
{
    serializer_class<npl_termination_to_forwarding_fi_hardwired_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_termination_to_forwarding_fi_hardwired_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_termination_to_forwarding_fi_hardwired_table_key_t& m)
{
    serializer_class<npl_termination_to_forwarding_fi_hardwired_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_termination_to_forwarding_fi_hardwired_table_key_t&);



template<>
class serializer_class<npl_termination_to_forwarding_fi_hardwired_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_termination_to_forwarding_fi_hardwired_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_termination_to_forwarding_fi_hardwired_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_termination_to_forwarding_fi_hardwired_table_value_t& m)
{
    serializer_class<npl_termination_to_forwarding_fi_hardwired_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_termination_to_forwarding_fi_hardwired_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_termination_to_forwarding_fi_hardwired_table_value_t& m)
{
    serializer_class<npl_termination_to_forwarding_fi_hardwired_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_termination_to_forwarding_fi_hardwired_table_value_t&);



template<>
class serializer_class<npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_to_forwarding_fields_fi_hardwired_type", m.termination_to_forwarding_fields_fi_hardwired_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t& m) {
            archive(::cereal::make_nvp("termination_to_forwarding_fields_fi_hardwired_type", m.termination_to_forwarding_fields_fi_hardwired_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t& m)
{
    serializer_class<npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t& m)
{
    serializer_class<npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_termination_to_forwarding_fi_hardwired_table_value_t::npl_termination_to_forwarding_fi_hardwired_table_payloads_t&);



template<>
class serializer_class<npl_tm_ibm_cmd_to_destination_found_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tm_ibm_cmd_to_destination_found_payload_t& m) {
        uint64_t m_dest_slice_id = m.dest_slice_id;
        uint64_t m_dest_pif = m.dest_pif;
        uint64_t m_dest_ifg = m.dest_ifg;
            archive(::cereal::make_nvp("dest_slice_id", m_dest_slice_id));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
            archive(::cereal::make_nvp("dest_ifg", m_dest_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tm_ibm_cmd_to_destination_found_payload_t& m) {
        uint64_t m_dest_slice_id;
        uint64_t m_dest_pif;
        uint64_t m_dest_ifg;
            archive(::cereal::make_nvp("dest_slice_id", m_dest_slice_id));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
            archive(::cereal::make_nvp("dest_ifg", m_dest_ifg));
        m.dest_slice_id = m_dest_slice_id;
        m.dest_pif = m_dest_pif;
        m.dest_ifg = m_dest_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tm_ibm_cmd_to_destination_found_payload_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_found_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tm_ibm_cmd_to_destination_found_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_tm_ibm_cmd_to_destination_found_payload_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_found_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tm_ibm_cmd_to_destination_found_payload_t&);



template<>
class serializer_class<npl_tm_ibm_cmd_to_destination_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tm_ibm_cmd_to_destination_key_t& m) {
        uint64_t m_rxpp_to_txpp_local_vars_mirror_command = m.rxpp_to_txpp_local_vars_mirror_command;
            archive(::cereal::make_nvp("rxpp_to_txpp_local_vars_mirror_command", m_rxpp_to_txpp_local_vars_mirror_command));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tm_ibm_cmd_to_destination_key_t& m) {
        uint64_t m_rxpp_to_txpp_local_vars_mirror_command;
            archive(::cereal::make_nvp("rxpp_to_txpp_local_vars_mirror_command", m_rxpp_to_txpp_local_vars_mirror_command));
        m.rxpp_to_txpp_local_vars_mirror_command = m_rxpp_to_txpp_local_vars_mirror_command;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tm_ibm_cmd_to_destination_key_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tm_ibm_cmd_to_destination_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tm_ibm_cmd_to_destination_key_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tm_ibm_cmd_to_destination_key_t&);



template<>
class serializer_class<npl_tm_ibm_cmd_to_destination_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tm_ibm_cmd_to_destination_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tm_ibm_cmd_to_destination_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tm_ibm_cmd_to_destination_value_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tm_ibm_cmd_to_destination_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tm_ibm_cmd_to_destination_value_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tm_ibm_cmd_to_destination_value_t&);



template<>
class serializer_class<npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t& m)
{
    serializer_class<npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tm_ibm_cmd_to_destination_value_t::npl_tm_ibm_cmd_to_destination_payloads_t&);



template<>
class serializer_class<npl_transmit_bucket_a_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_a_lu_data_selector_key_t& m) {
        uint64_t m_lu_a_key_index = m.lu_a_key_index;
            archive(::cereal::make_nvp("lu_a_dest", m.lu_a_dest));
            archive(::cereal::make_nvp("lu_a_key_index", m_lu_a_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_a_lu_data_selector_key_t& m) {
        uint64_t m_lu_a_key_index;
            archive(::cereal::make_nvp("lu_a_dest", m.lu_a_dest));
            archive(::cereal::make_nvp("lu_a_key_index", m_lu_a_key_index));
        m.lu_a_key_index = m_lu_a_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_a_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_a_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_a_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_a_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_a_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_a_lu_data_selector_key_t&);



template<>
class serializer_class<npl_transmit_bucket_a_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_a_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_a_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_a_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_a_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_a_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_a_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_a_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_a_lu_data_selector_value_t&);



template<>
class serializer_class<npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_a_lu_data", m.trans_bucket_a_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_a_lu_data", m.trans_bucket_a_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_a_lu_data_selector_value_t::npl_transmit_bucket_a_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_transmit_bucket_b_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_b_lu_data_selector_key_t& m) {
        uint64_t m_lu_b_dest = m.lu_b_dest;
        uint64_t m_lu_b_key_index = m.lu_b_key_index;
            archive(::cereal::make_nvp("lu_b_dest", m_lu_b_dest));
            archive(::cereal::make_nvp("lu_b_key_index", m_lu_b_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_b_lu_data_selector_key_t& m) {
        uint64_t m_lu_b_dest;
        uint64_t m_lu_b_key_index;
            archive(::cereal::make_nvp("lu_b_dest", m_lu_b_dest));
            archive(::cereal::make_nvp("lu_b_key_index", m_lu_b_key_index));
        m.lu_b_dest = m_lu_b_dest;
        m.lu_b_key_index = m_lu_b_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_b_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_b_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_b_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_b_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_b_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_b_lu_data_selector_key_t&);



template<>
class serializer_class<npl_transmit_bucket_b_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_b_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_b_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_b_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_b_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_b_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_b_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_b_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_b_lu_data_selector_value_t&);



template<>
class serializer_class<npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_b_lu_data", m.trans_bucket_b_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_b_lu_data", m.trans_bucket_b_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_b_lu_data_selector_value_t::npl_transmit_bucket_b_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_transmit_bucket_c_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_c_lu_data_selector_key_t& m) {
        uint64_t m_lu_c_key_index = m.lu_c_key_index;
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_c_key_index", m_lu_c_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_c_lu_data_selector_key_t& m) {
        uint64_t m_lu_c_key_index;
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_c_key_index", m_lu_c_key_index));
        m.lu_c_key_index = m_lu_c_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_c_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_c_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_c_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_c_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_c_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_c_lu_data_selector_key_t&);



template<>
class serializer_class<npl_transmit_bucket_c_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_c_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_c_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_c_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_c_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_c_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_c_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_c_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_c_lu_data_selector_value_t&);



}

