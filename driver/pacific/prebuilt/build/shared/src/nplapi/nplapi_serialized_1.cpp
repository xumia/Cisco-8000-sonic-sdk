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

unsigned g_nplapi_serialization_version = 1;
void cereal_gen_set_serialization_version_nplapi(unsigned int version) {g_nplapi_serialization_version = version;}

template <class Archive> void save(Archive&, const npl_additional_labels_t&);
template <class Archive> void load(Archive&, npl_additional_labels_t&);

template <class Archive> void save(Archive&, const npl_all_reachable_vector_result_t&);
template <class Archive> void load(Archive&, npl_all_reachable_vector_result_t&);

template <class Archive> void save(Archive&, const npl_bfd_em_lookup_t&);
template <class Archive> void load(Archive&, npl_bfd_em_lookup_t&);

template <class Archive> void save(Archive&, const npl_bfd_inject_ttl_t&);
template <class Archive> void load(Archive&, npl_bfd_inject_ttl_t&);

template <class Archive> void save(Archive&, const npl_bfd_ipv6_selector_t&);
template <class Archive> void load(Archive&, npl_bfd_ipv6_selector_t&);

template <class Archive> void save(Archive&, const npl_bfd_local_ipv6_sip_t&);
template <class Archive> void load(Archive&, npl_bfd_local_ipv6_sip_t&);

template <class Archive> void save(Archive&, const npl_bfd_transport_and_label_t&);
template <class Archive> void load(Archive&, npl_bfd_transport_and_label_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_calc_checksum_enable_t&);
template <class Archive> void load(Archive&, npl_calc_checksum_enable_t&);

template <class Archive> void save(Archive&, const npl_common_cntr_offset_and_padding_t&);
template <class Archive> void load(Archive&, npl_common_cntr_offset_and_padding_t&);

template <class Archive> void save(Archive&, const npl_counters_block_config_t&);
template <class Archive> void load(Archive&, npl_counters_block_config_t&);

template <class Archive> void save(Archive&, const npl_counters_voq_block_map_result_t&);
template <class Archive> void load(Archive&, npl_counters_voq_block_map_result_t&);

template <class Archive> void save(Archive&, const npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t&);
template <class Archive> void load(Archive&, npl_cud_mapping_local_vars_t_anonymous_union_wide_mc_cud_t&);

template <class Archive> void save(Archive&, const npl_dest_slice_voq_map_table_result_t&);
template <class Archive> void load(Archive&, npl_dest_slice_voq_map_table_result_t&);

template <class Archive> void save(Archive&, const npl_destination_decoding_table_result_t&);
template <class Archive> void load(Archive&, npl_destination_decoding_table_result_t&);

template <class Archive> void save(Archive&, const npl_device_mode_table_result_t&);
template <class Archive> void load(Archive&, npl_device_mode_table_result_t&);

template <class Archive> void save(Archive&, const npl_dip_index_t&);
template <class Archive> void load(Archive&, npl_dip_index_t&);

template <class Archive> void save(Archive&, const npl_dsp_l2_attributes_t&);
template <class Archive> void load(Archive&, npl_dsp_l2_attributes_t&);

template <class Archive> void save(Archive&, const npl_dsp_l3_attributes_t&);
template <class Archive> void load(Archive&, npl_dsp_l3_attributes_t&);

template <class Archive> void save(Archive&, const npl_egress_direct0_key_t&);
template <class Archive> void load(Archive&, npl_egress_direct0_key_t&);

template <class Archive> void save(Archive&, const npl_egress_direct1_key_t&);
template <class Archive> void load(Archive&, npl_egress_direct1_key_t&);

template <class Archive> void save(Archive&, const npl_egress_sec_acl_result_t&);
template <class Archive> void load(Archive&, npl_egress_sec_acl_result_t&);

template <class Archive> void save(Archive&, const npl_em_payload_t&);
template <class Archive> void load(Archive&, npl_em_payload_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_ipv4_sip_dip_t&);
template <class Archive> void load(Archive&, npl_ipv4_sip_dip_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ttl_and_protocol_t&);
template <class Archive> void load(Archive&, npl_ipv4_ttl_and_protocol_t&);

template <class Archive> void save(Archive&, const npl_l4_ports_header_t&);
template <class Archive> void load(Archive&, npl_l4_ports_header_t&);

template <class Archive> void save(Archive&, const npl_lpts_tcam_first_result_encap_data_msb_t&);
template <class Archive> void load(Archive&, npl_lpts_tcam_first_result_encap_data_msb_t&);

template <class Archive> void save(Archive&, const npl_nh_and_svi_payload_t&);
template <class Archive> void load(Archive&, npl_nh_and_svi_payload_t&);

template <class Archive> void save(Archive&, const npl_protocol_type_padded_t&);
template <class Archive> void load(Archive&, npl_protocol_type_padded_t&);

template <class Archive> void save(Archive&, const npl_tos_t&);
template <class Archive> void load(Archive&, npl_tos_t&);

template<>
class serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t& m) {
        uint64_t m_is_valid = m.is_valid;
        uint64_t m_acl_l4_protocol = m.acl_l4_protocol;
            archive(::cereal::make_nvp("is_valid", m_is_valid));
            archive(::cereal::make_nvp("acl_l4_protocol", m_acl_l4_protocol));
            archive(::cereal::make_nvp("protocol_type", m.protocol_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t& m) {
        uint64_t m_is_valid;
        uint64_t m_acl_l4_protocol;
            archive(::cereal::make_nvp("is_valid", m_is_valid));
            archive(::cereal::make_nvp("acl_l4_protocol", m_acl_l4_protocol));
            archive(::cereal::make_nvp("protocol_type", m.protocol_type));
        m.is_valid = m_is_valid;
        m.acl_l4_protocol = m_acl_l4_protocol;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_acl_map_fi_header_type_to_protocol_number_table_update_payload_t&);



template<>
class serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_key_t& m) {
            archive(::cereal::make_nvp("fi_hdr_type", m.fi_hdr_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_key_t& m) {
            archive(::cereal::make_nvp("fi_hdr_type", m.fi_hdr_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_key_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_acl_map_fi_header_type_to_protocol_number_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_key_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_acl_map_fi_header_type_to_protocol_number_table_key_t&);



template<>
class serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_value_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_acl_map_fi_header_type_to_protocol_number_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_value_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_acl_map_fi_header_type_to_protocol_number_table_value_t&);



template<>
class serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t& m)
{
    serializer_class<npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_acl_map_fi_header_type_to_protocol_number_table_value_t::npl_acl_map_fi_header_type_to_protocol_number_table_payloads_t&);



template<>
class serializer_class<npl_additional_labels_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_additional_labels_table_key_t& m) {
        uint64_t m_labels_index = m.labels_index;
            archive(::cereal::make_nvp("labels_index", m_labels_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_additional_labels_table_key_t& m) {
        uint64_t m_labels_index;
            archive(::cereal::make_nvp("labels_index", m_labels_index));
        m.labels_index = m_labels_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_additional_labels_table_key_t& m)
{
    serializer_class<npl_additional_labels_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_additional_labels_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_additional_labels_table_key_t& m)
{
    serializer_class<npl_additional_labels_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_additional_labels_table_key_t&);



template<>
class serializer_class<npl_additional_labels_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_additional_labels_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_additional_labels_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_additional_labels_table_value_t& m)
{
    serializer_class<npl_additional_labels_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_additional_labels_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_additional_labels_table_value_t& m)
{
    serializer_class<npl_additional_labels_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_additional_labels_table_value_t&);



template<>
class serializer_class<npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t& m) {
            archive(::cereal::make_nvp("additional_labels", m.additional_labels));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t& m) {
            archive(::cereal::make_nvp("additional_labels", m.additional_labels));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t& m)
{
    serializer_class<npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t& m)
{
    serializer_class<npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_additional_labels_table_value_t::npl_additional_labels_table_payloads_t&);



template<>
class serializer_class<npl_all_reachable_vector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_all_reachable_vector_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_all_reachable_vector_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_all_reachable_vector_key_t& m)
{
    serializer_class<npl_all_reachable_vector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_all_reachable_vector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_all_reachable_vector_key_t& m)
{
    serializer_class<npl_all_reachable_vector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_all_reachable_vector_key_t&);



template<>
class serializer_class<npl_all_reachable_vector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_all_reachable_vector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_all_reachable_vector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_all_reachable_vector_value_t& m)
{
    serializer_class<npl_all_reachable_vector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_all_reachable_vector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_all_reachable_vector_value_t& m)
{
    serializer_class<npl_all_reachable_vector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_all_reachable_vector_value_t&);



template<>
class serializer_class<npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t& m) {
            archive(::cereal::make_nvp("all_reachable_vector_result", m.all_reachable_vector_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t& m) {
            archive(::cereal::make_nvp("all_reachable_vector_result", m.all_reachable_vector_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t& m)
{
    serializer_class<npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t& m)
{
    serializer_class<npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_all_reachable_vector_value_t::npl_all_reachable_vector_payloads_t&);



template<>
class serializer_class<npl_bfd_desired_tx_interval_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_desired_tx_interval_table_key_t& m) {
        uint64_t m_interval_selector = m.interval_selector;
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_desired_tx_interval_table_key_t& m) {
        uint64_t m_interval_selector;
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
        m.interval_selector = m_interval_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_desired_tx_interval_table_key_t& m)
{
    serializer_class<npl_bfd_desired_tx_interval_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_desired_tx_interval_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_desired_tx_interval_table_key_t& m)
{
    serializer_class<npl_bfd_desired_tx_interval_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_desired_tx_interval_table_key_t&);



template<>
class serializer_class<npl_bfd_desired_tx_interval_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_desired_tx_interval_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_desired_tx_interval_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_desired_tx_interval_table_value_t& m)
{
    serializer_class<npl_bfd_desired_tx_interval_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_desired_tx_interval_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_desired_tx_interval_table_value_t& m)
{
    serializer_class<npl_bfd_desired_tx_interval_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_desired_tx_interval_table_value_t&);



template<>
class serializer_class<npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t& m) {
        uint64_t m_desired_min_tx_interval = m.desired_min_tx_interval;
            archive(::cereal::make_nvp("desired_min_tx_interval", m_desired_min_tx_interval));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t& m) {
        uint64_t m_desired_min_tx_interval;
            archive(::cereal::make_nvp("desired_min_tx_interval", m_desired_min_tx_interval));
        m.desired_min_tx_interval = m_desired_min_tx_interval;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t& m)
{
    serializer_class<npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t& m)
{
    serializer_class<npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_desired_tx_interval_table_value_t::npl_bfd_desired_tx_interval_table_payloads_t&);



template<>
class serializer_class<npl_bfd_detection_multiple_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_detection_multiple_table_key_t& m) {
        uint64_t m_interval_selector = m.interval_selector;
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_detection_multiple_table_key_t& m) {
        uint64_t m_interval_selector;
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
        m.interval_selector = m_interval_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_detection_multiple_table_key_t& m)
{
    serializer_class<npl_bfd_detection_multiple_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_detection_multiple_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_detection_multiple_table_key_t& m)
{
    serializer_class<npl_bfd_detection_multiple_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_detection_multiple_table_key_t&);



template<>
class serializer_class<npl_bfd_detection_multiple_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_detection_multiple_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_detection_multiple_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_detection_multiple_table_value_t& m)
{
    serializer_class<npl_bfd_detection_multiple_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_detection_multiple_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_detection_multiple_table_value_t& m)
{
    serializer_class<npl_bfd_detection_multiple_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_detection_multiple_table_value_t&);



template<>
class serializer_class<npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t& m) {
        uint64_t m_detection_mult = m.detection_mult;
            archive(::cereal::make_nvp("detection_mult", m_detection_mult));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t& m) {
        uint64_t m_detection_mult;
            archive(::cereal::make_nvp("detection_mult", m_detection_mult));
        m.detection_mult = m_detection_mult;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t& m)
{
    serializer_class<npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t& m)
{
    serializer_class<npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_detection_multiple_table_value_t::npl_bfd_detection_multiple_table_payloads_t&);



template<>
class serializer_class<npl_bfd_event_queue_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_event_queue_table_key_t& m) {
        uint64_t m_rmep_id = m.rmep_id;
        uint64_t m_mep_id = m.mep_id;
        uint64_t m_diag_code = m.diag_code;
        uint64_t m_flags_and_state = m.flags_and_state;
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("mep_id", m_mep_id));
            archive(::cereal::make_nvp("oamp_event", m.oamp_event));
            archive(::cereal::make_nvp("diag_code", m_diag_code));
            archive(::cereal::make_nvp("flags_and_state", m_flags_and_state));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_event_queue_table_key_t& m) {
        uint64_t m_rmep_id;
        uint64_t m_mep_id;
        uint64_t m_diag_code;
        uint64_t m_flags_and_state;
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("mep_id", m_mep_id));
            archive(::cereal::make_nvp("oamp_event", m.oamp_event));
            archive(::cereal::make_nvp("diag_code", m_diag_code));
            archive(::cereal::make_nvp("flags_and_state", m_flags_and_state));
        m.rmep_id = m_rmep_id;
        m.mep_id = m_mep_id;
        m.diag_code = m_diag_code;
        m.flags_and_state = m_flags_and_state;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_event_queue_table_key_t& m)
{
    serializer_class<npl_bfd_event_queue_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_event_queue_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_event_queue_table_key_t& m)
{
    serializer_class<npl_bfd_event_queue_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_event_queue_table_key_t&);



template<>
class serializer_class<npl_bfd_event_queue_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_event_queue_table_value_t& m)
{
    serializer_class<npl_bfd_event_queue_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_event_queue_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_event_queue_table_value_t& m)
{
    serializer_class<npl_bfd_event_queue_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_event_queue_table_value_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t& m) {
        uint64_t m_da = m.da;
            archive(::cereal::make_nvp("da", m_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t& m) {
        uint64_t m_da;
            archive(::cereal::make_nvp("da", m_da));
        m.da = m_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_high_table_set_inject_inner_da_payload_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_high_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_high_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_high_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_high_table_key_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_high_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_high_table_key_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_high_table_key_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_high_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_high_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_high_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_high_table_value_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_high_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_high_table_value_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_high_table_value_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_inner_da", m.set_inject_inner_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_inner_da", m.set_inject_inner_da));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_high_table_value_t::npl_bfd_inject_inner_da_high_table_payloads_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t& m) {
        uint64_t m_da = m.da;
            archive(::cereal::make_nvp("da", m_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t& m) {
        uint64_t m_da;
            archive(::cereal::make_nvp("da", m_da));
        m.da = m_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_low_table_set_inject_inner_da_payload_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_low_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_low_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_low_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_low_table_key_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_low_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_low_table_key_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_low_table_key_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_low_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_low_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_low_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_low_table_value_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_low_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_low_table_value_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_low_table_value_t&);



template<>
class serializer_class<npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_inner_da", m.set_inject_inner_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inject_inner_da", m.set_inject_inner_da));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_da_low_table_value_t::npl_bfd_inject_inner_da_low_table_payloads_t&);



template<>
class serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t& m) {
        uint64_t m_type = m.type;
        uint64_t m_pkt_size = m.pkt_size;
        uint64_t m_size1 = m.size1;
        uint64_t m_size2 = m.size2;
        uint64_t m_size3 = m.size3;
        uint64_t m_bitmap = m.bitmap;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("pkt_size", m_pkt_size));
            archive(::cereal::make_nvp("size1", m_size1));
            archive(::cereal::make_nvp("size2", m_size2));
            archive(::cereal::make_nvp("size3", m_size3));
            archive(::cereal::make_nvp("bitmap", m_bitmap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t& m) {
        uint64_t m_type;
        uint64_t m_pkt_size;
        uint64_t m_size1;
        uint64_t m_size2;
        uint64_t m_size3;
        uint64_t m_bitmap;
            archive(::cereal::make_nvp("type", m_type));
            archive(::cereal::make_nvp("pkt_size", m_pkt_size));
            archive(::cereal::make_nvp("size1", m_size1));
            archive(::cereal::make_nvp("size2", m_size2));
            archive(::cereal::make_nvp("size3", m_size3));
            archive(::cereal::make_nvp("bitmap", m_bitmap));
        m.type = m_type;
        m.pkt_size = m_pkt_size;
        m.size1 = m_size1;
        m.size2 = m_size2;
        m.size3 = m_size3;
        m.bitmap = m_bitmap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_ethernet_header_static_table_set_inner_inject_eth_payload_t&);



template<>
class serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_key_t& m) {
        uint64_t m_requires_inject_up = m.requires_inject_up;
            archive(::cereal::make_nvp("requires_inject_up", m_requires_inject_up));
            archive(::cereal::make_nvp("transport", m.transport));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_key_t& m) {
        uint64_t m_requires_inject_up;
            archive(::cereal::make_nvp("requires_inject_up", m_requires_inject_up));
            archive(::cereal::make_nvp("transport", m.transport));
        m.requires_inject_up = m_requires_inject_up;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_key_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_ethernet_header_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_key_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_ethernet_header_static_table_key_t&);



template<>
class serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_value_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_ethernet_header_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_value_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_ethernet_header_static_table_value_t&);



template<>
class serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inner_inject_eth", m.set_inner_inject_eth));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_inner_inject_eth", m.set_inner_inject_eth));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_inner_ethernet_header_static_table_value_t::npl_bfd_inject_inner_ethernet_header_static_table_payloads_t&);



template<>
class serializer_class<npl_bfd_inject_ttl_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_ttl_static_table_key_t& m) {
        uint64_t m_requires_inject_up = m.requires_inject_up;
        uint64_t m_requires_label = m.requires_label;
            archive(::cereal::make_nvp("requires_inject_up", m_requires_inject_up));
            archive(::cereal::make_nvp("requires_label", m_requires_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_ttl_static_table_key_t& m) {
        uint64_t m_requires_inject_up;
        uint64_t m_requires_label;
            archive(::cereal::make_nvp("requires_inject_up", m_requires_inject_up));
            archive(::cereal::make_nvp("requires_label", m_requires_label));
        m.requires_inject_up = m_requires_inject_up;
        m.requires_label = m_requires_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_ttl_static_table_key_t& m)
{
    serializer_class<npl_bfd_inject_ttl_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_ttl_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_ttl_static_table_key_t& m)
{
    serializer_class<npl_bfd_inject_ttl_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_ttl_static_table_key_t&);



template<>
class serializer_class<npl_bfd_inject_ttl_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_ttl_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_ttl_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_ttl_static_table_value_t& m)
{
    serializer_class<npl_bfd_inject_ttl_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_ttl_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_ttl_static_table_value_t& m)
{
    serializer_class<npl_bfd_inject_ttl_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_ttl_static_table_value_t&);



template<>
class serializer_class<npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_inject_ttl", m.bfd_inject_ttl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_inject_ttl", m.bfd_inject_ttl));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_ttl_static_table_value_t::npl_bfd_inject_ttl_static_table_payloads_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_A_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_A_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_A_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_A_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_A_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_A_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_A_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_A_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_A_table_key_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_A_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_A_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_A_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_A_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_A_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_A_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_A_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_A_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_A_table_value_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_A_sip", m.bfd_local_ipv6_A_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_A_sip", m.bfd_local_ipv6_A_sip));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_A_table_value_t::npl_bfd_ipv6_sip_A_table_payloads_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_B_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_B_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_B_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_B_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_B_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_B_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_B_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_B_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_B_table_key_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_B_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_B_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_B_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_B_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_B_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_B_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_B_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_B_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_B_table_value_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_B_sip", m.bfd_local_ipv6_B_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_B_sip", m.bfd_local_ipv6_B_sip));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_B_table_value_t::npl_bfd_ipv6_sip_B_table_payloads_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_C_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_C_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_C_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_C_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_C_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_C_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_C_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_C_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_C_table_key_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_C_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_C_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_C_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_C_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_C_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_C_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_C_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_C_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_C_table_value_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_C_sip", m.bfd_local_ipv6_C_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_C_sip", m.bfd_local_ipv6_C_sip));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_C_table_value_t::npl_bfd_ipv6_sip_C_table_payloads_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_D_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_D_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_D_table_key_t& m) {
            archive(::cereal::make_nvp("bfd_ipv6_selector", m.bfd_ipv6_selector));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_D_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_D_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_D_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_D_table_key_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_D_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_D_table_key_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_D_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_D_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_D_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_D_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_D_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_D_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_D_table_value_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_D_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_D_table_value_t&);



template<>
class serializer_class<npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_D_sip", m.bfd_local_ipv6_D_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_local_ipv6_D_sip", m.bfd_local_ipv6_D_sip));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t& m)
{
    serializer_class<npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_sip_D_table_value_t::npl_bfd_ipv6_sip_D_table_payloads_t&);



template<>
class serializer_class<npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t& m) {
        uint64_t m_fwd_offset = m.fwd_offset;
            archive(::cereal::make_nvp("fwd_offset", m_fwd_offset));
            archive(::cereal::make_nvp("nmret", m.nmret));
            archive(::cereal::make_nvp("lpts_punt_encap", m.lpts_punt_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t& m) {
        uint64_t m_fwd_offset;
            archive(::cereal::make_nvp("fwd_offset", m_fwd_offset));
            archive(::cereal::make_nvp("nmret", m.nmret));
            archive(::cereal::make_nvp("lpts_punt_encap", m.lpts_punt_encap));
        m.fwd_offset = m_fwd_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_punt_encap_static_table_bfd_hdr_punt_encap_action_payload_t&);



template<>
class serializer_class<npl_bfd_punt_encap_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_punt_encap_static_table_key_t& m) {
        uint64_t m_encap_result = m.encap_result;
            archive(::cereal::make_nvp("encap_result", m_encap_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_punt_encap_static_table_key_t& m) {
        uint64_t m_encap_result;
            archive(::cereal::make_nvp("encap_result", m_encap_result));
        m.encap_result = m_encap_result;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_punt_encap_static_table_key_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_punt_encap_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_punt_encap_static_table_key_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_punt_encap_static_table_key_t&);



template<>
class serializer_class<npl_bfd_punt_encap_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_punt_encap_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_punt_encap_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_punt_encap_static_table_value_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_punt_encap_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_punt_encap_static_table_value_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_punt_encap_static_table_value_t&);



template<>
class serializer_class<npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_hdr_punt_encap_action", m.bfd_hdr_punt_encap_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_hdr_punt_encap_action", m.bfd_hdr_punt_encap_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_punt_encap_static_table_value_t::npl_bfd_punt_encap_static_table_payloads_t&);



template<>
class serializer_class<npl_bfd_required_tx_interval_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_required_tx_interval_table_key_t& m) {
        uint64_t m_interval_selector = m.interval_selector;
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_required_tx_interval_table_key_t& m) {
        uint64_t m_interval_selector;
            archive(::cereal::make_nvp("interval_selector", m_interval_selector));
        m.interval_selector = m_interval_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_required_tx_interval_table_key_t& m)
{
    serializer_class<npl_bfd_required_tx_interval_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_required_tx_interval_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_required_tx_interval_table_key_t& m)
{
    serializer_class<npl_bfd_required_tx_interval_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_required_tx_interval_table_key_t&);



template<>
class serializer_class<npl_bfd_required_tx_interval_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_required_tx_interval_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_required_tx_interval_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_required_tx_interval_table_value_t& m)
{
    serializer_class<npl_bfd_required_tx_interval_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_required_tx_interval_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_required_tx_interval_table_value_t& m)
{
    serializer_class<npl_bfd_required_tx_interval_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_required_tx_interval_table_value_t&);



template<>
class serializer_class<npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t& m) {
        uint64_t m_required_min_tx_interval = m.required_min_tx_interval;
            archive(::cereal::make_nvp("required_min_tx_interval", m_required_min_tx_interval));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t& m) {
        uint64_t m_required_min_tx_interval;
            archive(::cereal::make_nvp("required_min_tx_interval", m_required_min_tx_interval));
        m.required_min_tx_interval = m_required_min_tx_interval;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t& m)
{
    serializer_class<npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t& m)
{
    serializer_class<npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_required_tx_interval_table_value_t::npl_bfd_required_tx_interval_table_payloads_t&);



template<>
class serializer_class<npl_bfd_rx_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_rx_table_key_t& m) {
        uint64_t m_your_discr_31_16_ = m.your_discr_31_16_;
        uint64_t m_your_discr_23_16_ = m.your_discr_23_16_;
        uint64_t m_dst_port = m.dst_port;
            archive(::cereal::make_nvp("your_discr_31_16_", m_your_discr_31_16_));
            archive(::cereal::make_nvp("your_discr_23_16_", m_your_discr_23_16_));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("protocol_type", m.protocol_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_rx_table_key_t& m) {
        uint64_t m_your_discr_31_16_;
        uint64_t m_your_discr_23_16_;
        uint64_t m_dst_port;
            archive(::cereal::make_nvp("your_discr_31_16_", m_your_discr_31_16_));
            archive(::cereal::make_nvp("your_discr_23_16_", m_your_discr_23_16_));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("protocol_type", m.protocol_type));
        m.your_discr_31_16_ = m_your_discr_31_16_;
        m.your_discr_23_16_ = m_your_discr_23_16_;
        m.dst_port = m_dst_port;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_rx_table_key_t& m)
{
    serializer_class<npl_bfd_rx_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_rx_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_rx_table_key_t& m)
{
    serializer_class<npl_bfd_rx_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_rx_table_key_t&);



template<>
class serializer_class<npl_bfd_rx_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_rx_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_rx_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_rx_table_value_t& m)
{
    serializer_class<npl_bfd_rx_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_rx_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_rx_table_value_t& m)
{
    serializer_class<npl_bfd_rx_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_rx_table_value_t&);



template<>
class serializer_class<npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_em_lookup_result", m.bfd_em_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_em_lookup_result", m.bfd_em_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t& m)
{
    serializer_class<npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t& m)
{
    serializer_class<npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_rx_table_value_t::npl_bfd_rx_table_payloads_t&);



template<>
class serializer_class<npl_bfd_set_inject_type_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_set_inject_type_static_table_key_t& m) {
        uint64_t m_pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up = m.pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up;
            archive(::cereal::make_nvp("pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up", m_pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_set_inject_type_static_table_key_t& m) {
        uint64_t m_pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up;
            archive(::cereal::make_nvp("pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up", m_pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up));
        m.pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up = m_pd_pd_npu_host_inject_fields_aux_data_bfd_requires_inject_up;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_set_inject_type_static_table_key_t& m)
{
    serializer_class<npl_bfd_set_inject_type_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_set_inject_type_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_set_inject_type_static_table_key_t& m)
{
    serializer_class<npl_bfd_set_inject_type_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_set_inject_type_static_table_key_t&);



template<>
class serializer_class<npl_bfd_set_inject_type_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_set_inject_type_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_set_inject_type_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_set_inject_type_static_table_value_t& m)
{
    serializer_class<npl_bfd_set_inject_type_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_set_inject_type_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_set_inject_type_static_table_value_t& m)
{
    serializer_class<npl_bfd_set_inject_type_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_set_inject_type_static_table_value_t&);



template<>
class serializer_class<npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("packet_inject_header_inject_header_type", m.packet_inject_header_inject_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("packet_inject_header_inject_header_type", m.packet_inject_header_inject_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_set_inject_type_static_table_value_t::npl_bfd_set_inject_type_static_table_payloads_t&);



template<>
class serializer_class<npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t& m) {
        uint64_t m_bfd_valid = m.bfd_valid;
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("bfd_valid", m_bfd_valid));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t& m) {
        uint64_t m_bfd_valid;
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("bfd_valid", m_bfd_valid));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.bfd_valid = m_bfd_valid;
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_map_static_table_bfd_udp_port_result_payload_t&);



template<>
class serializer_class<npl_bfd_udp_port_map_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_map_static_table_key_t& m) {
        uint64_t m_pd_redirect_stage_vars_skip_bfd_or_ttl_255 = m.pd_redirect_stage_vars_skip_bfd_or_ttl_255;
        uint64_t m_packet_ipv4_header_protocol = m.packet_ipv4_header_protocol;
        uint64_t m_packet_ipv6_header_next_header = m.packet_ipv6_header_next_header;
        uint64_t m_packet_header_1__udp_header_dst_port = m.packet_header_1__udp_header_dst_port;
            archive(::cereal::make_nvp("pd_redirect_stage_vars_skip_bfd_or_ttl_255", m_pd_redirect_stage_vars_skip_bfd_or_ttl_255));
            archive(::cereal::make_nvp("packet_header_info_type", m.packet_header_info_type));
            archive(::cereal::make_nvp("packet_ipv4_header_protocol", m_packet_ipv4_header_protocol));
            archive(::cereal::make_nvp("packet_ipv6_header_next_header", m_packet_ipv6_header_next_header));
            archive(::cereal::make_nvp("packet_header_1__udp_header_dst_port", m_packet_header_1__udp_header_dst_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_map_static_table_key_t& m) {
        uint64_t m_pd_redirect_stage_vars_skip_bfd_or_ttl_255;
        uint64_t m_packet_ipv4_header_protocol;
        uint64_t m_packet_ipv6_header_next_header;
        uint64_t m_packet_header_1__udp_header_dst_port;
            archive(::cereal::make_nvp("pd_redirect_stage_vars_skip_bfd_or_ttl_255", m_pd_redirect_stage_vars_skip_bfd_or_ttl_255));
            archive(::cereal::make_nvp("packet_header_info_type", m.packet_header_info_type));
            archive(::cereal::make_nvp("packet_ipv4_header_protocol", m_packet_ipv4_header_protocol));
            archive(::cereal::make_nvp("packet_ipv6_header_next_header", m_packet_ipv6_header_next_header));
            archive(::cereal::make_nvp("packet_header_1__udp_header_dst_port", m_packet_header_1__udp_header_dst_port));
        m.pd_redirect_stage_vars_skip_bfd_or_ttl_255 = m_pd_redirect_stage_vars_skip_bfd_or_ttl_255;
        m.packet_ipv4_header_protocol = m_packet_ipv4_header_protocol;
        m.packet_ipv6_header_next_header = m_packet_ipv6_header_next_header;
        m.packet_header_1__udp_header_dst_port = m_packet_header_1__udp_header_dst_port;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_map_static_table_key_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_map_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_map_static_table_key_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_map_static_table_key_t&);



template<>
class serializer_class<npl_bfd_udp_port_map_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_map_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_map_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_map_static_table_value_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_map_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_map_static_table_value_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_map_static_table_value_t&);



template<>
class serializer_class<npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_udp_port_result", m.bfd_udp_port_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_udp_port_result", m.bfd_udp_port_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_map_static_table_value_t::npl_bfd_udp_port_map_static_table_payloads_t&);



template<>
class serializer_class<npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t& m) {
        uint64_t m_length = m.length;
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("length", m_length));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t& m) {
        uint64_t m_length;
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("length", m_length));
        m.length = m_length;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_static_table_bfd_udp_port_static_result_payload_t&);



template<>
class serializer_class<npl_bfd_udp_port_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_static_table_key_t& m) {
            archive(::cereal::make_nvp("pd_pd_npu_host_inject_fields_aux_data_bfd_session_type", m.pd_pd_npu_host_inject_fields_aux_data_bfd_session_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_static_table_key_t& m) {
            archive(::cereal::make_nvp("pd_pd_npu_host_inject_fields_aux_data_bfd_session_type", m.pd_pd_npu_host_inject_fields_aux_data_bfd_session_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_static_table_key_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_static_table_key_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_static_table_key_t&);



template<>
class serializer_class<npl_bfd_udp_port_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_static_table_value_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_static_table_value_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_static_table_value_t&);



template<>
class serializer_class<npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_udp_port_static_result", m.bfd_udp_port_static_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_udp_port_static_result", m.bfd_udp_port_static_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t& m)
{
    serializer_class<npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_udp_port_static_table_value_t::npl_bfd_udp_port_static_table_payloads_t&);



template<>
class serializer_class<npl_bitmap_oqg_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bitmap_oqg_map_table_key_t& m) {
        uint64_t m_bitmap_oqg_map_index_index = m.bitmap_oqg_map_index_index;
            archive(::cereal::make_nvp("bitmap_oqg_map_index_index", m_bitmap_oqg_map_index_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bitmap_oqg_map_table_key_t& m) {
        uint64_t m_bitmap_oqg_map_index_index;
            archive(::cereal::make_nvp("bitmap_oqg_map_index_index", m_bitmap_oqg_map_index_index));
        m.bitmap_oqg_map_index_index = m_bitmap_oqg_map_index_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bitmap_oqg_map_table_key_t& m)
{
    serializer_class<npl_bitmap_oqg_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bitmap_oqg_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bitmap_oqg_map_table_key_t& m)
{
    serializer_class<npl_bitmap_oqg_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bitmap_oqg_map_table_key_t&);



template<>
class serializer_class<npl_bitmap_oqg_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bitmap_oqg_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bitmap_oqg_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bitmap_oqg_map_table_value_t& m)
{
    serializer_class<npl_bitmap_oqg_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bitmap_oqg_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bitmap_oqg_map_table_value_t& m)
{
    serializer_class<npl_bitmap_oqg_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bitmap_oqg_map_table_value_t&);



template<>
class serializer_class<npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t& m) {
        uint64_t m_bitmap_oqg_map_result_oqg_id = m.bitmap_oqg_map_result_oqg_id;
            archive(::cereal::make_nvp("bitmap_oqg_map_result_oqg_id", m_bitmap_oqg_map_result_oqg_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t& m) {
        uint64_t m_bitmap_oqg_map_result_oqg_id;
            archive(::cereal::make_nvp("bitmap_oqg_map_result_oqg_id", m_bitmap_oqg_map_result_oqg_id));
        m.bitmap_oqg_map_result_oqg_id = m_bitmap_oqg_map_result_oqg_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t& m)
{
    serializer_class<npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t& m)
{
    serializer_class<npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bitmap_oqg_map_table_value_t::npl_bitmap_oqg_map_table_payloads_t&);



template<>
class serializer_class<npl_bvn_tc_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bvn_tc_map_table_key_t& m) {
        uint64_t m_tc_map_profile = m.tc_map_profile;
        uint64_t m_tc = m.tc;
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("tc", m_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bvn_tc_map_table_key_t& m) {
        uint64_t m_tc_map_profile;
        uint64_t m_tc;
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
            archive(::cereal::make_nvp("tc", m_tc));
        m.tc_map_profile = m_tc_map_profile;
        m.tc = m_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bvn_tc_map_table_key_t& m)
{
    serializer_class<npl_bvn_tc_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bvn_tc_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_bvn_tc_map_table_key_t& m)
{
    serializer_class<npl_bvn_tc_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bvn_tc_map_table_key_t&);



template<>
class serializer_class<npl_bvn_tc_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bvn_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bvn_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bvn_tc_map_table_value_t& m)
{
    serializer_class<npl_bvn_tc_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bvn_tc_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_bvn_tc_map_table_value_t& m)
{
    serializer_class<npl_bvn_tc_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bvn_tc_map_table_value_t&);



template<>
class serializer_class<npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t& m) {
        uint64_t m_bvn_offset = m.bvn_offset;
            archive(::cereal::make_nvp("bvn_offset", m_bvn_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t& m) {
        uint64_t m_bvn_offset;
            archive(::cereal::make_nvp("bvn_offset", m_bvn_offset));
        m.bvn_offset = m_bvn_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t& m)
{
    serializer_class<npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t& m)
{
    serializer_class<npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bvn_tc_map_table_value_t::npl_bvn_tc_map_table_payloads_t&);



template<>
class serializer_class<npl_calc_checksum_enable_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_calc_checksum_enable_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_npe_to_npe_metadata_fwd_header_type", m.txpp_npe_to_npe_metadata_fwd_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_calc_checksum_enable_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_npe_to_npe_metadata_fwd_header_type", m.txpp_npe_to_npe_metadata_fwd_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_calc_checksum_enable_table_key_t& m)
{
    serializer_class<npl_calc_checksum_enable_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_calc_checksum_enable_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_calc_checksum_enable_table_key_t& m)
{
    serializer_class<npl_calc_checksum_enable_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_calc_checksum_enable_table_key_t&);



template<>
class serializer_class<npl_calc_checksum_enable_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_calc_checksum_enable_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_calc_checksum_enable_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_calc_checksum_enable_table_value_t& m)
{
    serializer_class<npl_calc_checksum_enable_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_calc_checksum_enable_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_calc_checksum_enable_table_value_t& m)
{
    serializer_class<npl_calc_checksum_enable_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_calc_checksum_enable_table_value_t&);



template<>
class serializer_class<npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t& m) {
            archive(::cereal::make_nvp("calc_checksum_enable", m.calc_checksum_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t& m) {
            archive(::cereal::make_nvp("calc_checksum_enable", m.calc_checksum_enable));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t& m)
{
    serializer_class<npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t& m)
{
    serializer_class<npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_calc_checksum_enable_table_value_t::npl_calc_checksum_enable_table_payloads_t&);



template<>
class serializer_class<npl_ccm_flags_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ccm_flags_table_key_t& m) {
        uint64_t m_tx_rdi = m.tx_rdi;
        uint64_t m_ccm_period = m.ccm_period;
            archive(::cereal::make_nvp("tx_rdi", m_tx_rdi));
            archive(::cereal::make_nvp("ccm_period", m_ccm_period));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ccm_flags_table_key_t& m) {
        uint64_t m_tx_rdi;
        uint64_t m_ccm_period;
            archive(::cereal::make_nvp("tx_rdi", m_tx_rdi));
            archive(::cereal::make_nvp("ccm_period", m_ccm_period));
        m.tx_rdi = m_tx_rdi;
        m.ccm_period = m_ccm_period;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ccm_flags_table_key_t& m)
{
    serializer_class<npl_ccm_flags_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ccm_flags_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ccm_flags_table_key_t& m)
{
    serializer_class<npl_ccm_flags_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ccm_flags_table_key_t&);



template<>
class serializer_class<npl_ccm_flags_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ccm_flags_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ccm_flags_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ccm_flags_table_value_t& m)
{
    serializer_class<npl_ccm_flags_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ccm_flags_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ccm_flags_table_value_t& m)
{
    serializer_class<npl_ccm_flags_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ccm_flags_table_value_t&);



template<>
class serializer_class<npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t& m) {
        uint64_t m_flags = m.flags;
            archive(::cereal::make_nvp("flags", m_flags));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t& m) {
        uint64_t m_flags;
            archive(::cereal::make_nvp("flags", m_flags));
        m.flags = m_flags;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t& m)
{
    serializer_class<npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t& m)
{
    serializer_class<npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ccm_flags_table_value_t::npl_ccm_flags_table_payloads_t&);



template<>
class serializer_class<npl_cif2npa_c_lri_macro_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cif2npa_c_lri_macro_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cif2npa_c_lri_macro_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cif2npa_c_lri_macro_key_t& m)
{
    serializer_class<npl_cif2npa_c_lri_macro_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cif2npa_c_lri_macro_key_t&);

template <class Archive>
void
load(Archive& archive, npl_cif2npa_c_lri_macro_key_t& m)
{
    serializer_class<npl_cif2npa_c_lri_macro_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cif2npa_c_lri_macro_key_t&);



template<>
class serializer_class<npl_cif2npa_c_lri_macro_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cif2npa_c_lri_macro_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cif2npa_c_lri_macro_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cif2npa_c_lri_macro_value_t& m)
{
    serializer_class<npl_cif2npa_c_lri_macro_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cif2npa_c_lri_macro_value_t&);

template <class Archive>
void
load(Archive& archive, npl_cif2npa_c_lri_macro_value_t& m)
{
    serializer_class<npl_cif2npa_c_lri_macro_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cif2npa_c_lri_macro_value_t&);



template<>
class serializer_class<npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t& m) {
        uint64_t m_next_macro_update_next_macro_id = m.next_macro_update_next_macro_id;
            archive(::cereal::make_nvp("next_macro_update_next_macro_id", m_next_macro_update_next_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t& m) {
        uint64_t m_next_macro_update_next_macro_id;
            archive(::cereal::make_nvp("next_macro_update_next_macro_id", m_next_macro_update_next_macro_id));
        m.next_macro_update_next_macro_id = m_next_macro_update_next_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t& m)
{
    serializer_class<npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t& m)
{
    serializer_class<npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cif2npa_c_lri_macro_value_t::npl_cif2npa_c_lri_macro_payloads_t&);



template<>
class serializer_class<npl_cif2npa_c_mps_macro_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cif2npa_c_mps_macro_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cif2npa_c_mps_macro_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cif2npa_c_mps_macro_key_t& m)
{
    serializer_class<npl_cif2npa_c_mps_macro_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cif2npa_c_mps_macro_key_t&);

template <class Archive>
void
load(Archive& archive, npl_cif2npa_c_mps_macro_key_t& m)
{
    serializer_class<npl_cif2npa_c_mps_macro_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cif2npa_c_mps_macro_key_t&);



template<>
class serializer_class<npl_cif2npa_c_mps_macro_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cif2npa_c_mps_macro_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cif2npa_c_mps_macro_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cif2npa_c_mps_macro_value_t& m)
{
    serializer_class<npl_cif2npa_c_mps_macro_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cif2npa_c_mps_macro_value_t&);

template <class Archive>
void
load(Archive& archive, npl_cif2npa_c_mps_macro_value_t& m)
{
    serializer_class<npl_cif2npa_c_mps_macro_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cif2npa_c_mps_macro_value_t&);



template<>
class serializer_class<npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t& m) {
        uint64_t m_next_macro_update_next_macro_id = m.next_macro_update_next_macro_id;
            archive(::cereal::make_nvp("next_macro_update_next_macro_id", m_next_macro_update_next_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t& m) {
        uint64_t m_next_macro_update_next_macro_id;
            archive(::cereal::make_nvp("next_macro_update_next_macro_id", m_next_macro_update_next_macro_id));
        m.next_macro_update_next_macro_id = m_next_macro_update_next_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t& m)
{
    serializer_class<npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t& m)
{
    serializer_class<npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cif2npa_c_mps_macro_value_t::npl_cif2npa_c_mps_macro_payloads_t&);



template<>
class serializer_class<npl_counters_block_config_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_block_config_table_key_t& m) {
        uint64_t m_counter_block_id = m.counter_block_id;
            archive(::cereal::make_nvp("counter_block_id", m_counter_block_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_block_config_table_key_t& m) {
        uint64_t m_counter_block_id;
            archive(::cereal::make_nvp("counter_block_id", m_counter_block_id));
        m.counter_block_id = m_counter_block_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_block_config_table_key_t& m)
{
    serializer_class<npl_counters_block_config_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_block_config_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_block_config_table_key_t& m)
{
    serializer_class<npl_counters_block_config_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_block_config_table_key_t&);



template<>
class serializer_class<npl_counters_block_config_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_block_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_block_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_block_config_table_value_t& m)
{
    serializer_class<npl_counters_block_config_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_block_config_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_block_config_table_value_t& m)
{
    serializer_class<npl_counters_block_config_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_block_config_table_value_t&);



template<>
class serializer_class<npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("counters_block_config", m.counters_block_config));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("counters_block_config", m.counters_block_config));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t& m)
{
    serializer_class<npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t& m)
{
    serializer_class<npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_block_config_table_value_t::npl_counters_block_config_table_payloads_t&);



template<>
class serializer_class<npl_counters_voq_block_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_voq_block_map_table_key_t& m) {
        uint64_t m_voq_base_id = m.voq_base_id;
            archive(::cereal::make_nvp("voq_base_id", m_voq_base_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_voq_block_map_table_key_t& m) {
        uint64_t m_voq_base_id;
            archive(::cereal::make_nvp("voq_base_id", m_voq_base_id));
        m.voq_base_id = m_voq_base_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_voq_block_map_table_key_t& m)
{
    serializer_class<npl_counters_voq_block_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_voq_block_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_voq_block_map_table_key_t& m)
{
    serializer_class<npl_counters_voq_block_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_voq_block_map_table_key_t&);



template<>
class serializer_class<npl_counters_voq_block_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_voq_block_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_voq_block_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_voq_block_map_table_value_t& m)
{
    serializer_class<npl_counters_voq_block_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_voq_block_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_voq_block_map_table_value_t& m)
{
    serializer_class<npl_counters_voq_block_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_voq_block_map_table_value_t&);



template<>
class serializer_class<npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("counters_voq_block_map_result", m.counters_voq_block_map_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("counters_voq_block_map_result", m.counters_voq_block_map_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t& m)
{
    serializer_class<npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t& m)
{
    serializer_class<npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_voq_block_map_table_value_t::npl_counters_voq_block_map_table_payloads_t&);



template<>
class serializer_class<npl_cud_is_multicast_bitmap_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_is_multicast_bitmap_key_t& m) {
        uint64_t m_tx_cud_prefix = m.tx_cud_prefix;
            archive(::cereal::make_nvp("tx_cud_prefix", m_tx_cud_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_is_multicast_bitmap_key_t& m) {
        uint64_t m_tx_cud_prefix;
            archive(::cereal::make_nvp("tx_cud_prefix", m_tx_cud_prefix));
        m.tx_cud_prefix = m_tx_cud_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_is_multicast_bitmap_key_t& m)
{
    serializer_class<npl_cud_is_multicast_bitmap_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_is_multicast_bitmap_key_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_is_multicast_bitmap_key_t& m)
{
    serializer_class<npl_cud_is_multicast_bitmap_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_is_multicast_bitmap_key_t&);



template<>
class serializer_class<npl_cud_is_multicast_bitmap_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_is_multicast_bitmap_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_is_multicast_bitmap_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_is_multicast_bitmap_value_t& m)
{
    serializer_class<npl_cud_is_multicast_bitmap_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_is_multicast_bitmap_value_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_is_multicast_bitmap_value_t& m)
{
    serializer_class<npl_cud_is_multicast_bitmap_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_is_multicast_bitmap_value_t&);



template<>
class serializer_class<npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t& m) {
        uint64_t m_cud_mapping_local_vars_cud_is_multicast = m.cud_mapping_local_vars_cud_is_multicast;
            archive(::cereal::make_nvp("cud_mapping_local_vars_cud_is_multicast", m_cud_mapping_local_vars_cud_is_multicast));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t& m) {
        uint64_t m_cud_mapping_local_vars_cud_is_multicast;
            archive(::cereal::make_nvp("cud_mapping_local_vars_cud_is_multicast", m_cud_mapping_local_vars_cud_is_multicast));
        m.cud_mapping_local_vars_cud_is_multicast = m_cud_mapping_local_vars_cud_is_multicast;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t& m)
{
    serializer_class<npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t& m)
{
    serializer_class<npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_is_multicast_bitmap_value_t::npl_cud_is_multicast_bitmap_payloads_t&);



template<>
class serializer_class<npl_cud_narrow_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_narrow_hw_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_12_0_ = m.cud_mapping_local_vars_mc_copy_id_12_0_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_12_0_", m_cud_mapping_local_vars_mc_copy_id_12_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_narrow_hw_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_12_0_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_12_0_", m_cud_mapping_local_vars_mc_copy_id_12_0_));
        m.cud_mapping_local_vars_mc_copy_id_12_0_ = m_cud_mapping_local_vars_mc_copy_id_12_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_narrow_hw_table_key_t& m)
{
    serializer_class<npl_cud_narrow_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_narrow_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_narrow_hw_table_key_t& m)
{
    serializer_class<npl_cud_narrow_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_narrow_hw_table_key_t&);



template<>
class serializer_class<npl_cud_narrow_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_narrow_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_narrow_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_narrow_hw_table_value_t& m)
{
    serializer_class<npl_cud_narrow_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_narrow_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_narrow_hw_table_value_t& m)
{
    serializer_class<npl_cud_narrow_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_narrow_hw_table_value_t&);



template<>
class serializer_class<npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t& m) {
        uint64_t m_cud_mapping_local_vars_narrow_mc_cud = m.cud_mapping_local_vars_narrow_mc_cud;
            archive(::cereal::make_nvp("cud_mapping_local_vars_narrow_mc_cud", m_cud_mapping_local_vars_narrow_mc_cud));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t& m) {
        uint64_t m_cud_mapping_local_vars_narrow_mc_cud;
            archive(::cereal::make_nvp("cud_mapping_local_vars_narrow_mc_cud", m_cud_mapping_local_vars_narrow_mc_cud));
        m.cud_mapping_local_vars_narrow_mc_cud = m_cud_mapping_local_vars_narrow_mc_cud;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t& m)
{
    serializer_class<npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t& m)
{
    serializer_class<npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_narrow_hw_table_value_t::npl_cud_narrow_hw_table_payloads_t&);



template<>
class serializer_class<npl_cud_wide_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_wide_hw_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_12_1_ = m.cud_mapping_local_vars_mc_copy_id_12_1_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_12_1_", m_cud_mapping_local_vars_mc_copy_id_12_1_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_wide_hw_table_key_t& m) {
        uint64_t m_cud_mapping_local_vars_mc_copy_id_12_1_;
            archive(::cereal::make_nvp("cud_mapping_local_vars_mc_copy_id_12_1_", m_cud_mapping_local_vars_mc_copy_id_12_1_));
        m.cud_mapping_local_vars_mc_copy_id_12_1_ = m_cud_mapping_local_vars_mc_copy_id_12_1_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_wide_hw_table_key_t& m)
{
    serializer_class<npl_cud_wide_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_wide_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_wide_hw_table_key_t& m)
{
    serializer_class<npl_cud_wide_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_wide_hw_table_key_t&);



template<>
class serializer_class<npl_cud_wide_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_wide_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_wide_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_wide_hw_table_value_t& m)
{
    serializer_class<npl_cud_wide_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_wide_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_wide_hw_table_value_t& m)
{
    serializer_class<npl_cud_wide_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_wide_hw_table_value_t&);



template<>
class serializer_class<npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t& m) {
            archive(::cereal::make_nvp("cud_mapping_local_vars_wide_mc_cud", m.cud_mapping_local_vars_wide_mc_cud));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t& m) {
            archive(::cereal::make_nvp("cud_mapping_local_vars_wide_mc_cud", m.cud_mapping_local_vars_wide_mc_cud));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t& m)
{
    serializer_class<npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t& m)
{
    serializer_class<npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_cud_wide_hw_table_value_t::npl_cud_wide_hw_table_payloads_t&);



template<>
class serializer_class<npl_default_egress_ipv4_sec_acl_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_default_egress_ipv4_sec_acl_table_key_t& m) {
        uint64_t m_sip = m.sip;
        uint64_t m_dip = m.dip;
        uint64_t m_src_port = m.src_port;
        uint64_t m_dst_port = m.dst_port;
        uint64_t m_fwd_qos_tag_5_0_ = m.fwd_qos_tag_5_0_;
        uint64_t m_new_ttl = m.new_ttl;
        uint64_t m_protocol = m.protocol;
        uint64_t m_tcp_flags = m.tcp_flags;
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("fwd_qos_tag_5_0_", m_fwd_qos_tag_5_0_));
            archive(::cereal::make_nvp("new_ttl", m_new_ttl));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_default_egress_ipv4_sec_acl_table_key_t& m) {
        uint64_t m_sip;
        uint64_t m_dip;
        uint64_t m_src_port;
        uint64_t m_dst_port;
        uint64_t m_fwd_qos_tag_5_0_;
        uint64_t m_new_ttl;
        uint64_t m_protocol;
        uint64_t m_tcp_flags;
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("fwd_qos_tag_5_0_", m_fwd_qos_tag_5_0_));
            archive(::cereal::make_nvp("new_ttl", m_new_ttl));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.sip = m_sip;
        m.dip = m_dip;
        m.src_port = m_src_port;
        m.dst_port = m_dst_port;
        m.fwd_qos_tag_5_0_ = m_fwd_qos_tag_5_0_;
        m.new_ttl = m_new_ttl;
        m.protocol = m_protocol;
        m.tcp_flags = m_tcp_flags;
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_default_egress_ipv4_sec_acl_table_key_t& m)
{
    serializer_class<npl_default_egress_ipv4_sec_acl_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_default_egress_ipv4_sec_acl_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_default_egress_ipv4_sec_acl_table_key_t& m)
{
    serializer_class<npl_default_egress_ipv4_sec_acl_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_default_egress_ipv4_sec_acl_table_key_t&);



template<>
class serializer_class<npl_default_egress_ipv4_sec_acl_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_default_egress_ipv4_sec_acl_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_default_egress_ipv4_sec_acl_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_default_egress_ipv4_sec_acl_table_value_t& m)
{
    serializer_class<npl_default_egress_ipv4_sec_acl_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_default_egress_ipv4_sec_acl_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_default_egress_ipv4_sec_acl_table_value_t& m)
{
    serializer_class<npl_default_egress_ipv4_sec_acl_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_default_egress_ipv4_sec_acl_table_value_t&);



template<>
class serializer_class<npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t& m) {
            archive(::cereal::make_nvp("egress_sec_acl_result", m.egress_sec_acl_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t& m) {
            archive(::cereal::make_nvp("egress_sec_acl_result", m.egress_sec_acl_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t& m)
{
    serializer_class<npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t& m)
{
    serializer_class<npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_default_egress_ipv4_sec_acl_table_value_t::npl_default_egress_ipv4_sec_acl_table_payloads_t&);



template<>
class serializer_class<npl_default_egress_ipv6_acl_sec_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_default_egress_ipv6_acl_sec_table_key_t& m) {
        uint64_t m_next_header = m.next_header;
        uint64_t m_dst_port = m.dst_port;
        uint64_t m_acl_id = m.acl_id;
        uint64_t m_src_port = m.src_port;
        uint64_t m_qos_tag = m.qos_tag;
        uint64_t m_tcp_flags = m.tcp_flags;
            archive(::cereal::make_nvp("next_header", m_next_header));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("first_fragment", m.first_fragment));
            archive(::cereal::make_nvp("sip", m.sip));
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("qos_tag", m_qos_tag));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_default_egress_ipv6_acl_sec_table_key_t& m) {
        uint64_t m_next_header;
        uint64_t m_dst_port;
        uint64_t m_acl_id;
        uint64_t m_src_port;
        uint64_t m_qos_tag;
        uint64_t m_tcp_flags;
            archive(::cereal::make_nvp("next_header", m_next_header));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
            archive(::cereal::make_nvp("dip", m.dip));
            archive(::cereal::make_nvp("first_fragment", m.first_fragment));
            archive(::cereal::make_nvp("sip", m.sip));
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("qos_tag", m_qos_tag));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
        m.next_header = m_next_header;
        m.dst_port = m_dst_port;
        m.acl_id = m_acl_id;
        m.src_port = m_src_port;
        m.qos_tag = m_qos_tag;
        m.tcp_flags = m_tcp_flags;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_default_egress_ipv6_acl_sec_table_key_t& m)
{
    serializer_class<npl_default_egress_ipv6_acl_sec_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_default_egress_ipv6_acl_sec_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_default_egress_ipv6_acl_sec_table_key_t& m)
{
    serializer_class<npl_default_egress_ipv6_acl_sec_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_default_egress_ipv6_acl_sec_table_key_t&);



template<>
class serializer_class<npl_default_egress_ipv6_acl_sec_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_default_egress_ipv6_acl_sec_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_default_egress_ipv6_acl_sec_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_default_egress_ipv6_acl_sec_table_value_t& m)
{
    serializer_class<npl_default_egress_ipv6_acl_sec_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_default_egress_ipv6_acl_sec_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_default_egress_ipv6_acl_sec_table_value_t& m)
{
    serializer_class<npl_default_egress_ipv6_acl_sec_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_default_egress_ipv6_acl_sec_table_value_t&);



template<>
class serializer_class<npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t& m) {
            archive(::cereal::make_nvp("sec_action", m.sec_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t& m) {
            archive(::cereal::make_nvp("sec_action", m.sec_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t& m)
{
    serializer_class<npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t& m)
{
    serializer_class<npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_default_egress_ipv6_acl_sec_table_value_t::npl_default_egress_ipv6_acl_sec_table_payloads_t&);



template<>
class serializer_class<npl_dest_slice_voq_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dest_slice_voq_map_table_key_t& m) {
        uint64_t m_calc_msvoq_num_input_tx_slice = m.calc_msvoq_num_input_tx_slice;
            archive(::cereal::make_nvp("calc_msvoq_num_input_tx_slice", m_calc_msvoq_num_input_tx_slice));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dest_slice_voq_map_table_key_t& m) {
        uint64_t m_calc_msvoq_num_input_tx_slice;
            archive(::cereal::make_nvp("calc_msvoq_num_input_tx_slice", m_calc_msvoq_num_input_tx_slice));
        m.calc_msvoq_num_input_tx_slice = m_calc_msvoq_num_input_tx_slice;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dest_slice_voq_map_table_key_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dest_slice_voq_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_dest_slice_voq_map_table_key_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dest_slice_voq_map_table_key_t&);



template<>
class serializer_class<npl_dest_slice_voq_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dest_slice_voq_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dest_slice_voq_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dest_slice_voq_map_table_value_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dest_slice_voq_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_dest_slice_voq_map_table_value_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dest_slice_voq_map_table_value_t&);



template<>
class serializer_class<npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("dest_slice_voq_map_table_result", m.dest_slice_voq_map_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("dest_slice_voq_map_table_result", m.dest_slice_voq_map_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dest_slice_voq_map_table_value_t::npl_dest_slice_voq_map_table_payloads_t&);



template<>
class serializer_class<npl_destination_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_destination_decoding_table_key_t& m) {
        uint64_t m_destination_encoding = m.destination_encoding;
            archive(::cereal::make_nvp("destination_encoding", m_destination_encoding));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_destination_decoding_table_key_t& m) {
        uint64_t m_destination_encoding;
            archive(::cereal::make_nvp("destination_encoding", m_destination_encoding));
        m.destination_encoding = m_destination_encoding;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_destination_decoding_table_key_t& m)
{
    serializer_class<npl_destination_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_destination_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_destination_decoding_table_key_t& m)
{
    serializer_class<npl_destination_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_destination_decoding_table_key_t&);



template<>
class serializer_class<npl_destination_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_destination_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_destination_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_destination_decoding_table_value_t& m)
{
    serializer_class<npl_destination_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_destination_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_destination_decoding_table_value_t& m)
{
    serializer_class<npl_destination_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_destination_decoding_table_value_t&);



template<>
class serializer_class<npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("destination_decoding_table_result", m.destination_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("destination_decoding_table_result", m.destination_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t& m)
{
    serializer_class<npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t& m)
{
    serializer_class<npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_destination_decoding_table_value_t::npl_destination_decoding_table_payloads_t&);



template<>
class serializer_class<npl_device_mode_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_device_mode_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_device_mode_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_device_mode_table_key_t& m)
{
    serializer_class<npl_device_mode_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_device_mode_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_device_mode_table_key_t& m)
{
    serializer_class<npl_device_mode_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_device_mode_table_key_t&);



template<>
class serializer_class<npl_device_mode_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_device_mode_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_device_mode_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_device_mode_table_value_t& m)
{
    serializer_class<npl_device_mode_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_device_mode_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_device_mode_table_value_t& m)
{
    serializer_class<npl_device_mode_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_device_mode_table_value_t&);



template<>
class serializer_class<npl_device_mode_table_value_t::npl_device_mode_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_device_mode_table_value_t::npl_device_mode_table_payloads_t& m) {
            archive(::cereal::make_nvp("device_mode_table_result", m.device_mode_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_device_mode_table_value_t::npl_device_mode_table_payloads_t& m) {
            archive(::cereal::make_nvp("device_mode_table_result", m.device_mode_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_device_mode_table_value_t::npl_device_mode_table_payloads_t& m)
{
    serializer_class<npl_device_mode_table_value_t::npl_device_mode_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_device_mode_table_value_t::npl_device_mode_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_device_mode_table_value_t::npl_device_mode_table_payloads_t& m)
{
    serializer_class<npl_device_mode_table_value_t::npl_device_mode_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_device_mode_table_value_t::npl_device_mode_table_payloads_t&);



template<>
class serializer_class<npl_dsp_l2_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l2_attributes_table_key_t& m) {
        uint64_t m_omd_txpp = m.omd_txpp;
            archive(::cereal::make_nvp("omd_txpp", m_omd_txpp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l2_attributes_table_key_t& m) {
        uint64_t m_omd_txpp;
            archive(::cereal::make_nvp("omd_txpp", m_omd_txpp));
        m.omd_txpp = m_omd_txpp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l2_attributes_table_key_t& m)
{
    serializer_class<npl_dsp_l2_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l2_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l2_attributes_table_key_t& m)
{
    serializer_class<npl_dsp_l2_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l2_attributes_table_key_t&);



template<>
class serializer_class<npl_dsp_l2_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l2_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l2_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l2_attributes_table_value_t& m)
{
    serializer_class<npl_dsp_l2_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l2_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l2_attributes_table_value_t& m)
{
    serializer_class<npl_dsp_l2_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l2_attributes_table_value_t&);



template<>
class serializer_class<npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("dsp_l2_attributes", m.dsp_l2_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("dsp_l2_attributes", m.dsp_l2_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t& m)
{
    serializer_class<npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t& m)
{
    serializer_class<npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l2_attributes_table_value_t::npl_dsp_l2_attributes_table_payloads_t&);



template<>
class serializer_class<npl_dsp_l3_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l3_attributes_table_key_t& m) {
        uint64_t m_omd_txpp = m.omd_txpp;
            archive(::cereal::make_nvp("omd_txpp", m_omd_txpp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l3_attributes_table_key_t& m) {
        uint64_t m_omd_txpp;
            archive(::cereal::make_nvp("omd_txpp", m_omd_txpp));
        m.omd_txpp = m_omd_txpp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l3_attributes_table_key_t& m)
{
    serializer_class<npl_dsp_l3_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l3_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l3_attributes_table_key_t& m)
{
    serializer_class<npl_dsp_l3_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l3_attributes_table_key_t&);



template<>
class serializer_class<npl_dsp_l3_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l3_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l3_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l3_attributes_table_value_t& m)
{
    serializer_class<npl_dsp_l3_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l3_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l3_attributes_table_value_t& m)
{
    serializer_class<npl_dsp_l3_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l3_attributes_table_value_t&);



template<>
class serializer_class<npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("dsp_l3_attributes", m.dsp_l3_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("dsp_l3_attributes", m.dsp_l3_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t& m)
{
    serializer_class<npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t& m)
{
    serializer_class<npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_l3_attributes_table_value_t::npl_dsp_l3_attributes_table_payloads_t&);



template<>
class serializer_class<npl_dummy_dip_index_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dummy_dip_index_table_key_t& m) {
            archive(::cereal::make_nvp("dummy_dip_index", m.dummy_dip_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dummy_dip_index_table_key_t& m) {
            archive(::cereal::make_nvp("dummy_dip_index", m.dummy_dip_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dummy_dip_index_table_key_t& m)
{
    serializer_class<npl_dummy_dip_index_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dummy_dip_index_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_dummy_dip_index_table_key_t& m)
{
    serializer_class<npl_dummy_dip_index_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dummy_dip_index_table_key_t&);



template<>
class serializer_class<npl_dummy_dip_index_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dummy_dip_index_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dummy_dip_index_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dummy_dip_index_table_value_t& m)
{
    serializer_class<npl_dummy_dip_index_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dummy_dip_index_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_dummy_dip_index_table_value_t& m)
{
    serializer_class<npl_dummy_dip_index_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dummy_dip_index_table_value_t&);



template<>
class serializer_class<npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t& m) {
            archive(::cereal::make_nvp("dummy_data", m.dummy_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t& m) {
            archive(::cereal::make_nvp("dummy_data", m.dummy_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t& m)
{
    serializer_class<npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t& m)
{
    serializer_class<npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dummy_dip_index_table_value_t::npl_dummy_dip_index_table_payloads_t&);



template<>
class serializer_class<npl_ecn_remark_static_table_set_value_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ecn_remark_static_table_set_value_payload_t& m) {
        uint64_t m_new_ecn = m.new_ecn;
        uint64_t m_en_ecn_counting = m.en_ecn_counting;
            archive(::cereal::make_nvp("new_ecn", m_new_ecn));
            archive(::cereal::make_nvp("en_ecn_counting", m_en_ecn_counting));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ecn_remark_static_table_set_value_payload_t& m) {
        uint64_t m_new_ecn;
        uint64_t m_en_ecn_counting;
            archive(::cereal::make_nvp("new_ecn", m_new_ecn));
            archive(::cereal::make_nvp("en_ecn_counting", m_en_ecn_counting));
        m.new_ecn = m_new_ecn;
        m.en_ecn_counting = m_en_ecn_counting;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ecn_remark_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ecn_remark_static_table_set_value_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ecn_remark_static_table_set_value_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ecn_remark_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ecn_remark_static_table_set_value_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ecn_remark_static_table_set_value_payload_t&);



template<>
class serializer_class<npl_ecn_remark_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ecn_remark_static_table_key_t& m) {
        uint64_t m_packet_ipv4_header_tos_3_0_ = m.packet_ipv4_header_tos_3_0_;
        uint64_t m_packet_ipv6_header_tos_3_0_ = m.packet_ipv6_header_tos_3_0_;
            archive(::cereal::make_nvp("pd_cong_on", m.pd_cong_on));
            archive(::cereal::make_nvp("tx_npu_header_fwd_header_type", m.tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_ipv4_header_tos_3_0_", m_packet_ipv4_header_tos_3_0_));
            archive(::cereal::make_nvp("packet_ipv6_header_tos_3_0_", m_packet_ipv6_header_tos_3_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ecn_remark_static_table_key_t& m) {
        uint64_t m_packet_ipv4_header_tos_3_0_;
        uint64_t m_packet_ipv6_header_tos_3_0_;
            archive(::cereal::make_nvp("pd_cong_on", m.pd_cong_on));
            archive(::cereal::make_nvp("tx_npu_header_fwd_header_type", m.tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_ipv4_header_tos_3_0_", m_packet_ipv4_header_tos_3_0_));
            archive(::cereal::make_nvp("packet_ipv6_header_tos_3_0_", m_packet_ipv6_header_tos_3_0_));
        m.packet_ipv4_header_tos_3_0_ = m_packet_ipv4_header_tos_3_0_;
        m.packet_ipv6_header_tos_3_0_ = m_packet_ipv6_header_tos_3_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ecn_remark_static_table_key_t& m)
{
    serializer_class<npl_ecn_remark_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ecn_remark_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ecn_remark_static_table_key_t& m)
{
    serializer_class<npl_ecn_remark_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ecn_remark_static_table_key_t&);



template<>
class serializer_class<npl_ecn_remark_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ecn_remark_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ecn_remark_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ecn_remark_static_table_value_t& m)
{
    serializer_class<npl_ecn_remark_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ecn_remark_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ecn_remark_static_table_value_t& m)
{
    serializer_class<npl_ecn_remark_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ecn_remark_static_table_value_t&);



template<>
class serializer_class<npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t& m)
{
    serializer_class<npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t& m)
{
    serializer_class<npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ecn_remark_static_table_value_t::npl_ecn_remark_static_table_payloads_t&);



template<>
class serializer_class<npl_egress_mac_ipv4_sec_acl_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_mac_ipv4_sec_acl_table_key_t& m) {
        uint64_t m_tcp_flags = m.tcp_flags;
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("sip_dip", m.sip_dip));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("tos", m.tos));
            archive(::cereal::make_nvp("ttl_and_protocol", m.ttl_and_protocol));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_mac_ipv4_sec_acl_table_key_t& m) {
        uint64_t m_tcp_flags;
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("sip_dip", m.sip_dip));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("tos", m.tos));
            archive(::cereal::make_nvp("ttl_and_protocol", m.ttl_and_protocol));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.tcp_flags = m_tcp_flags;
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_mac_ipv4_sec_acl_table_key_t& m)
{
    serializer_class<npl_egress_mac_ipv4_sec_acl_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_mac_ipv4_sec_acl_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_mac_ipv4_sec_acl_table_key_t& m)
{
    serializer_class<npl_egress_mac_ipv4_sec_acl_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_mac_ipv4_sec_acl_table_key_t&);



template<>
class serializer_class<npl_egress_mac_ipv4_sec_acl_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_mac_ipv4_sec_acl_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_mac_ipv4_sec_acl_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_mac_ipv4_sec_acl_table_value_t& m)
{
    serializer_class<npl_egress_mac_ipv4_sec_acl_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_mac_ipv4_sec_acl_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_mac_ipv4_sec_acl_table_value_t& m)
{
    serializer_class<npl_egress_mac_ipv4_sec_acl_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_mac_ipv4_sec_acl_table_value_t&);



template<>
class serializer_class<npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t& m) {
            archive(::cereal::make_nvp("egress_sec_acl_result", m.egress_sec_acl_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t& m) {
            archive(::cereal::make_nvp("egress_sec_acl_result", m.egress_sec_acl_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t& m)
{
    serializer_class<npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t& m)
{
    serializer_class<npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_mac_ipv4_sec_acl_table_value_t::npl_egress_mac_ipv4_sec_acl_table_payloads_t&);



template<>
class serializer_class<npl_egress_nh_and_svi_direct0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_nh_and_svi_direct0_table_key_t& m) {
            archive(::cereal::make_nvp("egress_direct0_key", m.egress_direct0_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_nh_and_svi_direct0_table_key_t& m) {
            archive(::cereal::make_nvp("egress_direct0_key", m.egress_direct0_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_nh_and_svi_direct0_table_key_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_nh_and_svi_direct0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_nh_and_svi_direct0_table_key_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_nh_and_svi_direct0_table_key_t&);



template<>
class serializer_class<npl_egress_nh_and_svi_direct0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_nh_and_svi_direct0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_nh_and_svi_direct0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_nh_and_svi_direct0_table_value_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_nh_and_svi_direct0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_nh_and_svi_direct0_table_value_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_nh_and_svi_direct0_table_value_t&);



template<>
class serializer_class<npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t& m) {
            archive(::cereal::make_nvp("nh_and_svi_payload", m.nh_and_svi_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t& m) {
            archive(::cereal::make_nvp("nh_and_svi_payload", m.nh_and_svi_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_nh_and_svi_direct0_table_value_t::npl_egress_nh_and_svi_direct0_table_payloads_t&);



template<>
class serializer_class<npl_egress_nh_and_svi_direct1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_nh_and_svi_direct1_table_key_t& m) {
            archive(::cereal::make_nvp("egress_direct1_key", m.egress_direct1_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_nh_and_svi_direct1_table_key_t& m) {
            archive(::cereal::make_nvp("egress_direct1_key", m.egress_direct1_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_nh_and_svi_direct1_table_key_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_nh_and_svi_direct1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_nh_and_svi_direct1_table_key_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_nh_and_svi_direct1_table_key_t&);



template<>
class serializer_class<npl_egress_nh_and_svi_direct1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_nh_and_svi_direct1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_nh_and_svi_direct1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_nh_and_svi_direct1_table_value_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_nh_and_svi_direct1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_nh_and_svi_direct1_table_value_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_nh_and_svi_direct1_table_value_t&);



template<>
class serializer_class<npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t& m) {
            archive(::cereal::make_nvp("nh_and_svi_payload", m.nh_and_svi_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t& m) {
            archive(::cereal::make_nvp("nh_and_svi_payload", m.nh_and_svi_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t& m)
{
    serializer_class<npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_nh_and_svi_direct1_table_value_t::npl_egress_nh_and_svi_direct1_table_payloads_t&);



template<>
class serializer_class<npl_em_mp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_mp_table_key_t& m) {
        uint64_t m_your_discr = m.your_discr;
        uint64_t m_udp_dest_port = m.udp_dest_port;
            archive(::cereal::make_nvp("your_discr", m_your_discr));
            archive(::cereal::make_nvp("udp_dest_port", m_udp_dest_port));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_mp_table_key_t& m) {
        uint64_t m_your_discr;
        uint64_t m_udp_dest_port;
            archive(::cereal::make_nvp("your_discr", m_your_discr));
            archive(::cereal::make_nvp("udp_dest_port", m_udp_dest_port));
        m.your_discr = m_your_discr;
        m.udp_dest_port = m_udp_dest_port;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_mp_table_key_t& m)
{
    serializer_class<npl_em_mp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_mp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_em_mp_table_key_t& m)
{
    serializer_class<npl_em_mp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_mp_table_key_t&);



template<>
class serializer_class<npl_em_mp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_mp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_mp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_mp_table_value_t& m)
{
    serializer_class<npl_em_mp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_mp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_em_mp_table_value_t& m)
{
    serializer_class<npl_em_mp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_mp_table_value_t&);



template<>
class serializer_class<npl_em_mp_table_value_t::npl_em_mp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_mp_table_value_t::npl_em_mp_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_em_payload", m.bfd_em_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_mp_table_value_t::npl_em_mp_table_payloads_t& m) {
            archive(::cereal::make_nvp("bfd_em_payload", m.bfd_em_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_mp_table_value_t::npl_em_mp_table_payloads_t& m)
{
    serializer_class<npl_em_mp_table_value_t::npl_em_mp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_mp_table_value_t::npl_em_mp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_em_mp_table_value_t::npl_em_mp_table_payloads_t& m)
{
    serializer_class<npl_em_mp_table_value_t::npl_em_mp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_mp_table_value_t::npl_em_mp_table_payloads_t&);



template<>
class serializer_class<npl_em_pfc_cong_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_pfc_cong_table_key_t& m) {
        uint64_t m_slice = m.slice;
        uint64_t m_tc = m.tc;
        uint64_t m_dsp1 = m.dsp1;
        uint64_t m_dsp2 = m.dsp2;
        uint64_t m_dsp3 = m.dsp3;
        uint64_t m_dsp4 = m.dsp4;
            archive(::cereal::make_nvp("slice", m_slice));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dsp1", m_dsp1));
            archive(::cereal::make_nvp("dsp2", m_dsp2));
            archive(::cereal::make_nvp("dsp3", m_dsp3));
            archive(::cereal::make_nvp("dsp4", m_dsp4));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_pfc_cong_table_key_t& m) {
        uint64_t m_slice;
        uint64_t m_tc;
        uint64_t m_dsp1;
        uint64_t m_dsp2;
        uint64_t m_dsp3;
        uint64_t m_dsp4;
            archive(::cereal::make_nvp("slice", m_slice));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dsp1", m_dsp1));
            archive(::cereal::make_nvp("dsp2", m_dsp2));
            archive(::cereal::make_nvp("dsp3", m_dsp3));
            archive(::cereal::make_nvp("dsp4", m_dsp4));
        m.slice = m_slice;
        m.tc = m_tc;
        m.dsp1 = m_dsp1;
        m.dsp2 = m_dsp2;
        m.dsp3 = m_dsp3;
        m.dsp4 = m_dsp4;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_pfc_cong_table_key_t& m)
{
    serializer_class<npl_em_pfc_cong_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_pfc_cong_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_em_pfc_cong_table_key_t& m)
{
    serializer_class<npl_em_pfc_cong_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_pfc_cong_table_key_t&);



template<>
class serializer_class<npl_em_pfc_cong_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_pfc_cong_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_pfc_cong_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_pfc_cong_table_value_t& m)
{
    serializer_class<npl_em_pfc_cong_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_pfc_cong_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_em_pfc_cong_table_value_t& m)
{
    serializer_class<npl_em_pfc_cong_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_pfc_cong_table_value_t&);



template<>
class serializer_class<npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t& m) {
            archive(::cereal::make_nvp("em_payload", m.em_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t& m) {
            archive(::cereal::make_nvp("em_payload", m.em_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t& m)
{
    serializer_class<npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t& m)
{
    serializer_class<npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_pfc_cong_table_value_t::npl_em_pfc_cong_table_payloads_t&);



template<>
class serializer_class<npl_ene_byte_addition_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_byte_addition_static_table_key_t& m) {
            archive(::cereal::make_nvp("pd_first_ene_macro", m.pd_first_ene_macro));
            archive(::cereal::make_nvp("pd_ene_macro_ids_0_", m.pd_ene_macro_ids_0_));
            archive(::cereal::make_nvp("pd_ene_macro_ids_1_", m.pd_ene_macro_ids_1_));
            archive(::cereal::make_nvp("pd_ene_macro_ids_2_", m.pd_ene_macro_ids_2_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_byte_addition_static_table_key_t& m) {
            archive(::cereal::make_nvp("pd_first_ene_macro", m.pd_first_ene_macro));
            archive(::cereal::make_nvp("pd_ene_macro_ids_0_", m.pd_ene_macro_ids_0_));
            archive(::cereal::make_nvp("pd_ene_macro_ids_1_", m.pd_ene_macro_ids_1_));
            archive(::cereal::make_nvp("pd_ene_macro_ids_2_", m.pd_ene_macro_ids_2_));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_byte_addition_static_table_key_t& m)
{
    serializer_class<npl_ene_byte_addition_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_byte_addition_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_byte_addition_static_table_key_t& m)
{
    serializer_class<npl_ene_byte_addition_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_byte_addition_static_table_key_t&);



template<>
class serializer_class<npl_ene_byte_addition_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_byte_addition_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_byte_addition_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_byte_addition_static_table_value_t& m)
{
    serializer_class<npl_ene_byte_addition_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_byte_addition_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_byte_addition_static_table_value_t& m)
{
    serializer_class<npl_ene_byte_addition_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_byte_addition_static_table_value_t&);



template<>
class serializer_class<npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t& m) {
        uint64_t m_padding_vars_ene_byte_addition = m.padding_vars_ene_byte_addition;
            archive(::cereal::make_nvp("padding_vars_ene_byte_addition", m_padding_vars_ene_byte_addition));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t& m) {
        uint64_t m_padding_vars_ene_byte_addition;
            archive(::cereal::make_nvp("padding_vars_ene_byte_addition", m_padding_vars_ene_byte_addition));
        m.padding_vars_ene_byte_addition = m_padding_vars_ene_byte_addition;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t& m)
{
    serializer_class<npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t& m)
{
    serializer_class<npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_byte_addition_static_table_value_t::npl_ene_byte_addition_static_table_payloads_t&);



template<>
class serializer_class<npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t& m) {
        uint64_t m_ene_encap_tpid = m.ene_encap_tpid;
            archive(::cereal::make_nvp("ene_encap_macro_id", m.ene_encap_macro_id));
            archive(::cereal::make_nvp("ene_encap_tpid", m_ene_encap_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t& m) {
        uint64_t m_ene_encap_tpid;
            archive(::cereal::make_nvp("ene_encap_macro_id", m.ene_encap_macro_id));
            archive(::cereal::make_nvp("ene_encap_tpid", m_ene_encap_tpid));
        m.ene_encap_tpid = m_ene_encap_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_macro_code_tpid_profile_static_table_set_value_payload_t&);



template<>
class serializer_class<npl_ene_macro_code_tpid_profile_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_key_t& m) {
        uint64_t m_tpid_profile = m.tpid_profile;
            archive(::cereal::make_nvp("tpid_profile", m_tpid_profile));
            archive(::cereal::make_nvp("macro_code", m.macro_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_key_t& m) {
        uint64_t m_tpid_profile;
            archive(::cereal::make_nvp("tpid_profile", m_tpid_profile));
            archive(::cereal::make_nvp("macro_code", m.macro_code));
        m.tpid_profile = m_tpid_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_key_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_macro_code_tpid_profile_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_key_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_macro_code_tpid_profile_static_table_key_t&);



template<>
class serializer_class<npl_ene_macro_code_tpid_profile_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_value_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_macro_code_tpid_profile_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_value_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_macro_code_tpid_profile_static_table_value_t&);



template<>
class serializer_class<npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t& m)
{
    serializer_class<npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_macro_code_tpid_profile_static_table_value_t::npl_ene_macro_code_tpid_profile_static_table_payloads_t&);



template<>
class serializer_class<npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t& m) {
            archive(::cereal::make_nvp("counter_offset", m.counter_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t& m) {
            archive(::cereal::make_nvp("counter_offset", m.counter_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t&);



template<>
class serializer_class<npl_erpp_fabric_counters_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_offset_table_key_t& m) {
        uint64_t m_vce = m.vce;
        uint64_t m_tc = m.tc;
        uint64_t m_dp = m.dp;
            archive(::cereal::make_nvp("vce", m_vce));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dp", m_dp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_offset_table_key_t& m) {
        uint64_t m_vce;
        uint64_t m_tc;
        uint64_t m_dp;
            archive(::cereal::make_nvp("vce", m_vce));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("dp", m_dp));
        m.vce = m_vce;
        m.tc = m_tc;
        m.dp = m_dp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_offset_table_key_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_offset_table_key_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_offset_table_key_t&);



}

