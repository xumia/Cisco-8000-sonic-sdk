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

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ene_inject_down_payload_t&);
template <class Archive> void load(Archive&, npl_ene_inject_down_payload_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_ip_encap_data_t&);
template <class Archive> void load(Archive&, npl_ip_encap_data_t&);

template <class Archive> void save(Archive&, const npl_is_pbts_prefix_t&);
template <class Archive> void load(Archive&, npl_is_pbts_prefix_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_large_em_label_encap_data_and_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_large_em_label_encap_data_and_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_lb_group_size_table_result_t&);
template <class Archive> void load(Archive&, npl_lb_group_size_table_result_t&);

template <class Archive> void save(Archive&, const npl_lp_id_t&);
template <class Archive> void load(Archive&, npl_lp_id_t&);

template <class Archive> void save(Archive&, const npl_nhlfe_t&);
template <class Archive> void load(Archive&, npl_nhlfe_t&);

template <class Archive> void save(Archive&, const npl_npp_protection_t&);
template <class Archive> void load(Archive&, npl_npp_protection_t&);

template <class Archive> void save(Archive&, const npl_path_lp_table_result_narrow_t&);
template <class Archive> void load(Archive&, npl_path_lp_table_result_narrow_t&);

template <class Archive> void save(Archive&, const npl_path_lp_table_result_protected_t&);
template <class Archive> void load(Archive&, npl_path_lp_table_result_protected_t&);

template <class Archive> void save(Archive&, const npl_path_lp_table_result_wide_t&);
template <class Archive> void load(Archive&, npl_path_lp_table_result_wide_t&);

template <class Archive> void save(Archive&, const npl_path_protection_id_t&);
template <class Archive> void load(Archive&, npl_path_protection_id_t&);

template <class Archive> void save(Archive&, const npl_pbts_map_table_key_t&);
template <class Archive> void load(Archive&, npl_pbts_map_table_key_t&);

template <class Archive> void save(Archive&, const npl_pbts_map_table_result_t&);
template <class Archive> void load(Archive&, npl_pbts_map_table_result_t&);

template <class Archive> void save(Archive&, const npl_pdoq_oq_ifc_mapping_result_t&);
template <class Archive> void load(Archive&, npl_pdoq_oq_ifc_mapping_result_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_bank_pair_offset_result_t&);
template <class Archive> void load(Archive&, npl_pdvoq_bank_pair_offset_result_t&);

template <class Archive> void save(Archive&, const npl_pdvoq_slice_voq_properties_result_t&);
template <class Archive> void load(Archive&, npl_pdvoq_slice_voq_properties_result_t&);

template <class Archive> void save(Archive&, const npl_pfc_em_lookup_t&);
template <class Archive> void load(Archive&, npl_pfc_em_lookup_t&);

template <class Archive> void save(Archive&, const npl_pfc_latency_t&);
template <class Archive> void load(Archive&, npl_pfc_latency_t&);

template <class Archive> void save(Archive&, const npl_pfc_quanta_table_result_t&);
template <class Archive> void load(Archive&, npl_pfc_quanta_table_result_t&);

template <class Archive> void save(Archive&, const npl_pfc_rx_counter_offset_t&);
template <class Archive> void load(Archive&, npl_pfc_rx_counter_offset_t&);

template <class Archive> void save(Archive&, const npl_pfc_ssp_info_table_t&);
template <class Archive> void load(Archive&, npl_pfc_ssp_info_table_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_pma_loopback_data_t&);
template <class Archive> void load(Archive&, npl_pma_loopback_data_t&);

template <class Archive> void save(Archive&, const npl_port_dspa_table_result_t&);
template <class Archive> void load(Archive&, npl_port_dspa_table_result_t&);

template <class Archive> void save(Archive&, const npl_port_npp_protection_table_result_protected_t&);
template <class Archive> void load(Archive&, npl_port_npp_protection_table_result_protected_t&);

template <class Archive> void save(Archive&, const npl_port_protection_id_t&);
template <class Archive> void load(Archive&, npl_port_protection_id_t&);

template <class Archive> void save(Archive&, const npl_protection_selector_t&);
template <class Archive> void load(Archive&, npl_protection_selector_t&);

template <class Archive> void save(Archive&, const npl_punt_nw_encap_ptr_t&);
template <class Archive> void load(Archive&, npl_punt_nw_encap_ptr_t&);

template <class Archive> void save(Archive&, const npl_resolution_type_decoding_table_result_t&);
template <class Archive> void load(Archive&, npl_resolution_type_decoding_table_result_t&);

template <class Archive> void save(Archive&, const npl_select_macros_t&);
template <class Archive> void load(Archive&, npl_select_macros_t&);

template <class Archive> void save(Archive&, const npl_tunnel_dlp_t&);
template <class Archive> void load(Archive&, npl_tunnel_dlp_t&);

template <class Archive> void save(Archive&, const npl_vpn_label_encap_data_t&);
template <class Archive> void load(Archive&, npl_vpn_label_encap_data_t&);

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
class serializer_class<npl_path_lb_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_type_decoding_table_key_t& m)
{
    serializer_class<npl_path_lb_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_type_decoding_table_key_t& m)
{
    serializer_class<npl_path_lb_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_type_decoding_table_key_t&);



template<>
class serializer_class<npl_path_lb_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_type_decoding_table_value_t& m)
{
    serializer_class<npl_path_lb_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_type_decoding_table_value_t& m)
{
    serializer_class<npl_path_lb_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_type_decoding_table_value_t&);



template<>
class serializer_class<npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lb_type_decoding_table_result", m.path_lb_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lb_type_decoding_table_result", m.path_lb_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lb_type_decoding_table_value_t::npl_path_lb_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_path_lp_is_pbts_prefix_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_is_pbts_prefix_table_key_t& m) {
        uint64_t m_prefix = m.prefix;
            archive(::cereal::make_nvp("prefix", m_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_is_pbts_prefix_table_key_t& m) {
        uint64_t m_prefix;
            archive(::cereal::make_nvp("prefix", m_prefix));
        m.prefix = m_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_is_pbts_prefix_table_key_t& m)
{
    serializer_class<npl_path_lp_is_pbts_prefix_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_is_pbts_prefix_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_is_pbts_prefix_table_key_t& m)
{
    serializer_class<npl_path_lp_is_pbts_prefix_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_is_pbts_prefix_table_key_t&);



template<>
class serializer_class<npl_path_lp_is_pbts_prefix_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_is_pbts_prefix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_is_pbts_prefix_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_is_pbts_prefix_table_value_t& m)
{
    serializer_class<npl_path_lp_is_pbts_prefix_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_is_pbts_prefix_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_is_pbts_prefix_table_value_t& m)
{
    serializer_class<npl_path_lp_is_pbts_prefix_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_is_pbts_prefix_table_value_t&);



template<>
class serializer_class<npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lp_is_pbts_prefix_table_result", m.path_lp_is_pbts_prefix_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lp_is_pbts_prefix_table_result", m.path_lp_is_pbts_prefix_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t& m)
{
    serializer_class<npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t& m)
{
    serializer_class<npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_is_pbts_prefix_table_value_t::npl_path_lp_is_pbts_prefix_table_payloads_t&);



template<>
class serializer_class<npl_path_lp_pbts_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_pbts_map_table_key_t& m) {
            archive(::cereal::make_nvp("pbts_map_key", m.pbts_map_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_pbts_map_table_key_t& m) {
            archive(::cereal::make_nvp("pbts_map_key", m.pbts_map_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_pbts_map_table_key_t& m)
{
    serializer_class<npl_path_lp_pbts_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_pbts_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_pbts_map_table_key_t& m)
{
    serializer_class<npl_path_lp_pbts_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_pbts_map_table_key_t&);



template<>
class serializer_class<npl_path_lp_pbts_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_pbts_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_pbts_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_pbts_map_table_value_t& m)
{
    serializer_class<npl_path_lp_pbts_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_pbts_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_pbts_map_table_value_t& m)
{
    serializer_class<npl_path_lp_pbts_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_pbts_map_table_value_t&);



template<>
class serializer_class<npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lp_pbts_map_table_result", m.path_lp_pbts_map_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lp_pbts_map_table_result", m.path_lp_pbts_map_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t& m)
{
    serializer_class<npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t& m)
{
    serializer_class<npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_pbts_map_table_value_t::npl_path_lp_pbts_map_table_payloads_t&);



template<>
class serializer_class<npl_path_lp_table_narrow_entry_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_narrow_entry_payload_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_narrow_entry_payload_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_narrow_entry_payload_t& m)
{
    serializer_class<npl_path_lp_table_narrow_entry_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_narrow_entry_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_narrow_entry_payload_t& m)
{
    serializer_class<npl_path_lp_table_narrow_entry_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_narrow_entry_payload_t&);



template<>
class serializer_class<npl_path_lp_table_protected_entry_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_protected_entry_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_protected_entry_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_protected_entry_payload_t& m)
{
    serializer_class<npl_path_lp_table_protected_entry_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_protected_entry_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_protected_entry_payload_t& m)
{
    serializer_class<npl_path_lp_table_protected_entry_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_protected_entry_payload_t&);



template<>
class serializer_class<npl_path_lp_table_wide_entry_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_wide_entry_payload_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_wide_entry_payload_t& m) {
            archive(::cereal::make_nvp("entry", m.entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_wide_entry_payload_t& m)
{
    serializer_class<npl_path_lp_table_wide_entry_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_wide_entry_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_wide_entry_payload_t& m)
{
    serializer_class<npl_path_lp_table_wide_entry_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_wide_entry_payload_t&);



template<>
class serializer_class<npl_path_lp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_key_t& m) {
            archive(::cereal::make_nvp("tunnel_dlp", m.tunnel_dlp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_key_t& m) {
            archive(::cereal::make_nvp("tunnel_dlp", m.tunnel_dlp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_key_t& m)
{
    serializer_class<npl_path_lp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_key_t& m)
{
    serializer_class<npl_path_lp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_key_t&);



template<>
class serializer_class<npl_path_lp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_value_t& m)
{
    serializer_class<npl_path_lp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_value_t& m)
{
    serializer_class<npl_path_lp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_value_t&);



template<>
class serializer_class<npl_path_lp_table_value_t::npl_path_lp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_table_value_t::npl_path_lp_table_payloads_t& m) {
            archive(::cereal::make_nvp("narrow_entry", m.narrow_entry));
            archive(::cereal::make_nvp("protected_entry", m.protected_entry));
            archive(::cereal::make_nvp("wide_entry", m.wide_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_table_value_t::npl_path_lp_table_payloads_t& m) {
            archive(::cereal::make_nvp("narrow_entry", m.narrow_entry));
            archive(::cereal::make_nvp("protected_entry", m.protected_entry));
            archive(::cereal::make_nvp("wide_entry", m.wide_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_table_value_t::npl_path_lp_table_payloads_t& m)
{
    serializer_class<npl_path_lp_table_value_t::npl_path_lp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_table_value_t::npl_path_lp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_table_value_t::npl_path_lp_table_payloads_t& m)
{
    serializer_class<npl_path_lp_table_value_t::npl_path_lp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_table_value_t::npl_path_lp_table_payloads_t&);



template<>
class serializer_class<npl_path_lp_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_type_decoding_table_key_t& m)
{
    serializer_class<npl_path_lp_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_type_decoding_table_key_t& m)
{
    serializer_class<npl_path_lp_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_type_decoding_table_key_t&);



template<>
class serializer_class<npl_path_lp_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_type_decoding_table_value_t& m)
{
    serializer_class<npl_path_lp_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_type_decoding_table_value_t& m)
{
    serializer_class<npl_path_lp_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_type_decoding_table_value_t&);



template<>
class serializer_class<npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lp_type_decoding_table_result", m.path_lp_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_lp_type_decoding_table_result", m.path_lp_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_lp_type_decoding_table_value_t::npl_path_lp_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_path_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_protection_table_key_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_protection_table_key_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_protection_table_key_t& m)
{
    serializer_class<npl_path_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_path_protection_table_key_t& m)
{
    serializer_class<npl_path_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_protection_table_key_t&);



template<>
class serializer_class<npl_path_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_protection_table_value_t& m)
{
    serializer_class<npl_path_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_path_protection_table_value_t& m)
{
    serializer_class<npl_path_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_protection_table_value_t&);



template<>
class serializer_class<npl_path_protection_table_value_t::npl_path_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_path_protection_table_value_t::npl_path_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_protection_table_result", m.path_protection_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_path_protection_table_value_t::npl_path_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("path_protection_table_result", m.path_protection_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_path_protection_table_value_t::npl_path_protection_table_payloads_t& m)
{
    serializer_class<npl_path_protection_table_value_t::npl_path_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_path_protection_table_value_t::npl_path_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_path_protection_table_value_t::npl_path_protection_table_payloads_t& m)
{
    serializer_class<npl_path_protection_table_value_t::npl_path_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_path_protection_table_value_t::npl_path_protection_table_payloads_t&);



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
class serializer_class<npl_pfc_event_queue_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_event_queue_table_key_t& m) {
        uint64_t m_slice = m.slice;
        uint64_t m_tc = m.tc;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("slice", m_slice));
            archive(::cereal::make_nvp("cong_state", m.cong_state));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_event_queue_table_key_t& m) {
        uint64_t m_slice;
        uint64_t m_tc;
        uint64_t m_destination;
            archive(::cereal::make_nvp("slice", m_slice));
            archive(::cereal::make_nvp("cong_state", m.cong_state));
            archive(::cereal::make_nvp("tc", m_tc));
            archive(::cereal::make_nvp("destination", m_destination));
        m.slice = m_slice;
        m.tc = m_tc;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_event_queue_table_key_t& m)
{
    serializer_class<npl_pfc_event_queue_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_event_queue_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_event_queue_table_key_t& m)
{
    serializer_class<npl_pfc_event_queue_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_event_queue_table_key_t&);



template<>
class serializer_class<npl_pfc_event_queue_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_event_queue_table_value_t& m)
{
    serializer_class<npl_pfc_event_queue_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_event_queue_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_event_queue_table_value_t& m)
{
    serializer_class<npl_pfc_event_queue_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_event_queue_table_value_t&);



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
class serializer_class<npl_pfc_tc_latency_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_latency_table_key_t& m) {
        uint64_t m_tc = m.tc;
            archive(::cereal::make_nvp("tc", m_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_latency_table_key_t& m) {
        uint64_t m_tc;
            archive(::cereal::make_nvp("tc", m_tc));
        m.tc = m_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_latency_table_key_t& m)
{
    serializer_class<npl_pfc_tc_latency_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_latency_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_latency_table_key_t& m)
{
    serializer_class<npl_pfc_tc_latency_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_latency_table_key_t&);



template<>
class serializer_class<npl_pfc_tc_latency_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_latency_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_latency_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_latency_table_value_t& m)
{
    serializer_class<npl_pfc_tc_latency_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_latency_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_latency_table_value_t& m)
{
    serializer_class<npl_pfc_tc_latency_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_latency_table_value_t&);



template<>
class serializer_class<npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_latency_threshold", m.pfc_latency_threshold));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_latency_threshold", m.pfc_latency_threshold));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t& m)
{
    serializer_class<npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t& m)
{
    serializer_class<npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_latency_table_value_t::npl_pfc_tc_latency_table_payloads_t&);



template<>
class serializer_class<npl_pfc_tc_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_table_key_t& m) {
        uint64_t m_profile = m.profile;
        uint64_t m_index = m.index;
            archive(::cereal::make_nvp("profile", m_profile));
            archive(::cereal::make_nvp("index", m_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_table_key_t& m) {
        uint64_t m_profile;
        uint64_t m_index;
            archive(::cereal::make_nvp("profile", m_profile));
            archive(::cereal::make_nvp("index", m_index));
        m.profile = m_profile;
        m.index = m_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_table_key_t& m)
{
    serializer_class<npl_pfc_tc_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_table_key_t& m)
{
    serializer_class<npl_pfc_tc_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_table_key_t&);



template<>
class serializer_class<npl_pfc_tc_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_table_value_t& m)
{
    serializer_class<npl_pfc_tc_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_table_value_t& m)
{
    serializer_class<npl_pfc_tc_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_table_value_t&);



template<>
class serializer_class<npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_quanta_result", m.pfc_quanta_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_quanta_result", m.pfc_quanta_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t& m)
{
    serializer_class<npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t& m)
{
    serializer_class<npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_table_value_t::npl_pfc_tc_table_payloads_t&);



template<>
class serializer_class<npl_pfc_tc_wrap_latency_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_wrap_latency_table_key_t& m) {
        uint64_t m_tc = m.tc;
            archive(::cereal::make_nvp("tc", m_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_wrap_latency_table_key_t& m) {
        uint64_t m_tc;
            archive(::cereal::make_nvp("tc", m_tc));
        m.tc = m_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_wrap_latency_table_key_t& m)
{
    serializer_class<npl_pfc_tc_wrap_latency_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_wrap_latency_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_wrap_latency_table_key_t& m)
{
    serializer_class<npl_pfc_tc_wrap_latency_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_wrap_latency_table_key_t&);



template<>
class serializer_class<npl_pfc_tc_wrap_latency_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_wrap_latency_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_wrap_latency_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_wrap_latency_table_value_t& m)
{
    serializer_class<npl_pfc_tc_wrap_latency_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_wrap_latency_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_wrap_latency_table_value_t& m)
{
    serializer_class<npl_pfc_tc_wrap_latency_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_wrap_latency_table_value_t&);



template<>
class serializer_class<npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_wrap_latency_threshold", m.pfc_wrap_latency_threshold));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t& m) {
            archive(::cereal::make_nvp("pfc_wrap_latency_threshold", m.pfc_wrap_latency_threshold));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t& m)
{
    serializer_class<npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t& m)
{
    serializer_class<npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_tc_wrap_latency_table_value_t::npl_pfc_tc_wrap_latency_table_payloads_t&);



template<>
class serializer_class<npl_pfc_vector_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_vector_static_table_key_t& m) {
        uint64_t m_tc = m.tc;
            archive(::cereal::make_nvp("tc", m_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_vector_static_table_key_t& m) {
        uint64_t m_tc;
            archive(::cereal::make_nvp("tc", m_tc));
        m.tc = m_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_vector_static_table_key_t& m)
{
    serializer_class<npl_pfc_vector_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_vector_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_vector_static_table_key_t& m)
{
    serializer_class<npl_pfc_vector_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_vector_static_table_key_t&);



template<>
class serializer_class<npl_pfc_vector_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_vector_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_vector_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_vector_static_table_value_t& m)
{
    serializer_class<npl_pfc_vector_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_vector_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_vector_static_table_value_t& m)
{
    serializer_class<npl_pfc_vector_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_vector_static_table_value_t&);



template<>
class serializer_class<npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t& m) {
        uint64_t m_pd_pd_npu_host_receive_fields_pfc_priority_table_vector = m.pd_pd_npu_host_receive_fields_pfc_priority_table_vector;
            archive(::cereal::make_nvp("pd_pd_npu_host_receive_fields_pfc_priority_table_vector", m_pd_pd_npu_host_receive_fields_pfc_priority_table_vector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t& m) {
        uint64_t m_pd_pd_npu_host_receive_fields_pfc_priority_table_vector;
            archive(::cereal::make_nvp("pd_pd_npu_host_receive_fields_pfc_priority_table_vector", m_pd_pd_npu_host_receive_fields_pfc_priority_table_vector));
        m.pd_pd_npu_host_receive_fields_pfc_priority_table_vector = m_pd_pd_npu_host_receive_fields_pfc_priority_table_vector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t& m)
{
    serializer_class<npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t& m)
{
    serializer_class<npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_pfc_vector_static_table_value_t::npl_pfc_vector_static_table_payloads_t&);



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
class serializer_class<npl_port_dspa_group_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_group_size_table_key_t& m) {
        uint64_t m_dspa = m.dspa;
            archive(::cereal::make_nvp("dspa", m_dspa));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_group_size_table_key_t& m) {
        uint64_t m_dspa;
            archive(::cereal::make_nvp("dspa", m_dspa));
        m.dspa = m_dspa;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_group_size_table_key_t& m)
{
    serializer_class<npl_port_dspa_group_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_group_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_group_size_table_key_t& m)
{
    serializer_class<npl_port_dspa_group_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_group_size_table_key_t&);



template<>
class serializer_class<npl_port_dspa_group_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_group_size_table_value_t& m)
{
    serializer_class<npl_port_dspa_group_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_group_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_group_size_table_value_t& m)
{
    serializer_class<npl_port_dspa_group_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_group_size_table_value_t&);



template<>
class serializer_class<npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("dspa_group_size_table_result", m.dspa_group_size_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("dspa_group_size_table_result", m.dspa_group_size_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t& m)
{
    serializer_class<npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t& m)
{
    serializer_class<npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_group_size_table_value_t::npl_port_dspa_group_size_table_payloads_t&);



template<>
class serializer_class<npl_port_dspa_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_table_key_t& m) {
        uint64_t m_member_id = m.member_id;
        uint64_t m_group_id = m.group_id;
            archive(::cereal::make_nvp("member_id", m_member_id));
            archive(::cereal::make_nvp("group_id", m_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_table_key_t& m) {
        uint64_t m_member_id;
        uint64_t m_group_id;
            archive(::cereal::make_nvp("member_id", m_member_id));
            archive(::cereal::make_nvp("group_id", m_group_id));
        m.member_id = m_member_id;
        m.group_id = m_group_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_table_key_t& m)
{
    serializer_class<npl_port_dspa_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_table_key_t& m)
{
    serializer_class<npl_port_dspa_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_table_key_t&);



template<>
class serializer_class<npl_port_dspa_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_table_value_t& m)
{
    serializer_class<npl_port_dspa_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_table_value_t& m)
{
    serializer_class<npl_port_dspa_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_table_value_t&);



template<>
class serializer_class<npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_dspa_result", m.port_dspa_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_dspa_result", m.port_dspa_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t& m)
{
    serializer_class<npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t& m)
{
    serializer_class<npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_table_value_t::npl_port_dspa_table_payloads_t&);



template<>
class serializer_class<npl_port_dspa_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_type_decoding_table_key_t& m)
{
    serializer_class<npl_port_dspa_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_type_decoding_table_key_t& m)
{
    serializer_class<npl_port_dspa_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_type_decoding_table_key_t&);



template<>
class serializer_class<npl_port_dspa_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_type_decoding_table_value_t& m)
{
    serializer_class<npl_port_dspa_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_type_decoding_table_value_t& m)
{
    serializer_class<npl_port_dspa_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_type_decoding_table_value_t&);



template<>
class serializer_class<npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_dspa_type_decoding_table_result", m.port_dspa_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_dspa_type_decoding_table_result", m.port_dspa_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_dspa_type_decoding_table_value_t::npl_port_dspa_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_port_npp_protection_table_protected_data_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_table_protected_data_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_table_protected_data_payload_t& m) {
            archive(::cereal::make_nvp("data", m.data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_table_protected_data_payload_t& m)
{
    serializer_class<npl_port_npp_protection_table_protected_data_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_table_protected_data_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_table_protected_data_payload_t& m)
{
    serializer_class<npl_port_npp_protection_table_protected_data_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_table_protected_data_payload_t&);



template<>
class serializer_class<npl_port_npp_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_table_key_t& m) {
            archive(::cereal::make_nvp("npp_protection_id", m.npp_protection_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_table_key_t& m) {
            archive(::cereal::make_nvp("npp_protection_id", m.npp_protection_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_table_key_t& m)
{
    serializer_class<npl_port_npp_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_table_key_t& m)
{
    serializer_class<npl_port_npp_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_table_key_t&);



template<>
class serializer_class<npl_port_npp_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_table_value_t& m)
{
    serializer_class<npl_port_npp_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_table_value_t& m)
{
    serializer_class<npl_port_npp_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_table_value_t&);



template<>
class serializer_class<npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("protected_data", m.protected_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("protected_data", m.protected_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t& m)
{
    serializer_class<npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t& m)
{
    serializer_class<npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_table_value_t::npl_port_npp_protection_table_payloads_t&);



template<>
class serializer_class<npl_port_npp_protection_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_type_decoding_table_key_t& m)
{
    serializer_class<npl_port_npp_protection_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_type_decoding_table_key_t& m)
{
    serializer_class<npl_port_npp_protection_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_type_decoding_table_key_t&);



template<>
class serializer_class<npl_port_npp_protection_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_type_decoding_table_value_t& m)
{
    serializer_class<npl_port_npp_protection_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_type_decoding_table_value_t& m)
{
    serializer_class<npl_port_npp_protection_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_type_decoding_table_value_t&);



template<>
class serializer_class<npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_npp_protection_type_decoding_table_result", m.port_npp_protection_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_npp_protection_type_decoding_table_result", m.port_npp_protection_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_npp_protection_type_decoding_table_value_t::npl_port_npp_protection_type_decoding_table_payloads_t&);



template<>
class serializer_class<npl_port_protection_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_protection_table_key_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_protection_table_key_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_protection_table_key_t& m)
{
    serializer_class<npl_port_protection_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_protection_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_port_protection_table_key_t& m)
{
    serializer_class<npl_port_protection_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_protection_table_key_t&);



template<>
class serializer_class<npl_port_protection_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_protection_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_protection_table_value_t& m)
{
    serializer_class<npl_port_protection_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_protection_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_port_protection_table_value_t& m)
{
    serializer_class<npl_port_protection_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_protection_table_value_t&);



template<>
class serializer_class<npl_port_protection_table_value_t::npl_port_protection_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_port_protection_table_value_t::npl_port_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_protection_table_result", m.port_protection_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_port_protection_table_value_t::npl_port_protection_table_payloads_t& m) {
            archive(::cereal::make_nvp("port_protection_table_result", m.port_protection_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_port_protection_table_value_t::npl_port_protection_table_payloads_t& m)
{
    serializer_class<npl_port_protection_table_value_t::npl_port_protection_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_port_protection_table_value_t::npl_port_protection_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_port_protection_table_value_t::npl_port_protection_table_payloads_t& m)
{
    serializer_class<npl_port_protection_table_value_t::npl_port_protection_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_port_protection_table_value_t::npl_port_protection_table_payloads_t&);



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



}

