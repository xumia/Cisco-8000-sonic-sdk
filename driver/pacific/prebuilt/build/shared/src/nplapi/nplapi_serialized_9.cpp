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

template <class Archive> void save(Archive&, const npl_common_cntr_offset_and_padding_t&);
template <class Archive> void load(Archive&, npl_common_cntr_offset_and_padding_t&);

template <class Archive> void save(Archive&, const npl_counter_offset_t&);
template <class Archive> void load(Archive&, npl_counter_offset_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_ifg_t&);
template <class Archive> void load(Archive&, npl_ifg_t&);

template <class Archive> void save(Archive&, const npl_inject_header_type_t&);
template <class Archive> void load(Archive&, npl_inject_header_type_t&);

template <class Archive> void save(Archive&, const npl_l3_slp_id_t&);
template <class Archive> void load(Archive&, npl_l3_slp_id_t&);

template <class Archive> void save(Archive&, const npl_lb_group_size_table_result_t&);
template <class Archive> void load(Archive&, npl_lb_group_size_table_result_t&);

template <class Archive> void save(Archive&, const npl_lm_command_t&);
template <class Archive> void load(Archive&, npl_lm_command_t&);

template <class Archive> void save(Archive&, const npl_lp_id_t&);
template <class Archive> void load(Archive&, npl_lp_id_t&);

template <class Archive> void save(Archive&, const npl_lsp_encap_mapping_data_payload_t&);
template <class Archive> void load(Archive&, npl_lsp_encap_mapping_data_payload_t&);

template <class Archive> void save(Archive&, const npl_mac_lp_attributes_table_payload_t&);
template <class Archive> void load(Archive&, npl_mac_lp_attributes_table_payload_t&);

template <class Archive> void save(Archive&, const npl_oqse_pair_t&);
template <class Archive> void load(Archive&, npl_oqse_pair_t&);

template <class Archive> void save(Archive&, const npl_pcp_dei_t&);
template <class Archive> void load(Archive&, npl_pcp_dei_t&);

template <class Archive> void save(Archive&, const npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t&);
template <class Archive> void load(Archive&, npl_pd_rx_nw_app_t_anonymous_union_init_fields_union_t&);

template <class Archive> void save(Archive&, const npl_relay_attr_table_payload_t&);
template <class Archive> void load(Archive&, npl_relay_attr_table_payload_t&);

template <class Archive> void save(Archive&, const npl_relay_id_t&);
template <class Archive> void load(Archive&, npl_relay_id_t&);

template <class Archive> void save(Archive&, const npl_resolution_type_decoding_table_result_t&);
template <class Archive> void load(Archive&, npl_resolution_type_decoding_table_result_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_lookup_table_entry_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_lookup_table_entry_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_tc_map_result_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_tc_map_result_t&);

template <class Archive> void save(Archive&, const npl_sch_oqse_cfg_result_t&);
template <class Archive> void load(Archive&, npl_sch_oqse_cfg_result_t&);

template <class Archive> void save(Archive&, const npl_sgacl_payload_t&);
template <class Archive> void load(Archive&, npl_sgacl_payload_t&);

template <class Archive> void save(Archive&, const npl_slp_fwd_result_t&);
template <class Archive> void load(Archive&, npl_slp_fwd_result_t&);

template <class Archive> void save(Archive&, const npl_snoop_code_t&);
template <class Archive> void load(Archive&, npl_snoop_code_t&);

template <class Archive> void save(Archive&, const npl_stage2_lb_table_result_t&);
template <class Archive> void load(Archive&, npl_stage2_lb_table_result_t&);

template <class Archive> void save(Archive&, const npl_stage3_lb_table_result_t&);
template <class Archive> void load(Archive&, npl_stage3_lb_table_result_t&);

template <class Archive> void save(Archive&, const npl_trap_conditions_t&);
template <class Archive> void load(Archive&, npl_trap_conditions_t&);

template <class Archive> void save(Archive&, const npl_traps_t&);
template <class Archive> void load(Archive&, npl_traps_t&);

template <class Archive> void save(Archive&, const npl_ts_cmd_trans_t&);
template <class Archive> void load(Archive&, npl_ts_cmd_trans_t&);

template <class Archive> void save(Archive&, const npl_ts_command_t&);
template <class Archive> void load(Archive&, npl_ts_command_t&);

template <class Archive> void save(Archive&, const npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t&);
template <class Archive> void load(Archive&, npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t&);

template <class Archive> void save(Archive&, const npl_tx_punt_nw_encap_ptr_t&);
template <class Archive> void load(Archive&, npl_tx_punt_nw_encap_ptr_t&);

template <class Archive> void save(Archive&, const npl_vlan_id_t&);
template <class Archive> void load(Archive&, npl_vlan_id_t&);

template<>
class serializer_class<npl_rx_term_error_handling_destination_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_term_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_destination_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_destination_table_update_result_payload_t&);



template<>
class serializer_class<npl_rx_term_error_handling_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_destination_table_key_t& m) {
        uint64_t m_ser = m.ser;
            archive(::cereal::make_nvp("ser", m_ser));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_destination_table_key_t& m) {
        uint64_t m_ser;
            archive(::cereal::make_nvp("ser", m_ser));
        m.ser = m_ser;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_term_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_destination_table_key_t&);



template<>
class serializer_class<npl_rx_term_error_handling_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_term_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_destination_table_value_t&);



template<>
class serializer_class<npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_destination_table_value_t::npl_rx_term_error_handling_destination_table_payloads_t&);



template<>
class serializer_class<npl_rxpdr_dsp_lookup_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_lookup_table_key_t& m) {
        uint64_t m_fwd_destination_lsb = m.fwd_destination_lsb;
            archive(::cereal::make_nvp("fwd_destination_lsb", m_fwd_destination_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_lookup_table_key_t& m) {
        uint64_t m_fwd_destination_lsb;
            archive(::cereal::make_nvp("fwd_destination_lsb", m_fwd_destination_lsb));
        m.fwd_destination_lsb = m_fwd_destination_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_lookup_table_key_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_lookup_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_lookup_table_key_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_lookup_table_key_t&);



template<>
class serializer_class<npl_rxpdr_dsp_lookup_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_lookup_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_lookup_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_lookup_table_value_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_lookup_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_lookup_table_value_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_lookup_table_value_t&);



template<>
class serializer_class<npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t& m) {
            archive(::cereal::make_nvp("rxpdr_dsp_lookup_table_result", m.rxpdr_dsp_lookup_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t& m) {
            archive(::cereal::make_nvp("rxpdr_dsp_lookup_table_result", m.rxpdr_dsp_lookup_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t& m)
{
    serializer_class<npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_lookup_table_value_t::npl_rxpdr_dsp_lookup_table_payloads_t&);



template<>
class serializer_class<npl_rxpdr_dsp_tc_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_tc_map_key_t& m) {
        uint64_t m_rxpdr_dsp_lookup_table_result_tc_map_profile = m.rxpdr_dsp_lookup_table_result_tc_map_profile;
        uint64_t m_rxpp_pd_tc = m.rxpp_pd_tc;
            archive(::cereal::make_nvp("rxpdr_dsp_lookup_table_result_tc_map_profile", m_rxpdr_dsp_lookup_table_result_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_tc_map_key_t& m) {
        uint64_t m_rxpdr_dsp_lookup_table_result_tc_map_profile;
        uint64_t m_rxpp_pd_tc;
            archive(::cereal::make_nvp("rxpdr_dsp_lookup_table_result_tc_map_profile", m_rxpdr_dsp_lookup_table_result_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
        m.rxpdr_dsp_lookup_table_result_tc_map_profile = m_rxpdr_dsp_lookup_table_result_tc_map_profile;
        m.rxpp_pd_tc = m_rxpp_pd_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_tc_map_key_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_tc_map_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_tc_map_key_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_tc_map_key_t&);



template<>
class serializer_class<npl_rxpdr_dsp_tc_map_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_tc_map_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_tc_map_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_tc_map_value_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_tc_map_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_tc_map_value_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_tc_map_value_t&);



template<>
class serializer_class<npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t& m) {
            archive(::cereal::make_nvp("rxpdr_dsp_tc_map_result", m.rxpdr_dsp_tc_map_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t& m) {
            archive(::cereal::make_nvp("rxpdr_dsp_tc_map_result", m.rxpdr_dsp_tc_map_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t& m)
{
    serializer_class<npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_dsp_tc_map_value_t::npl_rxpdr_dsp_tc_map_payloads_t&);



template<>
class serializer_class<npl_sch_oqse_cfg_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sch_oqse_cfg_key_t& m) {
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("oqse_pair_index", m.oqse_pair_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sch_oqse_cfg_key_t& m) {
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("oqse_pair_index", m.oqse_pair_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sch_oqse_cfg_key_t& m)
{
    serializer_class<npl_sch_oqse_cfg_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sch_oqse_cfg_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sch_oqse_cfg_key_t& m)
{
    serializer_class<npl_sch_oqse_cfg_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sch_oqse_cfg_key_t&);



template<>
class serializer_class<npl_sch_oqse_cfg_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sch_oqse_cfg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sch_oqse_cfg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sch_oqse_cfg_value_t& m)
{
    serializer_class<npl_sch_oqse_cfg_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sch_oqse_cfg_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sch_oqse_cfg_value_t& m)
{
    serializer_class<npl_sch_oqse_cfg_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sch_oqse_cfg_value_t&);



template<>
class serializer_class<npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t& m) {
            archive(::cereal::make_nvp("sch_oqse_cfg_result", m.sch_oqse_cfg_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t& m) {
            archive(::cereal::make_nvp("sch_oqse_cfg_result", m.sch_oqse_cfg_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t& m)
{
    serializer_class<npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t& m)
{
    serializer_class<npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sch_oqse_cfg_value_t::npl_sch_oqse_cfg_payloads_t&);



template<>
class serializer_class<npl_second_ene_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_second_ene_static_table_key_t& m) {
        uint64_t m_second_ene_macro_code = m.second_ene_macro_code;
            archive(::cereal::make_nvp("second_ene_macro_code", m_second_ene_macro_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_second_ene_static_table_key_t& m) {
        uint64_t m_second_ene_macro_code;
            archive(::cereal::make_nvp("second_ene_macro_code", m_second_ene_macro_code));
        m.second_ene_macro_code = m_second_ene_macro_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_second_ene_static_table_key_t& m)
{
    serializer_class<npl_second_ene_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_second_ene_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_second_ene_static_table_key_t& m)
{
    serializer_class<npl_second_ene_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_second_ene_static_table_key_t&);



template<>
class serializer_class<npl_second_ene_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_second_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_second_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_second_ene_static_table_value_t& m)
{
    serializer_class<npl_second_ene_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_second_ene_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_second_ene_static_table_value_t& m)
{
    serializer_class<npl_second_ene_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_second_ene_static_table_value_t&);



template<>
class serializer_class<npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("second_ene_macro", m.second_ene_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("second_ene_macro", m.second_ene_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t& m)
{
    serializer_class<npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t& m)
{
    serializer_class<npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_second_ene_static_table_value_t::npl_second_ene_static_table_payloads_t&);



template<>
class serializer_class<npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t& m) {
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
save(Archive& archive, const npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_inject_next_macro_static_table_rx_inject_up_next_macro_payload_t&);



template<>
class serializer_class<npl_select_inject_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_inject_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("local_inject_type_7_0_", m.local_inject_type_7_0_));
            archive(::cereal::make_nvp("protocol", m.protocol));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_inject_next_macro_static_table_key_t& m) {
            archive(::cereal::make_nvp("local_inject_type_7_0_", m.local_inject_type_7_0_));
            archive(::cereal::make_nvp("protocol", m.protocol));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_select_inject_next_macro_static_table_key_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_inject_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_select_inject_next_macro_static_table_key_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_inject_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_select_inject_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_inject_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_inject_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_select_inject_next_macro_static_table_value_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_inject_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_select_inject_next_macro_static_table_value_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_inject_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_inject_up_next_macro", m.rx_inject_up_next_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_inject_up_next_macro", m.rx_inject_up_next_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_inject_next_macro_static_table_value_t::npl_select_inject_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_service_lp_attributes_table_write_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_lp_attributes_table_write_payload_t& m) {
            archive(::cereal::make_nvp("mac_lp_attributes_payload", m.mac_lp_attributes_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_lp_attributes_table_write_payload_t& m) {
            archive(::cereal::make_nvp("mac_lp_attributes_payload", m.mac_lp_attributes_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_lp_attributes_table_write_payload_t& m)
{
    serializer_class<npl_service_lp_attributes_table_write_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_lp_attributes_table_write_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_lp_attributes_table_write_payload_t& m)
{
    serializer_class<npl_service_lp_attributes_table_write_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_lp_attributes_table_write_payload_t&);



template<>
class serializer_class<npl_service_lp_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_lp_attributes_table_key_t& m) {
            archive(::cereal::make_nvp("service_lp_attributes_table_key", m.service_lp_attributes_table_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_lp_attributes_table_key_t& m) {
            archive(::cereal::make_nvp("service_lp_attributes_table_key", m.service_lp_attributes_table_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_lp_attributes_table_key_t& m)
{
    serializer_class<npl_service_lp_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_lp_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_lp_attributes_table_key_t& m)
{
    serializer_class<npl_service_lp_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_lp_attributes_table_key_t&);



template<>
class serializer_class<npl_service_lp_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_lp_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_lp_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_lp_attributes_table_value_t& m)
{
    serializer_class<npl_service_lp_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_lp_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_lp_attributes_table_value_t& m)
{
    serializer_class<npl_service_lp_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_lp_attributes_table_value_t&);



template<>
class serializer_class<npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("write", m.write));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("write", m.write));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t& m)
{
    serializer_class<npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t& m)
{
    serializer_class<npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_lp_attributes_table_value_t::npl_service_lp_attributes_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_table_key_t& m) {
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_table_key_t& m) {
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_table_key_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_table_value_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_table_key_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_table_value_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_tag_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid2", m.vid2));
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid2", m.vid2));
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_tag_table_key_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_tag_table_value_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_em0_pwe_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_pwe_tag_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_pwe_tag_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_em0_pwe_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_pwe_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_pwe_tag_table_key_t&);



template<>
class serializer_class<npl_service_mapping_em0_pwe_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_pwe_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_pwe_tag_table_value_t&);



template<>
class serializer_class<npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_pwe_tag_table_value_t::npl_service_mapping_em0_pwe_tag_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_em1_ac_port_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_sm_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em1_ac_port_tag_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em1_ac_port_tag_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_em1_ac_port_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em1_ac_port_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em1_ac_port_tag_table_key_t&);



template<>
class serializer_class<npl_service_mapping_em1_ac_port_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em1_ac_port_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em1_ac_port_tag_table_value_t&);



template<>
class serializer_class<npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em1_ac_port_tag_table_value_t::npl_service_mapping_em1_ac_port_tag_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_sm_payload_t& m) {
        uint64_t m_relay_id = m.relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
        m.relay_id = m_relay_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_key_t& m) {
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_table_key_t& m) {
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_table_key_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_table_value_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_table_value_t::npl_service_mapping_tcam_ac_port_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id = m.relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
        m.relay_id = m_relay_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_table_key_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_table_value_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id = m.relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
        m.relay_id = m_relay_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid2", m.vid2));
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid2", m.vid2));
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_tag_table_key_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t&);



template<>
class serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_ac_port_tag_tag_table_value_t::npl_service_mapping_tcam_ac_port_tag_tag_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_tcam_pwe_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id = m.relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
        m.relay_id = m_relay_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_sm_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_pwe_tag_table_sm_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_sm_payload_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_sm_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_pwe_tag_table_sm_payload_t&);



template<>
class serializer_class<npl_service_mapping_tcam_pwe_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_key_t& m) {
            archive(::cereal::make_nvp("vid1", m.vid1));
            archive(::cereal::make_nvp("local_slp_id", m.local_slp_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_pwe_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_pwe_tag_table_key_t&);



template<>
class serializer_class<npl_service_mapping_tcam_pwe_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_pwe_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_pwe_tag_table_value_t&);



template<>
class serializer_class<npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("sm", m.sm));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_pwe_tag_table_value_t::npl_service_mapping_tcam_pwe_tag_table_payloads_t&);



template<>
class serializer_class<npl_service_relay_attributes_table_relay_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_attributes_table_relay_payload_t& m) {
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_attributes_table_relay_payload_t& m) {
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_attributes_table_relay_payload_t& m)
{
    serializer_class<npl_service_relay_attributes_table_relay_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_attributes_table_relay_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_attributes_table_relay_payload_t& m)
{
    serializer_class<npl_service_relay_attributes_table_relay_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_attributes_table_relay_payload_t&);



template<>
class serializer_class<npl_service_relay_attributes_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_attributes_table_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_attributes_table_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_attributes_table_key_t& m)
{
    serializer_class<npl_service_relay_attributes_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_attributes_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_attributes_table_key_t& m)
{
    serializer_class<npl_service_relay_attributes_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_attributes_table_key_t&);



template<>
class serializer_class<npl_service_relay_attributes_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_attributes_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_attributes_table_value_t& m)
{
    serializer_class<npl_service_relay_attributes_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_attributes_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_attributes_table_value_t& m)
{
    serializer_class<npl_service_relay_attributes_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_attributes_table_value_t&);



template<>
class serializer_class<npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t& m)
{
    serializer_class<npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t& m)
{
    serializer_class<npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_attributes_table_value_t::npl_service_relay_attributes_table_payloads_t&);



template<>
class serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t& m) {
        uint64_t m_bytes_to_remove = m.bytes_to_remove;
            archive(::cereal::make_nvp("bytes_to_remove", m_bytes_to_remove));
            archive(::cereal::make_nvp("new_hdr_type", m.new_hdr_type));
            archive(::cereal::make_nvp("ene_macro_id", m.ene_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t& m) {
        uint64_t m_bytes_to_remove;
            archive(::cereal::make_nvp("bytes_to_remove", m_bytes_to_remove));
            archive(::cereal::make_nvp("new_hdr_type", m.new_hdr_type));
            archive(::cereal::make_nvp("ene_macro_id", m.ene_macro_id));
        m.bytes_to_remove = m_bytes_to_remove;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_set_ene_macro_and_bytes_to_remove_table_set_ene_macro_and_bytes_to_remove_table_payload_t&);



template<>
class serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_key_t& m) {
            archive(::cereal::make_nvp("hdr_type", m.hdr_type));
            archive(::cereal::make_nvp("plb_header_type", m.plb_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_key_t& m) {
            archive(::cereal::make_nvp("hdr_type", m.hdr_type));
            archive(::cereal::make_nvp("plb_header_type", m.plb_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_key_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_set_ene_macro_and_bytes_to_remove_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_key_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_set_ene_macro_and_bytes_to_remove_table_key_t&);



template<>
class serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_value_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_set_ene_macro_and_bytes_to_remove_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_value_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_set_ene_macro_and_bytes_to_remove_table_value_t&);



template<>
class serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_ene_macro_and_bytes_to_remove_table", m.set_ene_macro_and_bytes_to_remove_table));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_ene_macro_and_bytes_to_remove_table", m.set_ene_macro_and_bytes_to_remove_table));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t& m)
{
    serializer_class<npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_set_ene_macro_and_bytes_to_remove_table_value_t::npl_set_ene_macro_and_bytes_to_remove_table_payloads_t&);



template<>
class serializer_class<npl_sgacl_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_table_key_t& m)
{
    serializer_class<npl_sgacl_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_table_key_t& m)
{
    serializer_class<npl_sgacl_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_table_key_t&);



template<>
class serializer_class<npl_sgacl_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_table_value_t& m)
{
    serializer_class<npl_sgacl_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_table_value_t& m)
{
    serializer_class<npl_sgacl_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_table_value_t&);



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
        uint64_t m_np_macro_id = m.np_macro_id;
        uint64_t m_fi_macro_id = m.fi_macro_id;
            archive(::cereal::make_nvp("initial_layer_index", m_initial_layer_index));
            archive(::cereal::make_nvp("initial_rx_data", m.initial_rx_data));
            archive(::cereal::make_nvp("tag_swap_cmd", m.tag_swap_cmd));
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
            archive(::cereal::make_nvp("fi_macro_id", m_fi_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_source_pif_hw_table_init_rx_data_payload_t& m) {
        uint64_t m_initial_layer_index;
        uint64_t m_np_macro_id;
        uint64_t m_fi_macro_id;
            archive(::cereal::make_nvp("initial_layer_index", m_initial_layer_index));
            archive(::cereal::make_nvp("initial_rx_data", m.initial_rx_data));
            archive(::cereal::make_nvp("tag_swap_cmd", m.tag_swap_cmd));
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
            archive(::cereal::make_nvp("fi_macro_id", m_fi_macro_id));
        m.initial_layer_index = m_initial_layer_index;
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
class serializer_class<npl_stage2_lb_group_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_lb_group_size_table_key_t& m) {
        uint64_t m_ecmp_id = m.ecmp_id;
            archive(::cereal::make_nvp("ecmp_id", m_ecmp_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_lb_group_size_table_key_t& m) {
        uint64_t m_ecmp_id;
            archive(::cereal::make_nvp("ecmp_id", m_ecmp_id));
        m.ecmp_id = m_ecmp_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_lb_group_size_table_key_t& m)
{
    serializer_class<npl_stage2_lb_group_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_lb_group_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_lb_group_size_table_key_t& m)
{
    serializer_class<npl_stage2_lb_group_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_lb_group_size_table_key_t&);



template<>
class serializer_class<npl_stage2_lb_group_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_lb_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_lb_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_lb_group_size_table_value_t& m)
{
    serializer_class<npl_stage2_lb_group_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_lb_group_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_lb_group_size_table_value_t& m)
{
    serializer_class<npl_stage2_lb_group_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_lb_group_size_table_value_t&);



template<>
class serializer_class<npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage2_lb_group_size_table_result", m.stage2_lb_group_size_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage2_lb_group_size_table_result", m.stage2_lb_group_size_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_lb_group_size_table_value_t::npl_stage2_lb_group_size_table_payloads_t&);



template<>
class serializer_class<npl_stage2_lb_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_lb_table_key_t& m) {
        uint64_t m_member_id = m.member_id;
        uint64_t m_group_id = m.group_id;
            archive(::cereal::make_nvp("member_id", m_member_id));
            archive(::cereal::make_nvp("group_id", m_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_lb_table_key_t& m) {
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
save(Archive& archive, const npl_stage2_lb_table_key_t& m)
{
    serializer_class<npl_stage2_lb_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_lb_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_lb_table_key_t& m)
{
    serializer_class<npl_stage2_lb_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_lb_table_key_t&);



template<>
class serializer_class<npl_stage2_lb_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_lb_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_lb_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_lb_table_value_t& m)
{
    serializer_class<npl_stage2_lb_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_lb_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_lb_table_value_t& m)
{
    serializer_class<npl_stage2_lb_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_lb_table_value_t&);



template<>
class serializer_class<npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage2_lb_result", m.stage2_lb_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage2_lb_result", m.stage2_lb_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t& m)
{
    serializer_class<npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t& m)
{
    serializer_class<npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage2_lb_table_value_t::npl_stage2_lb_table_payloads_t&);



template<>
class serializer_class<npl_stage3_lb_group_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_group_size_table_key_t& m) {
        uint64_t m_stage3_lb_id = m.stage3_lb_id;
            archive(::cereal::make_nvp("stage3_lb_id", m_stage3_lb_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_group_size_table_key_t& m) {
        uint64_t m_stage3_lb_id;
            archive(::cereal::make_nvp("stage3_lb_id", m_stage3_lb_id));
        m.stage3_lb_id = m_stage3_lb_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_group_size_table_key_t& m)
{
    serializer_class<npl_stage3_lb_group_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_group_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_group_size_table_key_t& m)
{
    serializer_class<npl_stage3_lb_group_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_group_size_table_key_t&);



template<>
class serializer_class<npl_stage3_lb_group_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_group_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_group_size_table_value_t& m)
{
    serializer_class<npl_stage3_lb_group_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_group_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_group_size_table_value_t& m)
{
    serializer_class<npl_stage3_lb_group_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_group_size_table_value_t&);



template<>
class serializer_class<npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage3_lb_group_size_table_result", m.stage3_lb_group_size_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage3_lb_group_size_table_result", m.stage3_lb_group_size_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t& m)
{
    serializer_class<npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_group_size_table_value_t::npl_stage3_lb_group_size_table_payloads_t&);



template<>
class serializer_class<npl_stage3_lb_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_table_key_t& m) {
        uint64_t m_member_id = m.member_id;
        uint64_t m_group_id = m.group_id;
            archive(::cereal::make_nvp("member_id", m_member_id));
            archive(::cereal::make_nvp("group_id", m_group_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_table_key_t& m) {
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
save(Archive& archive, const npl_stage3_lb_table_key_t& m)
{
    serializer_class<npl_stage3_lb_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_table_key_t& m)
{
    serializer_class<npl_stage3_lb_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_table_key_t&);



template<>
class serializer_class<npl_stage3_lb_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_table_value_t& m)
{
    serializer_class<npl_stage3_lb_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_table_value_t& m)
{
    serializer_class<npl_stage3_lb_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_table_value_t&);



template<>
class serializer_class<npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage3_lb_result", m.stage3_lb_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage3_lb_result", m.stage3_lb_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t& m)
{
    serializer_class<npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t& m)
{
    serializer_class<npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_table_value_t::npl_stage3_lb_table_payloads_t&);



template<>
class serializer_class<npl_stage3_lb_type_decoding_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_type_decoding_table_key_t& m) {
            archive(::cereal::make_nvp("type", m.type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage3_lb_type_decoding_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_type_decoding_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_type_decoding_table_key_t& m)
{
    serializer_class<npl_stage3_lb_type_decoding_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_type_decoding_table_key_t&);



template<>
class serializer_class<npl_stage3_lb_type_decoding_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_type_decoding_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage3_lb_type_decoding_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_type_decoding_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_type_decoding_table_value_t& m)
{
    serializer_class<npl_stage3_lb_type_decoding_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_type_decoding_table_value_t&);



template<>
class serializer_class<npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage3_lb_type_decoding_table_result", m.stage3_lb_type_decoding_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t& m) {
            archive(::cereal::make_nvp("stage3_lb_type_decoding_table_result", m.stage3_lb_type_decoding_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t& m)
{
    serializer_class<npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_stage3_lb_type_decoding_table_value_t::npl_stage3_lb_type_decoding_table_payloads_t&);



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
class serializer_class<npl_ts_cmd_hw_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ts_cmd_hw_static_table_key_t& m) {
        uint64_t m_pd_tx_common_tx_leaba_fields_ts_command_op = m.pd_tx_common_tx_leaba_fields_ts_command_op;
            archive(::cereal::make_nvp("pd_tx_common_tx_leaba_fields_ts_command_op", m_pd_tx_common_tx_leaba_fields_ts_command_op));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ts_cmd_hw_static_table_key_t& m) {
        uint64_t m_pd_tx_common_tx_leaba_fields_ts_command_op;
            archive(::cereal::make_nvp("pd_tx_common_tx_leaba_fields_ts_command_op", m_pd_tx_common_tx_leaba_fields_ts_command_op));
        m.pd_tx_common_tx_leaba_fields_ts_command_op = m_pd_tx_common_tx_leaba_fields_ts_command_op;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ts_cmd_hw_static_table_key_t& m)
{
    serializer_class<npl_ts_cmd_hw_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ts_cmd_hw_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ts_cmd_hw_static_table_key_t& m)
{
    serializer_class<npl_ts_cmd_hw_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ts_cmd_hw_static_table_key_t&);



template<>
class serializer_class<npl_ts_cmd_hw_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ts_cmd_hw_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ts_cmd_hw_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ts_cmd_hw_static_table_value_t& m)
{
    serializer_class<npl_ts_cmd_hw_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ts_cmd_hw_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ts_cmd_hw_static_table_value_t& m)
{
    serializer_class<npl_ts_cmd_hw_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ts_cmd_hw_static_table_value_t&);



template<>
class serializer_class<npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ts_cmd_trans", m.ts_cmd_trans));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ts_cmd_trans", m.ts_cmd_trans));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t& m)
{
    serializer_class<npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t& m)
{
    serializer_class<npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ts_cmd_hw_static_table_value_t::npl_ts_cmd_hw_static_table_payloads_t&);



template<>
class serializer_class<npl_tunnel_dlp_p_counter_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_dlp_p_counter_offset_table_key_t& m) {
        uint64_t m_is_mc = m.is_mc;
        uint64_t m_is_mpls = m.is_mpls;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("is_mpls", m_is_mpls));
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_dlp_p_counter_offset_table_key_t& m) {
        uint64_t m_is_mc;
        uint64_t m_is_mpls;
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("is_mpls", m_is_mpls));
            archive(::cereal::make_nvp("l3_encap_type", m.l3_encap_type));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
        m.is_mc = m_is_mc;
        m.is_mpls = m_is_mpls;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_dlp_p_counter_offset_table_key_t& m)
{
    serializer_class<npl_tunnel_dlp_p_counter_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_dlp_p_counter_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_dlp_p_counter_offset_table_key_t& m)
{
    serializer_class<npl_tunnel_dlp_p_counter_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_dlp_p_counter_offset_table_key_t&);



template<>
class serializer_class<npl_tunnel_dlp_p_counter_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_dlp_p_counter_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_dlp_p_counter_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_dlp_p_counter_offset_table_value_t& m)
{
    serializer_class<npl_tunnel_dlp_p_counter_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_dlp_p_counter_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_dlp_p_counter_offset_table_value_t& m)
{
    serializer_class<npl_tunnel_dlp_p_counter_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_dlp_p_counter_offset_table_value_t&);



template<>
class serializer_class<npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("cntr_offset", m.cntr_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("cntr_offset", m.cntr_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t& m)
{
    serializer_class<npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t& m)
{
    serializer_class<npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_dlp_p_counter_offset_table_value_t::npl_tunnel_dlp_p_counter_offset_table_payloads_t&);



template<>
class serializer_class<npl_tunnel_qos_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_qos_static_table_key_t& m) {
        uint64_t m_lp_set = m.lp_set;
        uint64_t m_l3_dlp_is_group_qos = m.l3_dlp_is_group_qos;
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("l3_dlp_is_group_qos", m_l3_dlp_is_group_qos));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_qos_static_table_key_t& m) {
        uint64_t m_lp_set;
        uint64_t m_l3_dlp_is_group_qos;
            archive(::cereal::make_nvp("lp_set", m_lp_set));
            archive(::cereal::make_nvp("l3_dlp_is_group_qos", m_l3_dlp_is_group_qos));
        m.lp_set = m_lp_set;
        m.l3_dlp_is_group_qos = m_l3_dlp_is_group_qos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_qos_static_table_key_t& m)
{
    serializer_class<npl_tunnel_qos_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_qos_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_qos_static_table_key_t& m)
{
    serializer_class<npl_tunnel_qos_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_qos_static_table_key_t&);



template<>
class serializer_class<npl_tunnel_qos_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tunnel_qos_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tunnel_qos_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tunnel_qos_static_table_value_t& m)
{
    serializer_class<npl_tunnel_qos_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tunnel_qos_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tunnel_qos_static_table_value_t& m)
{
    serializer_class<npl_tunnel_qos_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tunnel_qos_static_table_value_t&);



template<>
class serializer_class<npl_tx_counters_block_config_table_config_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_block_config_table_config_payload_t& m) {
        uint64_t m_inc_bank_for_ifg_b = m.inc_bank_for_ifg_b;
        uint64_t m_inc_addr_for_set = m.inc_addr_for_set;
            archive(::cereal::make_nvp("inc_bank_for_ifg_b", m_inc_bank_for_ifg_b));
            archive(::cereal::make_nvp("inc_addr_for_set", m_inc_addr_for_set));
            archive(::cereal::make_nvp("bank_set_type", m.bank_set_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_block_config_table_config_payload_t& m) {
        uint64_t m_inc_bank_for_ifg_b;
        uint64_t m_inc_addr_for_set;
            archive(::cereal::make_nvp("inc_bank_for_ifg_b", m_inc_bank_for_ifg_b));
            archive(::cereal::make_nvp("inc_addr_for_set", m_inc_addr_for_set));
            archive(::cereal::make_nvp("bank_set_type", m.bank_set_type));
        m.inc_bank_for_ifg_b = m_inc_bank_for_ifg_b;
        m.inc_addr_for_set = m_inc_addr_for_set;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_counters_block_config_table_config_payload_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_config_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_counters_block_config_table_config_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_counters_block_config_table_config_payload_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_config_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_counters_block_config_table_config_payload_t&);



template<>
class serializer_class<npl_tx_counters_block_config_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_block_config_table_key_t& m) {
        uint64_t m_counter_block_id = m.counter_block_id;
            archive(::cereal::make_nvp("counter_block_id", m_counter_block_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_block_config_table_key_t& m) {
        uint64_t m_counter_block_id;
            archive(::cereal::make_nvp("counter_block_id", m_counter_block_id));
        m.counter_block_id = m_counter_block_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_counters_block_config_table_key_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_counters_block_config_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_counters_block_config_table_key_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_counters_block_config_table_key_t&);



template<>
class serializer_class<npl_tx_counters_block_config_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_block_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_block_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_counters_block_config_table_value_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_counters_block_config_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_counters_block_config_table_value_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_counters_block_config_table_value_t&);



template<>
class serializer_class<npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("config", m.config));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("config", m.config));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t& m)
{
    serializer_class<npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_counters_block_config_table_value_t::npl_tx_counters_block_config_table_payloads_t&);



template<>
class serializer_class<npl_tx_error_handling_counter_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_error_handling_counter_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_error_handling_counter_table_update_result_payload_t&);



template<>
class serializer_class<npl_tx_error_handling_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_error_handling_counter_table_key_t& m) {
        uint64_t m_ser = m.ser;
        uint64_t m_dest_pif = m.dest_pif;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_error_handling_counter_table_key_t& m) {
        uint64_t m_ser;
        uint64_t m_dest_pif;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
        m.ser = m_ser;
        m.dest_pif = m_dest_pif;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_error_handling_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_error_handling_counter_table_key_t&);



template<>
class serializer_class<npl_tx_error_handling_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_error_handling_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_error_handling_counter_table_value_t&);



template<>
class serializer_class<npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_error_handling_counter_table_value_t::npl_tx_error_handling_counter_table_payloads_t&);



template<>
class serializer_class<npl_tx_punt_eth_encap_table_found_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_punt_eth_encap_table_found_payload_t& m) {
        uint64_t m_wide_bit = m.wide_bit;
            archive(::cereal::make_nvp("wide_bit", m_wide_bit));
            archive(::cereal::make_nvp("eth_pcp_dei", m.eth_pcp_dei));
            archive(::cereal::make_nvp("punt_eth_or_npu_host_encap", m.punt_eth_or_npu_host_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_punt_eth_encap_table_found_payload_t& m) {
        uint64_t m_wide_bit;
            archive(::cereal::make_nvp("wide_bit", m_wide_bit));
            archive(::cereal::make_nvp("eth_pcp_dei", m.eth_pcp_dei));
            archive(::cereal::make_nvp("punt_eth_or_npu_host_encap", m.punt_eth_or_npu_host_encap));
        m.wide_bit = m_wide_bit;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_punt_eth_encap_table_found_payload_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_found_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_punt_eth_encap_table_found_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_punt_eth_encap_table_found_payload_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_found_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_punt_eth_encap_table_found_payload_t&);



template<>
class serializer_class<npl_tx_punt_eth_encap_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_punt_eth_encap_table_key_t& m) {
        uint64_t m_punt_encap = m.punt_encap;
            archive(::cereal::make_nvp("punt_encap", m_punt_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_punt_eth_encap_table_key_t& m) {
        uint64_t m_punt_encap;
            archive(::cereal::make_nvp("punt_encap", m_punt_encap));
        m.punt_encap = m_punt_encap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_punt_eth_encap_table_key_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_punt_eth_encap_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_punt_eth_encap_table_key_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_punt_eth_encap_table_key_t&);



template<>
class serializer_class<npl_tx_punt_eth_encap_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_punt_eth_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_punt_eth_encap_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_punt_eth_encap_table_value_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_punt_eth_encap_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_punt_eth_encap_table_value_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_punt_eth_encap_table_value_t&);



template<>
class serializer_class<npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t& m)
{
    serializer_class<npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_punt_eth_encap_table_value_t::npl_tx_punt_eth_encap_table_payloads_t&);



template<>
class serializer_class<npl_tx_redirect_code_table_tx_redirect_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_redirect_code_table_tx_redirect_action_payload_t& m) {
            archive(::cereal::make_nvp("is_drop_action", m.is_drop_action));
            archive(::cereal::make_nvp("stamp_into_packet_header", m.stamp_into_packet_header));
            archive(::cereal::make_nvp("cntr_stamp_cmd", m.cntr_stamp_cmd));
            archive(::cereal::make_nvp("ts_cmd", m.ts_cmd));
            archive(::cereal::make_nvp("tx_punt_nw_encap_ptr", m.tx_punt_nw_encap_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_redirect_code_table_tx_redirect_action_payload_t& m) {
            archive(::cereal::make_nvp("is_drop_action", m.is_drop_action));
            archive(::cereal::make_nvp("stamp_into_packet_header", m.stamp_into_packet_header));
            archive(::cereal::make_nvp("cntr_stamp_cmd", m.cntr_stamp_cmd));
            archive(::cereal::make_nvp("ts_cmd", m.ts_cmd));
            archive(::cereal::make_nvp("tx_punt_nw_encap_ptr", m.tx_punt_nw_encap_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_redirect_code_table_tx_redirect_action_payload_t& m)
{
    serializer_class<npl_tx_redirect_code_table_tx_redirect_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_redirect_code_table_tx_redirect_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_redirect_code_table_tx_redirect_action_payload_t& m)
{
    serializer_class<npl_tx_redirect_code_table_tx_redirect_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_redirect_code_table_tx_redirect_action_payload_t&);



}

