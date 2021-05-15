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

template <class Archive> void save(Archive&, const npl_color_len_t&);
template <class Archive> void load(Archive&, npl_color_len_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_db_access_service_mapping_access_attr_t&);
template <class Archive> void load(Archive&, npl_db_access_service_mapping_access_attr_t&);

template <class Archive> void save(Archive&, const npl_db_access_service_mapping_tcam_access_attr_t&);
template <class Archive> void load(Archive&, npl_db_access_service_mapping_tcam_access_attr_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_exact_bank_index_len_t&);
template <class Archive> void load(Archive&, npl_exact_bank_index_len_t&);

template <class Archive> void save(Archive&, const npl_exact_meter_index_len_t&);
template <class Archive> void load(Archive&, npl_exact_meter_index_len_t&);

template <class Archive> void save(Archive&, const npl_fabric_port_id_t&);
template <class Archive> void load(Archive&, npl_fabric_port_id_t&);

template <class Archive> void save(Archive&, const npl_g_ifg_len_t&);
template <class Archive> void load(Archive&, npl_g_ifg_len_t&);

template <class Archive> void save(Archive&, const npl_ifg_len_t&);
template <class Archive> void load(Archive&, npl_ifg_len_t&);

template <class Archive> void save(Archive&, const npl_ifg_t&);
template <class Archive> void load(Archive&, npl_ifg_t&);

template <class Archive> void save(Archive&, const npl_inject_header_type_t&);
template <class Archive> void load(Archive&, npl_inject_header_type_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_mc_t&);
template <class Archive> void load(Archive&, npl_ip_ver_mc_t&);

template <class Archive> void save(Archive&, const npl_l4_ports_header_t&);
template <class Archive> void load(Archive&, npl_l4_ports_header_t&);

template <class Archive> void save(Archive&, const npl_lm_command_t&);
template <class Archive> void load(Archive&, npl_lm_command_t&);

template <class Archive> void save(Archive&, const npl_lp_id_t&);
template <class Archive> void load(Archive&, npl_lp_id_t&);

template <class Archive> void save(Archive&, const npl_mac_lp_attributes_table_payload_t&);
template <class Archive> void load(Archive&, npl_mac_lp_attributes_table_payload_t&);

template <class Archive> void save(Archive&, const npl_meter_action_profile_len_t&);
template <class Archive> void load(Archive&, npl_meter_action_profile_len_t&);

template <class Archive> void save(Archive&, const npl_meter_profile_len_t&);
template <class Archive> void load(Archive&, npl_meter_profile_len_t&);

template <class Archive> void save(Archive&, const npl_oqse_pair_t&);
template <class Archive> void load(Archive&, npl_oqse_pair_t&);

template <class Archive> void save(Archive&, const npl_padding_for_sm_tcam_t&);
template <class Archive> void load(Archive&, npl_padding_for_sm_tcam_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_punt_encap_data_lsb_t&);
template <class Archive> void load(Archive&, npl_punt_encap_data_lsb_t&);

template <class Archive> void save(Archive&, const npl_punt_ssp_attributes_t&);
template <class Archive> void load(Archive&, npl_punt_ssp_attributes_t&);

template <class Archive> void save(Archive&, const npl_rate_limiters_port_packet_type_index_len_t&);
template <class Archive> void load(Archive&, npl_rate_limiters_port_packet_type_index_len_t&);

template <class Archive> void save(Archive&, const npl_relay_attr_table_payload_t&);
template <class Archive> void load(Archive&, npl_relay_attr_table_payload_t&);

template <class Archive> void save(Archive&, const npl_relay_id_t&);
template <class Archive> void load(Archive&, npl_relay_id_t&);

template <class Archive> void save(Archive&, const npl_rx_fwd_error_handling_destination_table_update_result_payload_t&);
template <class Archive> void load(Archive&, npl_rx_fwd_error_handling_destination_table_update_result_payload_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_attribute_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_attribute_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_profile_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_profile_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_block_meter_shaper_configuration_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_block_meter_shaper_configuration_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_distributed_meter_profile_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_distributed_meter_profile_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_exact_meter_decision_mapping_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_exact_meter_decision_mapping_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meter_profile_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meter_profile_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meter_shaper_configuration_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meter_shaper_configuration_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_meters_attribute_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_meters_attribute_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_rate_limiter_shaper_configuration_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_rate_limiter_shaper_configuration_result_t&);

template <class Archive> void save(Archive&, const npl_rx_meter_stat_meter_decision_mapping_result_t&);
template <class Archive> void load(Archive&, npl_rx_meter_stat_meter_decision_mapping_result_t&);

template <class Archive> void save(Archive&, const npl_rx_obm_punt_src_and_code_data_t&);
template <class Archive> void load(Archive&, npl_rx_obm_punt_src_and_code_data_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_lookup_table_entry_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_lookup_table_entry_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_dsp_tc_map_result_t&);
template <class Archive> void load(Archive&, npl_rxpdr_dsp_tc_map_result_t&);

template <class Archive> void save(Archive&, const npl_sch_oqse_cfg_result_t&);
template <class Archive> void load(Archive&, npl_sch_oqse_cfg_result_t&);

template <class Archive> void save(Archive&, const npl_sda_fabric_feature_t&);
template <class Archive> void load(Archive&, npl_sda_fabric_feature_t&);

template <class Archive> void save(Archive&, const npl_sgacl_table_value_t::npl_sgacl_table_payloads_t&);
template <class Archive> void load(Archive&, npl_sgacl_table_value_t::npl_sgacl_table_payloads_t&);

template <class Archive> void save(Archive&, const npl_stat_bank_index_len_t&);
template <class Archive> void load(Archive&, npl_stat_bank_index_len_t&);

template <class Archive> void save(Archive&, const npl_stat_meter_index_len_t&);
template <class Archive> void load(Archive&, npl_stat_meter_index_len_t&);

template <class Archive> void save(Archive&, const npl_ts_command_t&);
template <class Archive> void load(Archive&, npl_ts_command_t&);

template <class Archive> void save(Archive&, const npl_tx_to_rx_rcy_data_t&);
template <class Archive> void load(Archive&, npl_tx_to_rx_rcy_data_t&);

template <class Archive> void save(Archive&, const npl_use_metedata_table_per_packet_format_t&);
template <class Archive> void load(Archive&, npl_use_metedata_table_per_packet_format_t&);

template <class Archive> void save(Archive&, const npl_vlan_id_t&);
template <class Archive> void load(Archive&, npl_vlan_id_t&);

template<>
class serializer_class<npl_rx_fwd_error_handling_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_key_t& m) {
        uint64_t m_ser = m.ser;
            archive(::cereal::make_nvp("ser", m_ser));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_destination_table_key_t& m) {
        uint64_t m_ser;
            archive(::cereal::make_nvp("ser", m_ser));
        m.ser = m_ser;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_destination_table_key_t&);



template<>
class serializer_class<npl_rx_fwd_error_handling_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_destination_table_value_t&);



template<>
class serializer_class<npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_fwd_error_handling_destination_table_value_t::npl_rx_fwd_error_handling_destination_table_payloads_t&);



template<>
class serializer_class<npl_rx_ip_p_counter_offset_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_ip_p_counter_offset_static_table_key_t& m) {
        uint64_t m_per_protocol_count = m.per_protocol_count;
            archive(::cereal::make_nvp("ip_ver_mc", m.ip_ver_mc));
            archive(::cereal::make_nvp("per_protocol_count", m_per_protocol_count));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_ip_p_counter_offset_static_table_key_t& m) {
        uint64_t m_per_protocol_count;
            archive(::cereal::make_nvp("ip_ver_mc", m.ip_ver_mc));
            archive(::cereal::make_nvp("per_protocol_count", m_per_protocol_count));
        m.per_protocol_count = m_per_protocol_count;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_ip_p_counter_offset_static_table_key_t& m)
{
    serializer_class<npl_rx_ip_p_counter_offset_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_ip_p_counter_offset_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_ip_p_counter_offset_static_table_key_t& m)
{
    serializer_class<npl_rx_ip_p_counter_offset_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_ip_p_counter_offset_static_table_key_t&);



template<>
class serializer_class<npl_rx_ip_p_counter_offset_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_ip_p_counter_offset_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_ip_p_counter_offset_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_ip_p_counter_offset_static_table_value_t& m)
{
    serializer_class<npl_rx_ip_p_counter_offset_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_ip_p_counter_offset_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_ip_p_counter_offset_static_table_value_t& m)
{
    serializer_class<npl_rx_ip_p_counter_offset_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_ip_p_counter_offset_static_table_value_t&);



template<>
class serializer_class<npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t& m) {
        uint64_t m_macro_counters_update_counter_0_offset = m.macro_counters_update_counter_0_offset;
            archive(::cereal::make_nvp("macro_counters_update_counter_0_offset", m_macro_counters_update_counter_0_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t& m) {
        uint64_t m_macro_counters_update_counter_0_offset;
            archive(::cereal::make_nvp("macro_counters_update_counter_0_offset", m_macro_counters_update_counter_0_offset));
        m.macro_counters_update_counter_0_offset = m_macro_counters_update_counter_0_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t& m)
{
    serializer_class<npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t& m)
{
    serializer_class<npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_ip_p_counter_offset_static_table_value_t::npl_rx_ip_p_counter_offset_static_table_payloads_t&);



template<>
class serializer_class<npl_rx_map_npp_to_ssp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_map_npp_to_ssp_table_key_t& m) {
        uint64_t m_npp_attributes_index = m.npp_attributes_index;
            archive(::cereal::make_nvp("npp_attributes_index", m_npp_attributes_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_map_npp_to_ssp_table_key_t& m) {
        uint64_t m_npp_attributes_index;
            archive(::cereal::make_nvp("npp_attributes_index", m_npp_attributes_index));
        m.npp_attributes_index = m_npp_attributes_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_map_npp_to_ssp_table_key_t& m)
{
    serializer_class<npl_rx_map_npp_to_ssp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_map_npp_to_ssp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_map_npp_to_ssp_table_key_t& m)
{
    serializer_class<npl_rx_map_npp_to_ssp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_map_npp_to_ssp_table_key_t&);



template<>
class serializer_class<npl_rx_map_npp_to_ssp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_map_npp_to_ssp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_map_npp_to_ssp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_map_npp_to_ssp_table_value_t& m)
{
    serializer_class<npl_rx_map_npp_to_ssp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_map_npp_to_ssp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_map_npp_to_ssp_table_value_t& m)
{
    serializer_class<npl_rx_map_npp_to_ssp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_map_npp_to_ssp_table_value_t&);



template<>
class serializer_class<npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t& m) {
            archive(::cereal::make_nvp("local_npp_to_ssp_result", m.local_npp_to_ssp_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t& m) {
            archive(::cereal::make_nvp("local_npp_to_ssp_result", m.local_npp_to_ssp_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t& m)
{
    serializer_class<npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t& m)
{
    serializer_class<npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_map_npp_to_ssp_table_value_t::npl_rx_map_npp_to_ssp_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_bank_offset_map_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_bank_offset_map_key_t& m) {
        uint64_t m_npu_bank_id = m.npu_bank_id;
        uint64_t m_ifg = m.ifg;
            archive(::cereal::make_nvp("npu_bank_id", m_npu_bank_id));
            archive(::cereal::make_nvp("ifg", m_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_bank_offset_map_key_t& m) {
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
save(Archive& archive, const npl_rx_meter_bank_offset_map_key_t& m)
{
    serializer_class<npl_rx_meter_bank_offset_map_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_bank_offset_map_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_bank_offset_map_key_t& m)
{
    serializer_class<npl_rx_meter_bank_offset_map_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_bank_offset_map_key_t&);



template<>
class serializer_class<npl_rx_meter_bank_offset_map_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_bank_offset_map_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_bank_offset_map_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_bank_offset_map_value_t& m)
{
    serializer_class<npl_rx_meter_bank_offset_map_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_bank_offset_map_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_bank_offset_map_value_t& m)
{
    serializer_class<npl_rx_meter_bank_offset_map_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_bank_offset_map_value_t&);



template<>
class serializer_class<npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t& m) {
        uint64_t m_counter_bank_id = m.counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t& m) {
        uint64_t m_counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
        m.counter_bank_id = m_counter_bank_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t& m)
{
    serializer_class<npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t& m)
{
    serializer_class<npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_bank_offset_map_value_t::npl_rx_meter_bank_offset_map_payloads_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_attribute_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_attribute_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_attribute_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_attribute_table_key_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_attribute_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_attribute_table_key_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_attribute_table_key_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_attribute_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_attribute_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_attribute_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_attribute_table_value_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_attribute_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_attribute_table_value_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_attribute_table_value_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_block_meter_attribute_result", m.rx_meter_block_meter_attribute_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_block_meter_attribute_result", m.rx_meter_block_meter_attribute_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_attribute_table_value_t::npl_rx_meter_block_meter_attribute_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_profile_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_profile_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_profile_index", m.meter_profile_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_profile_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_profile_index", m.meter_profile_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_profile_table_key_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_profile_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_profile_table_key_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_profile_table_key_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_profile_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_profile_table_value_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_profile_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_profile_table_value_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_profile_table_value_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_block_meter_profile_result", m.rx_meter_block_meter_profile_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_block_meter_profile_result", m.rx_meter_block_meter_profile_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_profile_table_value_t::npl_rx_meter_block_meter_profile_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_table_key_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_shaper_configuration_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_table_key_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_shaper_configuration_table_key_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_table_value_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_shaper_configuration_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_table_value_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_shaper_configuration_table_value_t&);



template<>
class serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_block_meter_shaper_configuration_result", m.rx_meter_block_meter_shaper_configuration_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_block_meter_shaper_configuration_result", m.rx_meter_block_meter_shaper_configuration_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_block_meter_shaper_configuration_table_value_t::npl_rx_meter_block_meter_shaper_configuration_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_distributed_meter_profile_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_distributed_meter_profile_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_profile_index", m.meter_profile_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_distributed_meter_profile_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_profile_index", m.meter_profile_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_distributed_meter_profile_table_key_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_distributed_meter_profile_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_distributed_meter_profile_table_key_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_distributed_meter_profile_table_key_t&);



template<>
class serializer_class<npl_rx_meter_distributed_meter_profile_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_distributed_meter_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_distributed_meter_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_distributed_meter_profile_table_value_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_distributed_meter_profile_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_distributed_meter_profile_table_value_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_distributed_meter_profile_table_value_t&);



template<>
class serializer_class<npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_distributed_meter_profile_result", m.rx_meter_distributed_meter_profile_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_distributed_meter_profile_result", m.rx_meter_distributed_meter_profile_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_distributed_meter_profile_table_value_t::npl_rx_meter_distributed_meter_profile_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("meter_action_profile_index", m.meter_action_profile_index));
            archive(::cereal::make_nvp("rate_limiter_result_color", m.rate_limiter_result_color));
            archive(::cereal::make_nvp("meter_result_color", m.meter_result_color));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("ifg", m.ifg));
            archive(::cereal::make_nvp("meter_action_profile_index", m.meter_action_profile_index));
            archive(::cereal::make_nvp("rate_limiter_result_color", m.rate_limiter_result_color));
            archive(::cereal::make_nvp("meter_result_color", m.meter_result_color));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_table_key_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_exact_meter_decision_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_table_key_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_exact_meter_decision_mapping_table_key_t&);



template<>
class serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_table_value_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_exact_meter_decision_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_table_value_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_exact_meter_decision_mapping_table_value_t&);



template<>
class serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_exact_meter_decision_mapping_result", m.rx_meter_exact_meter_decision_mapping_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_exact_meter_decision_mapping_result", m.rx_meter_exact_meter_decision_mapping_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_exact_meter_decision_mapping_table_value_t::npl_rx_meter_exact_meter_decision_mapping_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_meter_profile_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_profile_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_profile_index", m.meter_profile_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_profile_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_profile_index", m.meter_profile_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_profile_table_key_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_profile_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_profile_table_key_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_profile_table_key_t&);



template<>
class serializer_class<npl_rx_meter_meter_profile_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_profile_table_value_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_profile_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_profile_table_value_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_profile_table_value_t&);



template<>
class serializer_class<npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_meter_profile_result", m.rx_meter_meter_profile_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_meter_profile_result", m.rx_meter_meter_profile_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_profile_table_value_t::npl_rx_meter_meter_profile_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_meter_shaper_configuration_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_shaper_configuration_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_table_key_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_shaper_configuration_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_shaper_configuration_table_key_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_shaper_configuration_table_key_t&);



template<>
class serializer_class<npl_rx_meter_meter_shaper_configuration_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_shaper_configuration_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_table_value_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_shaper_configuration_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_shaper_configuration_table_value_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_shaper_configuration_table_value_t&);



template<>
class serializer_class<npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_meter_shaper_configuration_result", m.rx_meter_meter_shaper_configuration_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_meter_shaper_configuration_result", m.rx_meter_meter_shaper_configuration_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meter_shaper_configuration_table_value_t::npl_rx_meter_meter_shaper_configuration_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_meters_attribute_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meters_attribute_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meters_attribute_table_key_t& m) {
            archive(::cereal::make_nvp("bank_index", m.bank_index));
            archive(::cereal::make_nvp("meter_index", m.meter_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meters_attribute_table_key_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meters_attribute_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meters_attribute_table_key_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meters_attribute_table_key_t&);



template<>
class serializer_class<npl_rx_meter_meters_attribute_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meters_attribute_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meters_attribute_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meters_attribute_table_value_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meters_attribute_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meters_attribute_table_value_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meters_attribute_table_value_t&);



template<>
class serializer_class<npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_meters_attribute_result", m.rx_meter_meters_attribute_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_meters_attribute_result", m.rx_meter_meters_attribute_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_meters_attribute_table_value_t::npl_rx_meter_meters_attribute_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_table_key_t& m) {
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("table_entry_index", m.table_entry_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_table_key_t& m) {
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("table_entry_index", m.table_entry_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_table_key_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_rate_limiter_shaper_configuration_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_table_key_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_rate_limiter_shaper_configuration_table_key_t&);



template<>
class serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_table_value_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_rate_limiter_shaper_configuration_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t&);



template<>
class serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_rate_limiter_shaper_configuration_result", m.rx_meter_rate_limiter_shaper_configuration_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_rate_limiter_shaper_configuration_result", m.rx_meter_rate_limiter_shaper_configuration_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_rate_limiter_shaper_configuration_table_value_t::npl_rx_meter_rate_limiter_shaper_configuration_table_payloads_t&);



template<>
class serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("meter_bank_index", m.meter_bank_index));
            archive(::cereal::make_nvp("meter_action_profile_index", m.meter_action_profile_index));
            archive(::cereal::make_nvp("exact_meter_to_stat_meter_color", m.exact_meter_to_stat_meter_color));
            archive(::cereal::make_nvp("meter_result_color", m.meter_result_color));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("meter_bank_index", m.meter_bank_index));
            archive(::cereal::make_nvp("meter_action_profile_index", m.meter_action_profile_index));
            archive(::cereal::make_nvp("exact_meter_to_stat_meter_color", m.exact_meter_to_stat_meter_color));
            archive(::cereal::make_nvp("meter_result_color", m.meter_result_color));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_table_key_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_stat_meter_decision_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_table_key_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_stat_meter_decision_mapping_table_key_t&);



template<>
class serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_table_value_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_stat_meter_decision_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_table_value_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_stat_meter_decision_mapping_table_value_t&);



template<>
class serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_stat_meter_decision_mapping_result", m.rx_meter_stat_meter_decision_mapping_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_meter_stat_meter_decision_mapping_result", m.rx_meter_stat_meter_decision_mapping_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t& m)
{
    serializer_class<npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_meter_stat_meter_decision_mapping_table_value_t::npl_rx_meter_stat_meter_decision_mapping_table_payloads_t&);



template<>
class serializer_class<npl_rx_npu_to_tm_dest_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_npu_to_tm_dest_table_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_19_14_ = m.rxpp_pd_fwd_destination_19_14_;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_19_14_", m_rxpp_pd_fwd_destination_19_14_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_npu_to_tm_dest_table_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_19_14_;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_19_14_", m_rxpp_pd_fwd_destination_19_14_));
        m.rxpp_pd_fwd_destination_19_14_ = m_rxpp_pd_fwd_destination_19_14_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_npu_to_tm_dest_table_key_t& m)
{
    serializer_class<npl_rx_npu_to_tm_dest_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_npu_to_tm_dest_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_npu_to_tm_dest_table_key_t& m)
{
    serializer_class<npl_rx_npu_to_tm_dest_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_npu_to_tm_dest_table_key_t&);



template<>
class serializer_class<npl_rx_npu_to_tm_dest_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_npu_to_tm_dest_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_npu_to_tm_dest_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_npu_to_tm_dest_table_value_t& m)
{
    serializer_class<npl_rx_npu_to_tm_dest_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_npu_to_tm_dest_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_npu_to_tm_dest_table_value_t& m)
{
    serializer_class<npl_rx_npu_to_tm_dest_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_npu_to_tm_dest_table_value_t&);



template<>
class serializer_class<npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t& m) {
        uint64_t m_pd_rx_tm_destination_prefix = m.pd_rx_tm_destination_prefix;
            archive(::cereal::make_nvp("pd_rx_tm_destination_prefix", m_pd_rx_tm_destination_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t& m) {
        uint64_t m_pd_rx_tm_destination_prefix;
            archive(::cereal::make_nvp("pd_rx_tm_destination_prefix", m_pd_rx_tm_destination_prefix));
        m.pd_rx_tm_destination_prefix = m_pd_rx_tm_destination_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t& m)
{
    serializer_class<npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t& m)
{
    serializer_class<npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_npu_to_tm_dest_table_value_t::npl_rx_npu_to_tm_dest_table_payloads_t&);



template<>
class serializer_class<npl_rx_obm_code_table_rx_obm_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_code_table_rx_obm_action_payload_t& m) {
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_code_table_rx_obm_action_payload_t& m) {
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("destination", m.destination));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_code_table_rx_obm_action_payload_t& m)
{
    serializer_class<npl_rx_obm_code_table_rx_obm_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_code_table_rx_obm_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_code_table_rx_obm_action_payload_t& m)
{
    serializer_class<npl_rx_obm_code_table_rx_obm_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_code_table_rx_obm_action_payload_t&);



template<>
class serializer_class<npl_rx_obm_code_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_code_table_key_t& m) {
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_code_table_key_t& m) {
            archive(::cereal::make_nvp("tx_to_rx_rcy_data", m.tx_to_rx_rcy_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_code_table_key_t& m)
{
    serializer_class<npl_rx_obm_code_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_code_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_code_table_key_t& m)
{
    serializer_class<npl_rx_obm_code_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_code_table_key_t&);



template<>
class serializer_class<npl_rx_obm_code_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_code_table_value_t& m)
{
    serializer_class<npl_rx_obm_code_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_code_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_code_table_value_t& m)
{
    serializer_class<npl_rx_obm_code_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_code_table_value_t&);



template<>
class serializer_class<npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_obm_action", m.rx_obm_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_obm_action", m.rx_obm_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t& m)
{
    serializer_class<npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t& m)
{
    serializer_class<npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_code_table_value_t::npl_rx_obm_code_table_payloads_t&);



template<>
class serializer_class<npl_rx_obm_punt_src_and_code_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_punt_src_and_code_table_key_t& m) {
        uint64_t m_punt_src_and_code = m.punt_src_and_code;
            archive(::cereal::make_nvp("is_dma", m.is_dma));
            archive(::cereal::make_nvp("punt_src_and_code", m_punt_src_and_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_punt_src_and_code_table_key_t& m) {
        uint64_t m_punt_src_and_code;
            archive(::cereal::make_nvp("is_dma", m.is_dma));
            archive(::cereal::make_nvp("punt_src_and_code", m_punt_src_and_code));
        m.punt_src_and_code = m_punt_src_and_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_punt_src_and_code_table_key_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_punt_src_and_code_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_punt_src_and_code_table_key_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_punt_src_and_code_table_key_t&);



template<>
class serializer_class<npl_rx_obm_punt_src_and_code_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_punt_src_and_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_punt_src_and_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_punt_src_and_code_table_value_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_punt_src_and_code_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_punt_src_and_code_table_value_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_punt_src_and_code_table_value_t&);



template<>
class serializer_class<npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_obm_punt_src_and_code_data", m.rx_obm_punt_src_and_code_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_obm_punt_src_and_code_data", m.rx_obm_punt_src_and_code_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t& m)
{
    serializer_class<npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_obm_punt_src_and_code_table_value_t::npl_rx_obm_punt_src_and_code_table_payloads_t&);



template<>
class serializer_class<npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t& m) {
            archive(::cereal::make_nvp("meter_counter", m.meter_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t& m) {
            archive(::cereal::make_nvp("meter_counter", m.meter_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_ext_table_rx_redirect_action_ext_payload_t&);



template<>
class serializer_class<npl_rx_redirect_code_ext_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_ext_table_key_t& m) {
        uint64_t m_redirect_code = m.redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_ext_table_key_t& m) {
        uint64_t m_redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
        m.redirect_code = m_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_ext_table_key_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_ext_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_ext_table_key_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_ext_table_key_t&);



template<>
class serializer_class<npl_rx_redirect_code_ext_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_ext_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_ext_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_ext_table_value_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_ext_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_ext_table_value_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_ext_table_value_t&);



template<>
class serializer_class<npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_redirect_action_ext", m.rx_redirect_action_ext));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_redirect_action_ext", m.rx_redirect_action_ext));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t& m)
{
    serializer_class<npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_ext_table_value_t::npl_rx_redirect_code_ext_table_payloads_t&);



template<>
class serializer_class<npl_rx_redirect_code_table_rx_redirect_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_table_rx_redirect_action_payload_t& m) {
        uint64_t m_override_phb = m.override_phb;
        uint64_t m_punt_sub_code = m.punt_sub_code;
        uint64_t m_disable_snoop = m.disable_snoop;
        uint64_t m_is_l3_trap = m.is_l3_trap;
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("override_phb", m_override_phb));
            archive(::cereal::make_nvp("per_pif_trap_mode", m.per_pif_trap_mode));
            archive(::cereal::make_nvp("stamp_into_packet_header", m.stamp_into_packet_header));
            archive(::cereal::make_nvp("punt_sub_code", m_punt_sub_code));
            archive(::cereal::make_nvp("disable_snoop", m_disable_snoop));
            archive(::cereal::make_nvp("is_l3_trap", m_is_l3_trap));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("ts_cmd", m.ts_cmd));
            archive(::cereal::make_nvp("cntr_stamp_cmd", m.cntr_stamp_cmd));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("redirect_counter", m.redirect_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_table_rx_redirect_action_payload_t& m) {
        uint64_t m_override_phb;
        uint64_t m_punt_sub_code;
        uint64_t m_disable_snoop;
        uint64_t m_is_l3_trap;
        uint64_t m_destination;
            archive(::cereal::make_nvp("override_phb", m_override_phb));
            archive(::cereal::make_nvp("per_pif_trap_mode", m.per_pif_trap_mode));
            archive(::cereal::make_nvp("stamp_into_packet_header", m.stamp_into_packet_header));
            archive(::cereal::make_nvp("punt_sub_code", m_punt_sub_code));
            archive(::cereal::make_nvp("disable_snoop", m_disable_snoop));
            archive(::cereal::make_nvp("is_l3_trap", m_is_l3_trap));
            archive(::cereal::make_nvp("phb", m.phb));
            archive(::cereal::make_nvp("destination", m_destination));
            archive(::cereal::make_nvp("ts_cmd", m.ts_cmd));
            archive(::cereal::make_nvp("cntr_stamp_cmd", m.cntr_stamp_cmd));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("redirect_counter", m.redirect_counter));
        m.override_phb = m_override_phb;
        m.punt_sub_code = m_punt_sub_code;
        m.disable_snoop = m_disable_snoop;
        m.is_l3_trap = m_is_l3_trap;
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_table_rx_redirect_action_payload_t& m)
{
    serializer_class<npl_rx_redirect_code_table_rx_redirect_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_table_rx_redirect_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_table_rx_redirect_action_payload_t& m)
{
    serializer_class<npl_rx_redirect_code_table_rx_redirect_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_table_rx_redirect_action_payload_t&);



template<>
class serializer_class<npl_rx_redirect_code_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_table_key_t& m) {
        uint64_t m_redirect_code = m.redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_table_key_t& m) {
        uint64_t m_redirect_code;
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
        m.redirect_code = m_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_table_key_t& m)
{
    serializer_class<npl_rx_redirect_code_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_table_key_t& m)
{
    serializer_class<npl_rx_redirect_code_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_table_key_t&);



template<>
class serializer_class<npl_rx_redirect_code_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_table_value_t& m)
{
    serializer_class<npl_rx_redirect_code_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_table_value_t& m)
{
    serializer_class<npl_rx_redirect_code_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_table_value_t&);



template<>
class serializer_class<npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_redirect_action", m.rx_redirect_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("rx_redirect_action", m.rx_redirect_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t& m)
{
    serializer_class<npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t& m)
{
    serializer_class<npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_code_table_value_t::npl_rx_redirect_code_table_payloads_t&);



template<>
class serializer_class<npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t& m) {
        uint64_t m_is_last_rx_macro = m.is_last_rx_macro;
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("is_last_rx_macro", m_is_last_rx_macro));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t& m) {
        uint64_t m_is_last_rx_macro;
        uint64_t m_pl_inc;
        uint64_t m_macro_id;
            archive(::cereal::make_nvp("is_last_rx_macro", m_is_last_rx_macro));
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
        m.is_last_rx_macro = m_is_last_rx_macro;
        m.pl_inc = m_pl_inc;
        m.macro_id = m_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_next_macro_static_table_update_next_macro_payload_t&);



template<>
class serializer_class<npl_rx_redirect_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_next_macro_static_table_key_t& m) {
        uint64_t m_redirect_code = m.redirect_code;
            archive(::cereal::make_nvp("cud_type", m.cud_type));
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
            archive(::cereal::make_nvp("protocol_type", m.protocol_type));
            archive(::cereal::make_nvp("next_protocol_type", m.next_protocol_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_next_macro_static_table_key_t& m) {
        uint64_t m_redirect_code;
            archive(::cereal::make_nvp("cud_type", m.cud_type));
            archive(::cereal::make_nvp("redirect_code", m_redirect_code));
            archive(::cereal::make_nvp("protocol_type", m.protocol_type));
            archive(::cereal::make_nvp("next_protocol_type", m.next_protocol_type));
        m.redirect_code = m_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_next_macro_static_table_key_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_next_macro_static_table_key_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_rx_redirect_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_next_macro_static_table_value_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_next_macro_static_table_value_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_next_macro", m.update_next_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_next_macro", m.update_next_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_redirect_next_macro_static_table_value_t::npl_rx_redirect_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_rx_term_error_handling_counter_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_term_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_counter_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_counter_table_update_result_payload_t&);



template<>
class serializer_class<npl_rx_term_error_handling_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_counter_table_key_t& m) {
        uint64_t m_ser = m.ser;
        uint64_t m_pd_source_if_pif = m.pd_source_if_pif;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("pd_source_if_pif", m_pd_source_if_pif));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_counter_table_key_t& m) {
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
save(Archive& archive, const npl_rx_term_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_counter_table_key_t&);



template<>
class serializer_class<npl_rx_term_error_handling_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_term_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_counter_table_value_t&);



template<>
class serializer_class<npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rx_term_error_handling_counter_table_value_t::npl_rx_term_error_handling_counter_table_payloads_t&);



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
class serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t& m) {
            archive(::cereal::make_nvp("calc_tx_slice_doq_of_fabric_port_context_input_tx_fabric_port_in_device", m.calc_tx_slice_doq_of_fabric_port_context_input_tx_fabric_port_in_device));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t& m) {
            archive(::cereal::make_nvp("calc_tx_slice_doq_of_fabric_port_context_input_tx_fabric_port_in_device", m.calc_tx_slice_doq_of_fabric_port_context_input_tx_fabric_port_in_device));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t& m)
{
    serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t& m)
{
    serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_key_t&);



template<>
class serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t& m)
{
    serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t& m)
{
    serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t&);



template<>
class serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t& m) {
        uint64_t m_calc_tx_slice_doq_of_fabric_port_context_output_dest_oq = m.calc_tx_slice_doq_of_fabric_port_context_output_dest_oq;
            archive(::cereal::make_nvp("calc_tx_slice_doq_of_fabric_port_context_output_dest_oq", m_calc_tx_slice_doq_of_fabric_port_context_output_dest_oq));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t& m) {
        uint64_t m_calc_tx_slice_doq_of_fabric_port_context_output_dest_oq;
            archive(::cereal::make_nvp("calc_tx_slice_doq_of_fabric_port_context_output_dest_oq", m_calc_tx_slice_doq_of_fabric_port_context_output_dest_oq));
        m.calc_tx_slice_doq_of_fabric_port_context_output_dest_oq = m_calc_tx_slice_doq_of_fabric_port_context_output_dest_oq;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t& m)
{
    serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t& m)
{
    serializer_class<npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_value_t::npl_rxpdr_fe_rlb_uc_tx_fb_link_to_oq_table_payloads_t&);



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
class serializer_class<npl_sda_fabric_enable_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sda_fabric_enable_table_key_t& m) {
        uint64_t m_l2_enforcement = m.l2_enforcement;
            archive(::cereal::make_nvp("l2_enforcement", m_l2_enforcement));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sda_fabric_enable_table_key_t& m) {
        uint64_t m_l2_enforcement;
            archive(::cereal::make_nvp("l2_enforcement", m_l2_enforcement));
        m.l2_enforcement = m_l2_enforcement;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sda_fabric_enable_table_key_t& m)
{
    serializer_class<npl_sda_fabric_enable_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sda_fabric_enable_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sda_fabric_enable_table_key_t& m)
{
    serializer_class<npl_sda_fabric_enable_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sda_fabric_enable_table_key_t&);



template<>
class serializer_class<npl_sda_fabric_enable_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sda_fabric_enable_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sda_fabric_enable_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sda_fabric_enable_table_value_t& m)
{
    serializer_class<npl_sda_fabric_enable_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sda_fabric_enable_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sda_fabric_enable_table_value_t& m)
{
    serializer_class<npl_sda_fabric_enable_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sda_fabric_enable_table_value_t&);



template<>
class serializer_class<npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t& m) {
            archive(::cereal::make_nvp("sda_fabric_feature", m.sda_fabric_feature));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t& m) {
            archive(::cereal::make_nvp("sda_fabric_feature", m.sda_fabric_feature));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t& m)
{
    serializer_class<npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t& m)
{
    serializer_class<npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sda_fabric_enable_table_value_t::npl_sda_fabric_enable_table_payloads_t&);



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
class serializer_class<npl_select_mac_forwarding_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_mac_forwarding_static_table_key_t& m) {
        uint64_t m_next_proto_type = m.next_proto_type;
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
            archive(::cereal::make_nvp("use_metedata_table_per_packet_format", m.use_metedata_table_per_packet_format));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_mac_forwarding_static_table_key_t& m) {
        uint64_t m_next_proto_type;
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
            archive(::cereal::make_nvp("use_metedata_table_per_packet_format", m.use_metedata_table_per_packet_format));
        m.next_proto_type = m_next_proto_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_select_mac_forwarding_static_table_key_t& m)
{
    serializer_class<npl_select_mac_forwarding_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_mac_forwarding_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_select_mac_forwarding_static_table_key_t& m)
{
    serializer_class<npl_select_mac_forwarding_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_mac_forwarding_static_table_key_t&);



template<>
class serializer_class<npl_select_mac_forwarding_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_mac_forwarding_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_mac_forwarding_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_select_mac_forwarding_static_table_value_t& m)
{
    serializer_class<npl_select_mac_forwarding_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_mac_forwarding_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_select_mac_forwarding_static_table_value_t& m)
{
    serializer_class<npl_select_mac_forwarding_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_mac_forwarding_static_table_value_t&);



template<>
class serializer_class<npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("use_metadata_table", m.use_metadata_table));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("use_metadata_table", m.use_metadata_table));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t& m)
{
    serializer_class<npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t& m)
{
    serializer_class<npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_select_mac_forwarding_static_table_value_t::npl_select_mac_forwarding_static_table_payloads_t&);



template<>
class serializer_class<npl_service_lp_attributes_table_write_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_lp_attributes_table_write_payload_t& m) {
            archive(::cereal::make_nvp("mac_lp_attributes_payload", m.mac_lp_attributes_payload));
            archive(::cereal::make_nvp("slp", m.slp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_lp_attributes_table_write_payload_t& m) {
            archive(::cereal::make_nvp("mac_lp_attributes_payload", m.mac_lp_attributes_payload));
            archive(::cereal::make_nvp("slp", m.slp));
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
class serializer_class<npl_service_mapping0_key_lsb_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping0_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("res_a_dest", m.res_a_dest));
            archive(::cereal::make_nvp("res_b_dest", m.res_b_dest));
            archive(::cereal::make_nvp("res_c_dest", m.res_c_dest));
            archive(::cereal::make_nvp("res_d_dest", m.res_d_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping0_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("res_a_dest", m.res_a_dest));
            archive(::cereal::make_nvp("res_b_dest", m.res_b_dest));
            archive(::cereal::make_nvp("res_c_dest", m.res_c_dest));
            archive(::cereal::make_nvp("res_d_dest", m.res_d_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping0_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_service_mapping0_key_lsb_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping0_key_lsb_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping0_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_service_mapping0_key_lsb_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping0_key_lsb_mapping_table_key_t&);



template<>
class serializer_class<npl_service_mapping0_key_lsb_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping0_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping0_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping0_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_service_mapping0_key_lsb_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping0_key_lsb_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping0_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_service_mapping0_key_lsb_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping0_key_lsb_mapping_table_value_t&);



template<>
class serializer_class<npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("service_mapping0_access_attr", m.service_mapping0_access_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("service_mapping0_access_attr", m.service_mapping0_access_attr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping0_key_lsb_mapping_table_value_t::npl_service_mapping0_key_lsb_mapping_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping1_key_lsb_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping1_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("res_a_dest", m.res_a_dest));
            archive(::cereal::make_nvp("res_b_dest", m.res_b_dest));
            archive(::cereal::make_nvp("res_c_dest", m.res_c_dest));
            archive(::cereal::make_nvp("res_d_dest", m.res_d_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping1_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("res_a_dest", m.res_a_dest));
            archive(::cereal::make_nvp("res_b_dest", m.res_b_dest));
            archive(::cereal::make_nvp("res_c_dest", m.res_c_dest));
            archive(::cereal::make_nvp("res_d_dest", m.res_d_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping1_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_service_mapping1_key_lsb_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping1_key_lsb_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping1_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_service_mapping1_key_lsb_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping1_key_lsb_mapping_table_key_t&);



template<>
class serializer_class<npl_service_mapping1_key_lsb_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping1_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping1_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping1_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_service_mapping1_key_lsb_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping1_key_lsb_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping1_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_service_mapping1_key_lsb_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping1_key_lsb_mapping_table_value_t&);



template<>
class serializer_class<npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("service_mapping1_access_attr", m.service_mapping1_access_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("service_mapping1_access_attr", m.service_mapping1_access_attr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping1_key_lsb_mapping_table_value_t::npl_service_mapping1_key_lsb_mapping_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_em0_ac_port_table_write_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_table_write_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_table_write_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_table_write_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_write_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_table_write_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_table_write_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_table_write_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_table_write_payload_t&);



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
            archive(::cereal::make_nvp("write", m.write));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_table_value_t::npl_service_mapping_em0_ac_port_table_payloads_t& m) {
            archive(::cereal::make_nvp("write", m.write));
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
class serializer_class<npl_service_mapping_em0_ac_port_tag_table_write_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_write_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_write_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_table_write_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_write_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_table_write_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_write_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_table_write_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_table_write_payload_t&);



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
            archive(::cereal::make_nvp("write", m.write));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("write", m.write));
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
class serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t& m) {
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t& m)
{
    serializer_class<npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_em0_ac_port_tag_tag_table_write_payload_t&);



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
            archive(::cereal::make_nvp("write", m.write));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_em0_ac_port_tag_tag_table_value_t::npl_service_mapping_em0_ac_port_tag_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("write", m.write));
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
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
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
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
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
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_ac_port_tag_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
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
class serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("res_a_dest", m.res_a_dest));
            archive(::cereal::make_nvp("res_b_dest", m.res_b_dest));
            archive(::cereal::make_nvp("res_c_dest", m.res_c_dest));
            archive(::cereal::make_nvp("res_d_dest", m.res_d_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_key_lsb_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("res_a_dest", m.res_a_dest));
            archive(::cereal::make_nvp("res_b_dest", m.res_b_dest));
            archive(::cereal::make_nvp("res_c_dest", m.res_c_dest));
            archive(::cereal::make_nvp("res_d_dest", m.res_d_dest));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_key_lsb_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_key_lsb_mapping_table_key_t& m)
{
    serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_key_lsb_mapping_table_key_t&);



template<>
class serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_key_lsb_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_key_lsb_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_key_lsb_mapping_table_value_t& m)
{
    serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_key_lsb_mapping_table_value_t&);



template<>
class serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("service_mapping_tcam_access_attr", m.service_mapping_tcam_access_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("service_mapping_tcam_access_attr", m.service_mapping_tcam_access_attr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t& m)
{
    serializer_class<npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_mapping_tcam_key_lsb_mapping_table_value_t::npl_service_mapping_tcam_key_lsb_mapping_table_payloads_t&);



template<>
class serializer_class<npl_service_mapping_tcam_pwe_tag_table_sm_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_mapping_tcam_pwe_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id = m.relay_id;
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_mapping_tcam_pwe_tag_table_sm_payload_t& m) {
        uint64_t m_relay_id;
            archive(::cereal::make_nvp("relay_table_payload", m.relay_table_payload));
            archive(::cereal::make_nvp("relay_id", m_relay_id));
            archive(::cereal::make_nvp("lp_attr", m.lp_attr));
            archive(::cereal::make_nvp("lp_id", m.lp_id));
            archive(::cereal::make_nvp("pad", m.pad));
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
class serializer_class<npl_service_relay_id_static_table_relay_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_id_static_table_relay_payload_t& m) {
        uint64_t m_relay_id_or_l3_lp_add_attr = m.relay_id_or_l3_lp_add_attr;
            archive(::cereal::make_nvp("relay_id_or_l3_lp_add_attr", m_relay_id_or_l3_lp_add_attr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_id_static_table_relay_payload_t& m) {
        uint64_t m_relay_id_or_l3_lp_add_attr;
            archive(::cereal::make_nvp("relay_id_or_l3_lp_add_attr", m_relay_id_or_l3_lp_add_attr));
        m.relay_id_or_l3_lp_add_attr = m_relay_id_or_l3_lp_add_attr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_id_static_table_relay_payload_t& m)
{
    serializer_class<npl_service_relay_id_static_table_relay_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_id_static_table_relay_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_id_static_table_relay_payload_t& m)
{
    serializer_class<npl_service_relay_id_static_table_relay_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_id_static_table_relay_payload_t&);



template<>
class serializer_class<npl_service_relay_id_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_id_static_table_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_id_static_table_key_t& m) {
            archive(::cereal::make_nvp("relay_id", m.relay_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_id_static_table_key_t& m)
{
    serializer_class<npl_service_relay_id_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_id_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_id_static_table_key_t& m)
{
    serializer_class<npl_service_relay_id_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_id_static_table_key_t&);



template<>
class serializer_class<npl_service_relay_id_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_id_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_id_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_id_static_table_value_t& m)
{
    serializer_class<npl_service_relay_id_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_id_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_id_static_table_value_t& m)
{
    serializer_class<npl_service_relay_id_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_id_static_table_value_t&);



template<>
class serializer_class<npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("relay", m.relay));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t& m)
{
    serializer_class<npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t& m)
{
    serializer_class<npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_service_relay_id_static_table_value_t::npl_service_relay_id_static_table_payloads_t&);



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
class serializer_class<npl_sgacl_counter_bank_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_counter_bank_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_counter_bank_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_counter_bank_table_key_t& m)
{
    serializer_class<npl_sgacl_counter_bank_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_counter_bank_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_counter_bank_table_key_t& m)
{
    serializer_class<npl_sgacl_counter_bank_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_counter_bank_table_key_t&);



template<>
class serializer_class<npl_sgacl_counter_bank_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_counter_bank_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_counter_bank_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_counter_bank_table_value_t& m)
{
    serializer_class<npl_sgacl_counter_bank_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_counter_bank_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_counter_bank_table_value_t& m)
{
    serializer_class<npl_sgacl_counter_bank_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_counter_bank_table_value_t&);



template<>
class serializer_class<npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_bank_msb", m.counter_bank_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_bank_msb", m.counter_bank_msb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t& m)
{
    serializer_class<npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t& m)
{
    serializer_class<npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_counter_bank_table_value_t::npl_sgacl_counter_bank_table_payloads_t&);



template<>
class serializer_class<npl_sgacl_ip_fragment_check_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_ip_fragment_check_table_key_t& m) {
        uint64_t m_v6_not_first_frag = m.v6_not_first_frag;
        uint64_t m_v4_frag_offset = m.v4_frag_offset;
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("v6_not_first_frag", m_v6_not_first_frag));
            archive(::cereal::make_nvp("v4_frag_offset", m_v4_frag_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_ip_fragment_check_table_key_t& m) {
        uint64_t m_v6_not_first_frag;
        uint64_t m_v4_frag_offset;
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("v6_not_first_frag", m_v6_not_first_frag));
            archive(::cereal::make_nvp("v4_frag_offset", m_v4_frag_offset));
        m.v6_not_first_frag = m_v6_not_first_frag;
        m.v4_frag_offset = m_v4_frag_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_ip_fragment_check_table_key_t& m)
{
    serializer_class<npl_sgacl_ip_fragment_check_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_ip_fragment_check_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_ip_fragment_check_table_key_t& m)
{
    serializer_class<npl_sgacl_ip_fragment_check_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_ip_fragment_check_table_key_t&);



template<>
class serializer_class<npl_sgacl_ip_fragment_check_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_ip_fragment_check_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_ip_fragment_check_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_ip_fragment_check_table_value_t& m)
{
    serializer_class<npl_sgacl_ip_fragment_check_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_ip_fragment_check_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_ip_fragment_check_table_value_t& m)
{
    serializer_class<npl_sgacl_ip_fragment_check_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_ip_fragment_check_table_value_t&);



template<>
class serializer_class<npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t& m) {
        uint64_t m_first_fragment = m.first_fragment;
            archive(::cereal::make_nvp("first_fragment", m_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t& m) {
        uint64_t m_first_fragment;
            archive(::cereal::make_nvp("first_fragment", m_first_fragment));
        m.first_fragment = m_first_fragment;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t& m)
{
    serializer_class<npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t& m)
{
    serializer_class<npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_ip_fragment_check_table_value_t::npl_sgacl_ip_fragment_check_table_payloads_t&);



template<>
class serializer_class<npl_sgacl_l4_protocol_select_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_l4_protocol_select_table_key_t& m) {
        uint64_t m_mapped_protocol_valid = m.mapped_protocol_valid;
            archive(::cereal::make_nvp("is_ipv6", m.is_ipv6));
            archive(::cereal::make_nvp("mapped_protocol_valid", m_mapped_protocol_valid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_l4_protocol_select_table_key_t& m) {
        uint64_t m_mapped_protocol_valid;
            archive(::cereal::make_nvp("is_ipv6", m.is_ipv6));
            archive(::cereal::make_nvp("mapped_protocol_valid", m_mapped_protocol_valid));
        m.mapped_protocol_valid = m_mapped_protocol_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_l4_protocol_select_table_key_t& m)
{
    serializer_class<npl_sgacl_l4_protocol_select_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_l4_protocol_select_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_l4_protocol_select_table_key_t& m)
{
    serializer_class<npl_sgacl_l4_protocol_select_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_l4_protocol_select_table_key_t&);



template<>
class serializer_class<npl_sgacl_l4_protocol_select_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_l4_protocol_select_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_l4_protocol_select_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_l4_protocol_select_table_value_t& m)
{
    serializer_class<npl_sgacl_l4_protocol_select_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_l4_protocol_select_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_l4_protocol_select_table_value_t& m)
{
    serializer_class<npl_sgacl_l4_protocol_select_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_l4_protocol_select_table_value_t&);



template<>
class serializer_class<npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_next_macro_static_table_sgacl_next_macro_action_payload_t&);



template<>
class serializer_class<npl_sgacl_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_next_macro_static_table_key_t& m) {
        uint64_t m_sgacl_stage = m.sgacl_stage;
        uint64_t m_svl = m.svl;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("sgacl_stage", m_sgacl_stage));
            archive(::cereal::make_nvp("svl", m_svl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_next_macro_static_table_key_t& m) {
        uint64_t m_sgacl_stage;
        uint64_t m_svl;
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("sgacl_stage", m_sgacl_stage));
            archive(::cereal::make_nvp("svl", m_svl));
        m.sgacl_stage = m_sgacl_stage;
        m.svl = m_svl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_next_macro_static_table_key_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_next_macro_static_table_key_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_sgacl_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_next_macro_static_table_value_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_next_macro_static_table_value_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgacl_next_macro_action", m.sgacl_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgacl_next_macro_action", m.sgacl_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_sgacl_next_macro_static_table_value_t::npl_sgacl_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_sgacl_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_sgacl_table_key_t& m) {
        uint64_t m_tos = m.tos;
        uint64_t m_protocol = m.protocol;
        uint64_t m_ttl = m.ttl;
        uint64_t m_first_fragment = m.first_fragment;
        uint64_t m_sgacl_id = m.sgacl_id;
        uint64_t m_tcp_flags = m.tcp_flags;
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("ttl", m_ttl));
            archive(::cereal::make_nvp("first_fragment", m_first_fragment));
            archive(::cereal::make_nvp("sgacl_id", m_sgacl_id));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_sgacl_table_key_t& m) {
        uint64_t m_tos;
        uint64_t m_protocol;
        uint64_t m_ttl;
        uint64_t m_first_fragment;
        uint64_t m_sgacl_id;
        uint64_t m_tcp_flags;
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("tos", m_tos));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("ttl", m_ttl));
            archive(::cereal::make_nvp("first_fragment", m_first_fragment));
            archive(::cereal::make_nvp("sgacl_id", m_sgacl_id));
            archive(::cereal::make_nvp("tcp_flags", m_tcp_flags));
        m.tos = m_tos;
        m.protocol = m_protocol;
        m.ttl = m_ttl;
        m.first_fragment = m_first_fragment;
        m.sgacl_id = m_sgacl_id;
        m.tcp_flags = m_tcp_flags;
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



}

