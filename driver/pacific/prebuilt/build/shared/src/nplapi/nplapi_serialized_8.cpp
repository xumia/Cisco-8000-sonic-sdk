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

template <class Archive> void save(Archive&, const npl_curr_and_next_prot_type_t&);
template <class Archive> void load(Archive&, npl_curr_and_next_prot_type_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_exact_bank_index_len_t&);
template <class Archive> void load(Archive&, npl_exact_bank_index_len_t&);

template <class Archive> void save(Archive&, const npl_exact_meter_index_len_t&);
template <class Archive> void load(Archive&, npl_exact_meter_index_len_t&);

template <class Archive> void save(Archive&, const npl_extended_encap_data2_t&);
template <class Archive> void load(Archive&, npl_extended_encap_data2_t&);

template <class Archive> void save(Archive&, const npl_extended_encap_data_t&);
template <class Archive> void load(Archive&, npl_extended_encap_data_t&);

template <class Archive> void save(Archive&, const npl_g_ifg_len_t&);
template <class Archive> void load(Archive&, npl_g_ifg_len_t&);

template <class Archive> void save(Archive&, const npl_ifg_len_t&);
template <class Archive> void load(Archive&, npl_ifg_len_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_mc_t&);
template <class Archive> void load(Archive&, npl_ip_ver_mc_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_init_rtf_stage_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive> void save(Archive&, const npl_l2_relay_id_t&);
template <class Archive> void load(Archive&, npl_l2_relay_id_t&);

template <class Archive> void save(Archive&, const npl_lm_command_t&);
template <class Archive> void load(Archive&, npl_lm_command_t&);

template <class Archive> void save(Archive&, const npl_lp_rtf_conf_set_t&);
template <class Archive> void load(Archive&, npl_lp_rtf_conf_set_t&);

template <class Archive> void save(Archive&, const npl_lpm_prefix_fec_access_map_output_t&);
template <class Archive> void load(Archive&, npl_lpm_prefix_fec_access_map_output_t&);

template <class Archive> void save(Archive&, const npl_meter_action_profile_len_t&);
template <class Archive> void load(Archive&, npl_meter_action_profile_len_t&);

template <class Archive> void save(Archive&, const npl_meter_profile_len_t&);
template <class Archive> void load(Archive&, npl_meter_profile_len_t&);

template <class Archive> void save(Archive&, const npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t&);
template <class Archive> void load(Archive&, npl_pd_rx_nw_app_t_anonymous_union_init_recycle_fields_union_t&);

template <class Archive> void save(Archive&, const npl_per_rtf_step_og_pcl_compress_bits_t&);
template <class Archive> void load(Archive&, npl_per_rtf_step_og_pcl_compress_bits_t&);

template <class Archive> void save(Archive&, const npl_per_rtf_step_og_pcl_ids_t&);
template <class Archive> void load(Archive&, npl_per_rtf_step_og_pcl_ids_t&);

template <class Archive> void save(Archive&, const npl_phb_t&);
template <class Archive> void load(Archive&, npl_phb_t&);

template <class Archive> void save(Archive&, const npl_post_fwd_params_t&);
template <class Archive> void load(Archive&, npl_post_fwd_params_t&);

template <class Archive> void save(Archive&, const npl_punt_encap_data_lsb_t&);
template <class Archive> void load(Archive&, npl_punt_encap_data_lsb_t&);

template <class Archive> void save(Archive&, const npl_punt_nw_encap_ptr_t&);
template <class Archive> void load(Archive&, npl_punt_nw_encap_ptr_t&);

template <class Archive> void save(Archive&, const npl_punt_ssp_attributes_t&);
template <class Archive> void load(Archive&, npl_punt_ssp_attributes_t&);

template <class Archive> void save(Archive&, const npl_punt_tunnel_transport_encap_table_ip_gre_payload_t&);
template <class Archive> void load(Archive&, npl_punt_tunnel_transport_encap_table_ip_gre_payload_t&);

template <class Archive> void save(Archive&, const npl_pwe_to_l3_lookup_result_t&);
template <class Archive> void load(Archive&, npl_pwe_to_l3_lookup_result_t&);

template <class Archive> void save(Archive&, const npl_rate_limiters_port_packet_type_index_len_t&);
template <class Archive> void load(Archive&, npl_rate_limiters_port_packet_type_index_len_t&);

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

template <class Archive> void save(Archive&, const npl_scanner_id_t&);
template <class Archive> void load(Archive&, npl_scanner_id_t&);

template <class Archive> void save(Archive&, const npl_stat_bank_index_len_t&);
template <class Archive> void load(Archive&, npl_stat_bank_index_len_t&);

template <class Archive> void save(Archive&, const npl_stat_meter_index_len_t&);
template <class Archive> void load(Archive&, npl_stat_meter_index_len_t&);

template <class Archive> void save(Archive&, const npl_trap_conditions_t&);
template <class Archive> void load(Archive&, npl_trap_conditions_t&);

template <class Archive> void save(Archive&, const npl_traps_t&);
template <class Archive> void load(Archive&, npl_traps_t&);

template <class Archive> void save(Archive&, const npl_ts_command_t&);
template <class Archive> void load(Archive&, npl_ts_command_t&);

template <class Archive> void save(Archive&, const npl_tx_to_rx_rcy_data_t&);
template <class Archive> void load(Archive&, npl_tx_to_rx_rcy_data_t&);

template <class Archive> void save(Archive&, const npl_vpn_label_encap_data_t&);
template <class Archive> void load(Archive&, npl_vpn_label_encap_data_t&);

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
        uint64_t m_initial_layer_index = m.initial_layer_index;
        uint64_t m_np_macro_id = m.np_macro_id;
        uint64_t m_fi_macro_id = m.fi_macro_id;
            archive(::cereal::make_nvp("override_source_port_table", m_override_source_port_table));
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
        uint64_t m_initial_layer_index;
        uint64_t m_np_macro_id;
        uint64_t m_fi_macro_id;
            archive(::cereal::make_nvp("override_source_port_table", m_override_source_port_table));
            archive(::cereal::make_nvp("initial_layer_index", m_initial_layer_index));
            archive(::cereal::make_nvp("initial_rx_data", m.initial_rx_data));
            archive(::cereal::make_nvp("tag_swap_cmd", m.tag_swap_cmd));
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
            archive(::cereal::make_nvp("fi_macro_id", m_fi_macro_id));
        m.override_source_port_table = m_override_source_port_table;
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
class serializer_class<npl_resolution_pfc_select_table_update_pfc_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_pfc_select_table_update_pfc_payload_t& m) {
        uint64_t m_pfc_sample = m.pfc_sample;
        uint64_t m_pfc_direct_sample = m.pfc_direct_sample;
            archive(::cereal::make_nvp("pfc_enable", m.pfc_enable));
            archive(::cereal::make_nvp("pfc_sample", m_pfc_sample));
            archive(::cereal::make_nvp("pfc_direct_sample", m_pfc_direct_sample));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_pfc_select_table_update_pfc_payload_t& m) {
        uint64_t m_pfc_sample;
        uint64_t m_pfc_direct_sample;
            archive(::cereal::make_nvp("pfc_enable", m.pfc_enable));
            archive(::cereal::make_nvp("pfc_sample", m_pfc_sample));
            archive(::cereal::make_nvp("pfc_direct_sample", m_pfc_direct_sample));
        m.pfc_sample = m_pfc_sample;
        m.pfc_direct_sample = m_pfc_direct_sample;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_pfc_select_table_update_pfc_payload_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_update_pfc_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_pfc_select_table_update_pfc_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_pfc_select_table_update_pfc_payload_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_update_pfc_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_pfc_select_table_update_pfc_payload_t&);



template<>
class serializer_class<npl_resolution_pfc_select_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_pfc_select_table_key_t& m) {
        uint64_t m_rx_time = m.rx_time;
        uint64_t m_tc = m.tc;
            archive(::cereal::make_nvp("rx_time", m_rx_time));
            archive(::cereal::make_nvp("tc", m_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_pfc_select_table_key_t& m) {
        uint64_t m_rx_time;
        uint64_t m_tc;
            archive(::cereal::make_nvp("rx_time", m_rx_time));
            archive(::cereal::make_nvp("tc", m_tc));
        m.rx_time = m_rx_time;
        m.tc = m_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_pfc_select_table_key_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_pfc_select_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_pfc_select_table_key_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_pfc_select_table_key_t&);



template<>
class serializer_class<npl_resolution_pfc_select_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_pfc_select_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_pfc_select_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_pfc_select_table_value_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_pfc_select_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_pfc_select_table_value_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_pfc_select_table_value_t&);



template<>
class serializer_class<npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_pfc", m.update_pfc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_pfc", m.update_pfc));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t& m)
{
    serializer_class<npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_resolution_pfc_select_table_value_t::npl_resolution_pfc_select_table_payloads_t&);



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
class serializer_class<npl_rewrite_sa_prefix_index_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rewrite_sa_prefix_index_table_key_t& m) {
        uint64_t m_rewrite_sa_index = m.rewrite_sa_index;
            archive(::cereal::make_nvp("rewrite_sa_index", m_rewrite_sa_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rewrite_sa_prefix_index_table_key_t& m) {
        uint64_t m_rewrite_sa_index;
            archive(::cereal::make_nvp("rewrite_sa_index", m_rewrite_sa_index));
        m.rewrite_sa_index = m_rewrite_sa_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rewrite_sa_prefix_index_table_key_t& m)
{
    serializer_class<npl_rewrite_sa_prefix_index_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rewrite_sa_prefix_index_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_rewrite_sa_prefix_index_table_key_t& m)
{
    serializer_class<npl_rewrite_sa_prefix_index_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rewrite_sa_prefix_index_table_key_t&);



template<>
class serializer_class<npl_rewrite_sa_prefix_index_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rewrite_sa_prefix_index_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rewrite_sa_prefix_index_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rewrite_sa_prefix_index_table_value_t& m)
{
    serializer_class<npl_rewrite_sa_prefix_index_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rewrite_sa_prefix_index_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_rewrite_sa_prefix_index_table_value_t& m)
{
    serializer_class<npl_rewrite_sa_prefix_index_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rewrite_sa_prefix_index_table_value_t&);



template<>
class serializer_class<npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t& m) {
        uint64_t m_sa_msb = m.sa_msb;
            archive(::cereal::make_nvp("sa_msb", m_sa_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t& m) {
        uint64_t m_sa_msb;
            archive(::cereal::make_nvp("sa_msb", m_sa_msb));
        m.sa_msb = m_sa_msb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t& m)
{
    serializer_class<npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t& m)
{
    serializer_class<npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_rewrite_sa_prefix_index_table_value_t::npl_rewrite_sa_prefix_index_table_payloads_t&);



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
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rpf_fec_table_found_payload_t& m) {
            archive(::cereal::make_nvp("dst", m.dst));
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
class serializer_class<npl_rx_counters_block_config_table_config_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_rx_counters_block_config_table_config_payload_t& m) {
        uint64_t m_inc_bank_for_ifg_b = m.inc_bank_for_ifg_b;
        uint64_t m_inc_addr_for_set = m.inc_addr_for_set;
            archive(::cereal::make_nvp("inc_bank_for_ifg_b", m_inc_bank_for_ifg_b));
            archive(::cereal::make_nvp("inc_addr_for_set", m_inc_addr_for_set));
            archive(::cereal::make_nvp("bank_set_type", m.bank_set_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_block_config_table_config_payload_t& m) {
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
        uint64_t m_counter_block_id = m.counter_block_id;
            archive(::cereal::make_nvp("counter_block_id", m_counter_block_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_rx_counters_block_config_table_key_t& m) {
        uint64_t m_counter_block_id;
            archive(::cereal::make_nvp("counter_block_id", m_counter_block_id));
        m.counter_block_id = m_counter_block_id;
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



}

