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

template <class Archive> void save(Archive&, const npl_aux_table_key_t&);
template <class Archive> void load(Archive&, npl_aux_table_key_t&);

template <class Archive> void save(Archive&, const npl_aux_table_result_t&);
template <class Archive> void load(Archive&, npl_aux_table_result_t&);

template <class Archive> void save(Archive&, const npl_bool_t&);
template <class Archive> void load(Archive&, npl_bool_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ene_macro_id_t&);
template <class Archive> void load(Archive&, npl_ene_macro_id_t&);

template <class Archive> void save(Archive&, const npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t&);
template <class Archive> void load(Archive&, npl_erpp_fabric_counters_offset_table_update_counter_offset_payload_t&);

template <class Archive> void save(Archive&, const npl_eth_rtf_iteration_properties_t&);
template <class Archive> void load(Archive&, npl_eth_rtf_iteration_properties_t&);

template <class Archive> void save(Archive&, const npl_event_queue_address_t&);
template <class Archive> void load(Archive&, npl_event_queue_address_t&);

template <class Archive> void save(Archive&, const npl_event_to_send_t&);
template <class Archive> void load(Archive&, npl_event_to_send_t&);

template <class Archive> void save(Archive&, const npl_fabric_cfg_t&);
template <class Archive> void load(Archive&, npl_fabric_cfg_t&);

template <class Archive> void save(Archive&, const npl_fabric_header_start_template_t_anonymous_union_ctrl_t&);
template <class Archive> void load(Archive&, npl_fabric_header_start_template_t_anonymous_union_ctrl_t&);

template <class Archive> void save(Archive&, const npl_fb_link_2_link_bundle_table_result_t&);
template <class Archive> void load(Archive&, npl_fb_link_2_link_bundle_table_result_t&);

template <class Archive> void save(Archive&, const npl_fe_broadcast_bmp_table_result_t&);
template <class Archive> void load(Archive&, npl_fe_broadcast_bmp_table_result_t&);

template <class Archive> void save(Archive&, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t&);
template <class Archive> void load(Archive&, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_result_t&);

template <class Archive> void save(Archive&, const npl_fe_uc_bundle_selected_link_t&);
template <class Archive> void load(Archive&, npl_fe_uc_bundle_selected_link_t&);

template <class Archive> void save(Archive&, const npl_fe_uc_link_bundle_desc_table_result_t&);
template <class Archive> void load(Archive&, npl_fe_uc_link_bundle_desc_table_result_t&);

template <class Archive> void save(Archive&, const npl_fe_uc_random_fb_link_t&);
template <class Archive> void load(Archive&, npl_fe_uc_random_fb_link_t&);

template <class Archive> void save(Archive&, const npl_fi_core_tcam_assoc_data_t&);
template <class Archive> void load(Archive&, npl_fi_core_tcam_assoc_data_t&);

template <class Archive> void save(Archive&, const npl_fi_macro_config_data_t&);
template <class Archive> void load(Archive&, npl_fi_macro_config_data_t&);

template <class Archive> void save(Archive&, const npl_filb_voq_mapping_result_t&);
template <class Archive> void load(Archive&, npl_filb_voq_mapping_result_t&);

template <class Archive> void save(Archive&, const npl_frm_db_fabric_routing_table_result_t&);
template <class Archive> void load(Archive&, npl_frm_db_fabric_routing_table_result_t&);

template <class Archive> void save(Archive&, const npl_hmc_cgm_cgm_lut_results_t&);
template <class Archive> void load(Archive&, npl_hmc_cgm_cgm_lut_results_t&);

template <class Archive> void save(Archive&, const npl_hmc_cgm_profile_global_results_t&);
template <class Archive> void load(Archive&, npl_hmc_cgm_profile_global_results_t&);

template <class Archive> void save(Archive&, const npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t&);
template <class Archive> void load(Archive&, npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t&);

template <class Archive> void save(Archive&, const npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t&);
template <class Archive> void load(Archive&, npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t&);

template <class Archive> void save(Archive&, const npl_ive_enable_t&);
template <class Archive> void load(Archive&, npl_ive_enable_t&);

template <class Archive> void save(Archive&, const npl_l2_rtf_conf_set_and_init_stages_t&);
template <class Archive> void load(Archive&, npl_l2_rtf_conf_set_and_init_stages_t&);

template <class Archive> void save(Archive&, const npl_lp_rtf_conf_set_t&);
template <class Archive> void load(Archive&, npl_lp_rtf_conf_set_t&);

template <class Archive> void save(Archive&, const npl_mcid_array_t&);
template <class Archive> void load(Archive&, npl_mcid_array_t&);

template <class Archive> void save(Archive&, const npl_mcid_t&);
template <class Archive> void load(Archive&, npl_mcid_t&);

template <class Archive> void save(Archive&, const npl_mismatch_indications_t&);
template <class Archive> void load(Archive&, npl_mismatch_indications_t&);

template <class Archive> void save(Archive&, const npl_random_bc_bmp_entry_t&);
template <class Archive> void load(Archive&, npl_random_bc_bmp_entry_t&);

template <class Archive> void save(Archive&, const npl_rtf_step_t&);
template <class Archive> void load(Archive&, npl_rtf_step_t&);

template <class Archive> void save(Archive&, const npl_svi_eve_sub_type_plus_prf_t&);
template <class Archive> void load(Archive&, npl_svi_eve_sub_type_plus_prf_t&);

template <class Archive> void save(Archive&, const npl_voq_profile_len&);
template <class Archive> void load(Archive&, npl_voq_profile_len&);

template<>
class serializer_class<npl_erpp_fabric_counters_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_offset_table_value_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_offset_table_value_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_offset_table_value_t&);



template<>
class serializer_class<npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_counter_offset", m.update_counter_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_counter_offset", m.update_counter_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t& m)
{
    serializer_class<npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_offset_table_value_t::npl_erpp_fabric_counters_offset_table_payloads_t&);



template<>
class serializer_class<npl_erpp_fabric_counters_table_update_counters_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_table_update_counters_payload_t& m) {
        uint64_t m_debug_conter_valid = m.debug_conter_valid;
            archive(::cereal::make_nvp("debug_conter_valid", m_debug_conter_valid));
            archive(::cereal::make_nvp("debug_counter_ptr", m.debug_counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_table_update_counters_payload_t& m) {
        uint64_t m_debug_conter_valid;
            archive(::cereal::make_nvp("debug_conter_valid", m_debug_conter_valid));
            archive(::cereal::make_nvp("debug_counter_ptr", m.debug_counter_ptr));
        m.debug_conter_valid = m_debug_conter_valid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_table_update_counters_payload_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_update_counters_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_table_update_counters_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_table_update_counters_payload_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_update_counters_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_table_update_counters_payload_t&);



template<>
class serializer_class<npl_erpp_fabric_counters_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_table_key_t& m) {
        uint64_t m_dest_device = m.dest_device;
        uint64_t m_dest_slice = m.dest_slice;
        uint64_t m_dest_oq = m.dest_oq;
            archive(::cereal::make_nvp("dest_device", m_dest_device));
            archive(::cereal::make_nvp("dest_slice", m_dest_slice));
            archive(::cereal::make_nvp("dest_oq", m_dest_oq));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_table_key_t& m) {
        uint64_t m_dest_device;
        uint64_t m_dest_slice;
        uint64_t m_dest_oq;
            archive(::cereal::make_nvp("dest_device", m_dest_device));
            archive(::cereal::make_nvp("dest_slice", m_dest_slice));
            archive(::cereal::make_nvp("dest_oq", m_dest_oq));
        m.dest_device = m_dest_device;
        m.dest_slice = m_dest_slice;
        m.dest_oq = m_dest_oq;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_table_key_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_table_key_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_table_key_t&);



template<>
class serializer_class<npl_erpp_fabric_counters_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_table_value_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_table_value_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_table_value_t&);



template<>
class serializer_class<npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_counters", m.update_counters));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_counters", m.update_counters));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t& m)
{
    serializer_class<npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_erpp_fabric_counters_table_value_t::npl_erpp_fabric_counters_table_payloads_t&);



template<>
class serializer_class<npl_eth_meter_profile_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_meter_profile_mapping_table_key_t& m) {
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_meter_profile_mapping_table_key_t& m) {
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_meter_profile_mapping_table_key_t& m)
{
    serializer_class<npl_eth_meter_profile_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_meter_profile_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_meter_profile_mapping_table_key_t& m)
{
    serializer_class<npl_eth_meter_profile_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_meter_profile_mapping_table_key_t&);



template<>
class serializer_class<npl_eth_meter_profile_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_meter_profile_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_meter_profile_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_meter_profile_mapping_table_value_t& m)
{
    serializer_class<npl_eth_meter_profile_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_meter_profile_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_meter_profile_mapping_table_value_t& m)
{
    serializer_class<npl_eth_meter_profile_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_meter_profile_mapping_table_value_t&);



template<>
class serializer_class<npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t& m) {
        uint64_t m_slp_qos_id = m.slp_qos_id;
            archive(::cereal::make_nvp("slp_qos_id", m_slp_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t& m) {
        uint64_t m_slp_qos_id;
            archive(::cereal::make_nvp("slp_qos_id", m_slp_qos_id));
        m.slp_qos_id = m_slp_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t& m)
{
    serializer_class<npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t& m)
{
    serializer_class<npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_meter_profile_mapping_table_value_t::npl_eth_meter_profile_mapping_table_payloads_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc2_static_table_set_da_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_set_da_payload_t& m) {
        uint64_t m_da = m.da;
            archive(::cereal::make_nvp("da", m_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_set_da_payload_t& m) {
        uint64_t m_da;
            archive(::cereal::make_nvp("da", m_da));
        m.da = m_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_set_da_payload_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_set_da_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc2_static_table_set_da_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_set_da_payload_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_set_da_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc2_static_table_set_da_payload_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc2_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_key_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc2_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_key_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc2_static_table_key_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc2_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_value_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc2_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_value_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc2_static_table_value_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_da", m.set_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_da", m.set_da));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc2_static_table_value_t::npl_eth_oam_set_da_mc2_static_table_payloads_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc_static_table_set_da_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_set_da_payload_t& m) {
        uint64_t m_da = m.da;
            archive(::cereal::make_nvp("da", m_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc_static_table_set_da_payload_t& m) {
        uint64_t m_da;
            archive(::cereal::make_nvp("da", m_da));
        m.da = m_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_set_da_payload_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_set_da_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc_static_table_set_da_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc_static_table_set_da_payload_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_set_da_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc_static_table_set_da_payload_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc_static_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_key_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc_static_table_key_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc_static_table_key_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_value_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc_static_table_value_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc_static_table_value_t&);



template<>
class serializer_class<npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_da", m.set_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_da", m.set_da));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t& m)
{
    serializer_class<npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_oam_set_da_mc_static_table_value_t::npl_eth_oam_set_da_mc_static_table_payloads_t&);



template<>
class serializer_class<npl_eth_rtf_conf_set_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rtf_conf_set_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rtf_conf_set_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rtf_conf_set_mapping_table_key_t& m)
{
    serializer_class<npl_eth_rtf_conf_set_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rtf_conf_set_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rtf_conf_set_mapping_table_key_t& m)
{
    serializer_class<npl_eth_rtf_conf_set_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rtf_conf_set_mapping_table_key_t&);



template<>
class serializer_class<npl_eth_rtf_conf_set_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rtf_conf_set_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rtf_conf_set_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rtf_conf_set_mapping_table_value_t& m)
{
    serializer_class<npl_eth_rtf_conf_set_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rtf_conf_set_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rtf_conf_set_mapping_table_value_t& m)
{
    serializer_class<npl_eth_rtf_conf_set_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rtf_conf_set_mapping_table_value_t&);



template<>
class serializer_class<npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("eth_rtf_iteration_prop", m.eth_rtf_iteration_prop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("eth_rtf_iteration_prop", m.eth_rtf_iteration_prop));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t& m)
{
    serializer_class<npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t& m)
{
    serializer_class<npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rtf_conf_set_mapping_table_value_t::npl_eth_rtf_conf_set_mapping_table_payloads_t&);



template<>
class serializer_class<npl_eve_byte_addition_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eve_byte_addition_static_table_key_t& m) {
        uint64_t m_padding_vars_eve_27_26_ = m.padding_vars_eve_27_26_;
        uint64_t m_padding_vars_eve_16_14_ = m.padding_vars_eve_16_14_;
            archive(::cereal::make_nvp("padding_vars_eve_27_26_", m_padding_vars_eve_27_26_));
            archive(::cereal::make_nvp("padding_vars_eve_16_14_", m_padding_vars_eve_16_14_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eve_byte_addition_static_table_key_t& m) {
        uint64_t m_padding_vars_eve_27_26_;
        uint64_t m_padding_vars_eve_16_14_;
            archive(::cereal::make_nvp("padding_vars_eve_27_26_", m_padding_vars_eve_27_26_));
            archive(::cereal::make_nvp("padding_vars_eve_16_14_", m_padding_vars_eve_16_14_));
        m.padding_vars_eve_27_26_ = m_padding_vars_eve_27_26_;
        m.padding_vars_eve_16_14_ = m_padding_vars_eve_16_14_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eve_byte_addition_static_table_key_t& m)
{
    serializer_class<npl_eve_byte_addition_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eve_byte_addition_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_eve_byte_addition_static_table_key_t& m)
{
    serializer_class<npl_eve_byte_addition_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eve_byte_addition_static_table_key_t&);



template<>
class serializer_class<npl_eve_byte_addition_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eve_byte_addition_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eve_byte_addition_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eve_byte_addition_static_table_value_t& m)
{
    serializer_class<npl_eve_byte_addition_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eve_byte_addition_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_eve_byte_addition_static_table_value_t& m)
{
    serializer_class<npl_eve_byte_addition_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eve_byte_addition_static_table_value_t&);



template<>
class serializer_class<npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t& m) {
        uint64_t m_padding_vars_eve_byte_addition = m.padding_vars_eve_byte_addition;
            archive(::cereal::make_nvp("padding_vars_eve_byte_addition", m_padding_vars_eve_byte_addition));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t& m) {
        uint64_t m_padding_vars_eve_byte_addition;
            archive(::cereal::make_nvp("padding_vars_eve_byte_addition", m_padding_vars_eve_byte_addition));
        m.padding_vars_eve_byte_addition = m_padding_vars_eve_byte_addition;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t& m)
{
    serializer_class<npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t& m)
{
    serializer_class<npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eve_byte_addition_static_table_value_t::npl_eve_byte_addition_static_table_payloads_t&);



template<>
class serializer_class<npl_eve_to_ethernet_ene_static_table_set_value_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_set_value_payload_t& m) {
        uint64_t m_ene_encap_tpid = m.ene_encap_tpid;
            archive(::cereal::make_nvp("ene_encap_tpid", m_ene_encap_tpid));
            archive(::cereal::make_nvp("ene_encap_macro_id", m.ene_encap_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eve_to_ethernet_ene_static_table_set_value_payload_t& m) {
        uint64_t m_ene_encap_tpid;
            archive(::cereal::make_nvp("ene_encap_tpid", m_ene_encap_tpid));
            archive(::cereal::make_nvp("ene_encap_macro_id", m.ene_encap_macro_id));
        m.ene_encap_tpid = m_ene_encap_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_set_value_payload_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_set_value_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eve_to_ethernet_ene_static_table_set_value_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_eve_to_ethernet_ene_static_table_set_value_payload_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_set_value_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eve_to_ethernet_ene_static_table_set_value_payload_t&);



template<>
class serializer_class<npl_eve_to_ethernet_ene_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_key_t& m) {
            archive(::cereal::make_nvp("main_type", m.main_type));
            archive(::cereal::make_nvp("sub_type", m.sub_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eve_to_ethernet_ene_static_table_key_t& m) {
            archive(::cereal::make_nvp("main_type", m.main_type));
            archive(::cereal::make_nvp("sub_type", m.sub_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_key_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eve_to_ethernet_ene_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_eve_to_ethernet_ene_static_table_key_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eve_to_ethernet_ene_static_table_key_t&);



template<>
class serializer_class<npl_eve_to_ethernet_ene_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eve_to_ethernet_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_value_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eve_to_ethernet_ene_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_eve_to_ethernet_ene_static_table_value_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eve_to_ethernet_ene_static_table_value_t&);



template<>
class serializer_class<npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t& m)
{
    serializer_class<npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eve_to_ethernet_ene_static_table_value_t::npl_eve_to_ethernet_ene_static_table_payloads_t&);



template<>
class serializer_class<npl_event_queue_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_event_queue_table_key_t& m) {
            archive(::cereal::make_nvp("event_queue_address", m.event_queue_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_event_queue_table_key_t& m) {
            archive(::cereal::make_nvp("event_queue_address", m.event_queue_address));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_event_queue_table_key_t& m)
{
    serializer_class<npl_event_queue_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_event_queue_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_event_queue_table_key_t& m)
{
    serializer_class<npl_event_queue_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_event_queue_table_key_t&);



template<>
class serializer_class<npl_event_queue_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_event_queue_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_event_queue_table_value_t& m)
{
    serializer_class<npl_event_queue_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_event_queue_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_event_queue_table_value_t& m)
{
    serializer_class<npl_event_queue_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_event_queue_table_value_t&);



template<>
class serializer_class<npl_event_queue_table_value_t::npl_event_queue_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_event_queue_table_value_t::npl_event_queue_table_payloads_t& m) {
            archive(::cereal::make_nvp("event_queue_result", m.event_queue_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_event_queue_table_value_t::npl_event_queue_table_payloads_t& m) {
            archive(::cereal::make_nvp("event_queue_result", m.event_queue_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_event_queue_table_value_t::npl_event_queue_table_payloads_t& m)
{
    serializer_class<npl_event_queue_table_value_t::npl_event_queue_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_event_queue_table_value_t::npl_event_queue_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_event_queue_table_value_t::npl_event_queue_table_payloads_t& m)
{
    serializer_class<npl_event_queue_table_value_t::npl_event_queue_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_event_queue_table_value_t::npl_event_queue_table_payloads_t&);



template<>
class serializer_class<npl_external_aux_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_external_aux_table_key_t& m) {
            archive(::cereal::make_nvp("aux_table_key", m.aux_table_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_external_aux_table_key_t& m) {
            archive(::cereal::make_nvp("aux_table_key", m.aux_table_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_external_aux_table_key_t& m)
{
    serializer_class<npl_external_aux_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_external_aux_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_external_aux_table_key_t& m)
{
    serializer_class<npl_external_aux_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_external_aux_table_key_t&);



template<>
class serializer_class<npl_external_aux_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_external_aux_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_external_aux_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_external_aux_table_value_t& m)
{
    serializer_class<npl_external_aux_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_external_aux_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_external_aux_table_value_t& m)
{
    serializer_class<npl_external_aux_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_external_aux_table_value_t&);



template<>
class serializer_class<npl_external_aux_table_value_t::npl_external_aux_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_external_aux_table_value_t::npl_external_aux_table_payloads_t& m) {
            archive(::cereal::make_nvp("aux_table_result", m.aux_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_external_aux_table_value_t::npl_external_aux_table_payloads_t& m) {
            archive(::cereal::make_nvp("aux_table_result", m.aux_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_external_aux_table_value_t::npl_external_aux_table_payloads_t& m)
{
    serializer_class<npl_external_aux_table_value_t::npl_external_aux_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_external_aux_table_value_t::npl_external_aux_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_external_aux_table_value_t::npl_external_aux_table_payloads_t& m)
{
    serializer_class<npl_external_aux_table_value_t::npl_external_aux_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_external_aux_table_value_t::npl_external_aux_table_payloads_t&);



template<>
class serializer_class<npl_fabric_and_tm_header_size_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_and_tm_header_size_static_table_key_t& m) {
        uint64_t m_npuh_size = m.npuh_size;
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
            archive(::cereal::make_nvp("tm_header_type", m.tm_header_type));
            archive(::cereal::make_nvp("npuh_size", m_npuh_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_and_tm_header_size_static_table_key_t& m) {
        uint64_t m_npuh_size;
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
            archive(::cereal::make_nvp("tm_header_type", m.tm_header_type));
            archive(::cereal::make_nvp("npuh_size", m_npuh_size));
        m.npuh_size = m_npuh_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_and_tm_header_size_static_table_key_t& m)
{
    serializer_class<npl_fabric_and_tm_header_size_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_and_tm_header_size_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_and_tm_header_size_static_table_key_t& m)
{
    serializer_class<npl_fabric_and_tm_header_size_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_and_tm_header_size_static_table_key_t&);



template<>
class serializer_class<npl_fabric_and_tm_header_size_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_and_tm_header_size_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_and_tm_header_size_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_and_tm_header_size_static_table_value_t& m)
{
    serializer_class<npl_fabric_and_tm_header_size_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_and_tm_header_size_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_and_tm_header_size_static_table_value_t& m)
{
    serializer_class<npl_fabric_and_tm_header_size_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_and_tm_header_size_static_table_value_t&);



template<>
class serializer_class<npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t& m) {
        uint64_t m_fabric_tm_npu_headers_size = m.fabric_tm_npu_headers_size;
            archive(::cereal::make_nvp("fabric_tm_npu_headers_size", m_fabric_tm_npu_headers_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t& m) {
        uint64_t m_fabric_tm_npu_headers_size;
            archive(::cereal::make_nvp("fabric_tm_npu_headers_size", m_fabric_tm_npu_headers_size));
        m.fabric_tm_npu_headers_size = m_fabric_tm_npu_headers_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_and_tm_header_size_static_table_value_t::npl_fabric_and_tm_header_size_static_table_payloads_t&);



template<>
class serializer_class<npl_fabric_header_ene_macro_table_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_ene_macro_table_update_payload_t& m) {
            archive(::cereal::make_nvp("ene_macro_id", m.ene_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_ene_macro_table_update_payload_t& m) {
            archive(::cereal::make_nvp("ene_macro_id", m.ene_macro_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_ene_macro_table_update_payload_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_ene_macro_table_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_ene_macro_table_update_payload_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_ene_macro_table_update_payload_t&);



template<>
class serializer_class<npl_fabric_header_ene_macro_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_ene_macro_table_key_t& m) {
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_ene_macro_table_key_t& m) {
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_ene_macro_table_key_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_ene_macro_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_ene_macro_table_key_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_ene_macro_table_key_t&);



template<>
class serializer_class<npl_fabric_header_ene_macro_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_ene_macro_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_ene_macro_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_ene_macro_table_value_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_ene_macro_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_ene_macro_table_value_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_ene_macro_table_value_t&);



template<>
class serializer_class<npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t& m)
{
    serializer_class<npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_ene_macro_table_value_t::npl_fabric_header_ene_macro_table_payloads_t&);



template<>
class serializer_class<npl_fabric_header_types_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_types_static_table_key_t& m) {
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_types_static_table_key_t& m) {
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_types_static_table_key_t& m)
{
    serializer_class<npl_fabric_header_types_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_types_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_types_static_table_key_t& m)
{
    serializer_class<npl_fabric_header_types_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_types_static_table_key_t&);



template<>
class serializer_class<npl_fabric_header_types_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_types_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_types_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_types_static_table_value_t& m)
{
    serializer_class<npl_fabric_header_types_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_types_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_types_static_table_value_t& m)
{
    serializer_class<npl_fabric_header_types_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_types_static_table_value_t&);



template<>
class serializer_class<npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("fabric_header_type_ok", m.fabric_header_type_ok));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("fabric_header_type_ok", m.fabric_header_type_ok));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_header_types_static_table_value_t::npl_fabric_header_types_static_table_payloads_t&);



template<>
class serializer_class<npl_fabric_headers_type_table_update_fabric_local_vars_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_headers_type_table_update_fabric_local_vars_payload_t& m) {
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_headers_type_table_update_fabric_local_vars_payload_t& m) {
            archive(::cereal::make_nvp("fabric_header_type", m.fabric_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_headers_type_table_update_fabric_local_vars_payload_t& m)
{
    serializer_class<npl_fabric_headers_type_table_update_fabric_local_vars_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_headers_type_table_update_fabric_local_vars_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_headers_type_table_update_fabric_local_vars_payload_t& m)
{
    serializer_class<npl_fabric_headers_type_table_update_fabric_local_vars_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_headers_type_table_update_fabric_local_vars_payload_t&);



template<>
class serializer_class<npl_fabric_headers_type_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_headers_type_table_key_t& m) {
        uint64_t m_start_packing = m.start_packing;
            archive(::cereal::make_nvp("initial_fabric_header_type", m.initial_fabric_header_type));
            archive(::cereal::make_nvp("plb_header_type", m.plb_header_type));
            archive(::cereal::make_nvp("start_packing", m_start_packing));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_headers_type_table_key_t& m) {
        uint64_t m_start_packing;
            archive(::cereal::make_nvp("initial_fabric_header_type", m.initial_fabric_header_type));
            archive(::cereal::make_nvp("plb_header_type", m.plb_header_type));
            archive(::cereal::make_nvp("start_packing", m_start_packing));
        m.start_packing = m_start_packing;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_headers_type_table_key_t& m)
{
    serializer_class<npl_fabric_headers_type_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_headers_type_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_headers_type_table_key_t& m)
{
    serializer_class<npl_fabric_headers_type_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_headers_type_table_key_t&);



template<>
class serializer_class<npl_fabric_headers_type_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_headers_type_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_headers_type_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_headers_type_table_value_t& m)
{
    serializer_class<npl_fabric_headers_type_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_headers_type_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_headers_type_table_value_t& m)
{
    serializer_class<npl_fabric_headers_type_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_headers_type_table_value_t&);



template<>
class serializer_class<npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_fabric_local_vars", m.update_fabric_local_vars));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_fabric_local_vars", m.update_fabric_local_vars));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t& m)
{
    serializer_class<npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t& m)
{
    serializer_class<npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_headers_type_table_value_t::npl_fabric_headers_type_table_payloads_t&);



template<>
class serializer_class<npl_fabric_init_cfg_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_init_cfg_update_payload_t& m) {
            archive(::cereal::make_nvp("fabric_init_cfg_hit_", m.fabric_init_cfg_hit_));
            archive(::cereal::make_nvp("fabric_cfg_", m.fabric_cfg_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_init_cfg_update_payload_t& m) {
            archive(::cereal::make_nvp("fabric_init_cfg_hit_", m.fabric_init_cfg_hit_));
            archive(::cereal::make_nvp("fabric_cfg_", m.fabric_cfg_));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_init_cfg_update_payload_t& m)
{
    serializer_class<npl_fabric_init_cfg_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_init_cfg_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_init_cfg_update_payload_t& m)
{
    serializer_class<npl_fabric_init_cfg_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_init_cfg_update_payload_t&);



template<>
class serializer_class<npl_fabric_init_cfg_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_init_cfg_key_t& m) {
        uint64_t m_ser = m.ser;
            archive(::cereal::make_nvp("ser", m_ser));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_init_cfg_key_t& m) {
        uint64_t m_ser;
            archive(::cereal::make_nvp("ser", m_ser));
        m.ser = m_ser;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_init_cfg_key_t& m)
{
    serializer_class<npl_fabric_init_cfg_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_init_cfg_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_init_cfg_key_t& m)
{
    serializer_class<npl_fabric_init_cfg_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_init_cfg_key_t&);



template<>
class serializer_class<npl_fabric_init_cfg_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_init_cfg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_init_cfg_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_init_cfg_value_t& m)
{
    serializer_class<npl_fabric_init_cfg_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_init_cfg_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_init_cfg_value_t& m)
{
    serializer_class<npl_fabric_init_cfg_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_init_cfg_value_t&);



template<>
class serializer_class<npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t& m)
{
    serializer_class<npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t& m)
{
    serializer_class<npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_init_cfg_value_t::npl_fabric_init_cfg_payloads_t&);



template<>
class serializer_class<npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t& m) {
        uint64_t m_is_inject_pkt = m.is_inject_pkt;
        uint64_t m_is_network_pkt = m.is_network_pkt;
        uint64_t m_ene_with_soft_npuh = m.ene_with_soft_npuh;
        uint64_t m_npuh_size = m.npuh_size;
            archive(::cereal::make_nvp("is_inject_pkt", m_is_inject_pkt));
            archive(::cereal::make_nvp("is_network_pkt", m_is_network_pkt));
            archive(::cereal::make_nvp("ene_with_soft_npuh", m_ene_with_soft_npuh));
            archive(::cereal::make_nvp("npuh_size", m_npuh_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t& m) {
        uint64_t m_is_inject_pkt;
        uint64_t m_is_network_pkt;
        uint64_t m_ene_with_soft_npuh;
        uint64_t m_npuh_size;
            archive(::cereal::make_nvp("is_inject_pkt", m_is_inject_pkt));
            archive(::cereal::make_nvp("is_network_pkt", m_is_network_pkt));
            archive(::cereal::make_nvp("ene_with_soft_npuh", m_ene_with_soft_npuh));
            archive(::cereal::make_nvp("npuh_size", m_npuh_size));
        m.is_inject_pkt = m_is_inject_pkt;
        m.is_network_pkt = m_is_network_pkt;
        m.ene_with_soft_npuh = m_ene_with_soft_npuh;
        m.npuh_size = m_npuh_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_npuh_size_calculation_static_table_update_npuh_size_payload_t&);



template<>
class serializer_class<npl_fabric_npuh_size_calculation_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_key_t& m) {
        uint64_t m_device_tx_cud_msb_4bits = m.device_tx_cud_msb_4bits;
            archive(::cereal::make_nvp("device_tx_cud_msb_4bits", m_device_tx_cud_msb_4bits));
            archive(::cereal::make_nvp("packet_tx_npu_header_fwd_header_type", m.packet_tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type", m.packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type));
            archive(::cereal::make_nvp("packet_tx_npu_header_is_inject_up", m.packet_tx_npu_header_is_inject_up));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_key_t& m) {
        uint64_t m_device_tx_cud_msb_4bits;
            archive(::cereal::make_nvp("device_tx_cud_msb_4bits", m_device_tx_cud_msb_4bits));
            archive(::cereal::make_nvp("packet_tx_npu_header_fwd_header_type", m.packet_tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type", m.packet_tx_npu_header_encap_encapsulation_type_redirect_encap_type));
            archive(::cereal::make_nvp("packet_tx_npu_header_is_inject_up", m.packet_tx_npu_header_is_inject_up));
        m.device_tx_cud_msb_4bits = m_device_tx_cud_msb_4bits;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_key_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_npuh_size_calculation_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_key_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_npuh_size_calculation_static_table_key_t&);



template<>
class serializer_class<npl_fabric_npuh_size_calculation_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_value_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_npuh_size_calculation_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_value_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_npuh_size_calculation_static_table_value_t&);



template<>
class serializer_class<npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_npuh_size", m.update_npuh_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_npuh_size", m.update_npuh_size));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_npuh_size_calculation_static_table_value_t::npl_fabric_npuh_size_calculation_static_table_payloads_t&);



template<>
class serializer_class<npl_fabric_out_color_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_out_color_map_table_key_t& m) {
        uint64_t m_out_color = m.out_color;
            archive(::cereal::make_nvp("out_color", m_out_color));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_out_color_map_table_key_t& m) {
        uint64_t m_out_color;
            archive(::cereal::make_nvp("out_color", m_out_color));
        m.out_color = m_out_color;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_out_color_map_table_key_t& m)
{
    serializer_class<npl_fabric_out_color_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_out_color_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_out_color_map_table_key_t& m)
{
    serializer_class<npl_fabric_out_color_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_out_color_map_table_key_t&);



template<>
class serializer_class<npl_fabric_out_color_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_out_color_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_out_color_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_out_color_map_table_value_t& m)
{
    serializer_class<npl_fabric_out_color_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_out_color_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_out_color_map_table_value_t& m)
{
    serializer_class<npl_fabric_out_color_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_out_color_map_table_value_t&);



template<>
class serializer_class<npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t& m) {
        uint64_t m_dp = m.dp;
            archive(::cereal::make_nvp("dp", m_dp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t& m) {
        uint64_t m_dp;
            archive(::cereal::make_nvp("dp", m_dp));
        m.dp = m_dp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t& m)
{
    serializer_class<npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t& m)
{
    serializer_class<npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_out_color_map_table_value_t::npl_fabric_out_color_map_table_payloads_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_counter_table_update_result_payload_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_key_t& m) {
        uint64_t m_ser = m.ser;
        uint64_t m_error_code = m.error_code;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("error_code", m_error_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_key_t& m) {
        uint64_t m_ser;
        uint64_t m_error_code;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("error_code", m_error_code));
        m.ser = m_ser;
        m.error_code = m_error_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_counter_table_key_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_counter_table_value_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_counter_table_value_t::npl_fabric_rx_fwd_error_handling_counter_table_payloads_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_destination_table_update_result_payload_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_key_t& m) {
        uint64_t m_ser = m.ser;
        uint64_t m_error_code = m.error_code;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("error_code", m_error_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_key_t& m) {
        uint64_t m_ser;
        uint64_t m_error_code;
            archive(::cereal::make_nvp("ser", m_ser));
            archive(::cereal::make_nvp("error_code", m_error_code));
        m.ser = m_ser;
        m.error_code = m_error_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_destination_table_key_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_destination_table_value_t&);



template<>
class serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_fwd_error_handling_destination_table_value_t::npl_fabric_rx_fwd_error_handling_destination_table_payloads_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t& m) {
            archive(::cereal::make_nvp("counter", m.counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_counter_table_update_result_payload_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_key_t& m) {
        uint64_t m_ser = m.ser;
            archive(::cereal::make_nvp("ser", m_ser));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_key_t& m) {
        uint64_t m_ser;
            archive(::cereal::make_nvp("ser", m_ser));
        m.ser = m_ser;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_key_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_counter_table_key_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_value_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_counter_table_value_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_counter_table_value_t::npl_fabric_rx_term_error_handling_counter_table_payloads_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination = m.destination;
            archive(::cereal::make_nvp("destination", m_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t& m) {
        uint64_t m_destination;
            archive(::cereal::make_nvp("destination", m_destination));
        m.destination = m_destination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_destination_table_update_result_payload_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_key_t& m) {
        uint64_t m_ser = m.ser;
            archive(::cereal::make_nvp("ser", m_ser));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_key_t& m) {
        uint64_t m_ser;
            archive(::cereal::make_nvp("ser", m_ser));
        m.ser = m_ser;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_key_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_destination_table_key_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_value_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_destination_table_value_t&);



template<>
class serializer_class<npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_result", m.update_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t& m)
{
    serializer_class<npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_rx_term_error_handling_destination_table_value_t::npl_fabric_rx_term_error_handling_destination_table_payloads_t&);



template<>
class serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t& m) {
        uint64_t m_smcid_lsb = m.smcid_lsb;
            archive(::cereal::make_nvp("smcid_lsb", m_smcid_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t& m) {
        uint64_t m_smcid_lsb;
            archive(::cereal::make_nvp("smcid_lsb", m_smcid_lsb));
        m.smcid_lsb = m_smcid_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t& m)
{
    serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t& m)
{
    serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_scaled_mc_map_to_netork_slice_static_table_key_t&);



template<>
class serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t& m)
{
    serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t& m)
{
    serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t&);



template<>
class serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("network_slice_mcid", m.network_slice_mcid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("network_slice_mcid", m.network_slice_mcid));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_scaled_mc_map_to_netork_slice_static_table_value_t::npl_fabric_scaled_mc_map_to_netork_slice_static_table_payloads_t&);



template<>
class serializer_class<npl_fabric_smcid_threshold_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_smcid_threshold_table_key_t& m) {
        uint64_t m_dummy = m.dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_smcid_threshold_table_key_t& m) {
        uint64_t m_dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
        m.dummy = m_dummy;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_smcid_threshold_table_key_t& m)
{
    serializer_class<npl_fabric_smcid_threshold_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_smcid_threshold_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_smcid_threshold_table_key_t& m)
{
    serializer_class<npl_fabric_smcid_threshold_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_smcid_threshold_table_key_t&);



template<>
class serializer_class<npl_fabric_smcid_threshold_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_smcid_threshold_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_smcid_threshold_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_smcid_threshold_table_value_t& m)
{
    serializer_class<npl_fabric_smcid_threshold_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_smcid_threshold_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_smcid_threshold_table_value_t& m)
{
    serializer_class<npl_fabric_smcid_threshold_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_smcid_threshold_table_value_t&);



template<>
class serializer_class<npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t& m) {
            archive(::cereal::make_nvp("smcid_threshold", m.smcid_threshold));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t& m) {
            archive(::cereal::make_nvp("smcid_threshold", m.smcid_threshold));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t& m)
{
    serializer_class<npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t& m)
{
    serializer_class<npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_smcid_threshold_table_value_t::npl_fabric_smcid_threshold_table_payloads_t&);



template<>
class serializer_class<npl_fabric_term_error_checker_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_term_error_checker_static_table_key_t& m) {
        uint64_t m_is_keepalive = m.is_keepalive;
            archive(::cereal::make_nvp("is_keepalive", m_is_keepalive));
            archive(::cereal::make_nvp("fabric_header_type_ok", m.fabric_header_type_ok));
            archive(::cereal::make_nvp("fabric_init_cfg_table_hit", m.fabric_init_cfg_table_hit));
            archive(::cereal::make_nvp("mismatch_indications", m.mismatch_indications));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_term_error_checker_static_table_key_t& m) {
        uint64_t m_is_keepalive;
            archive(::cereal::make_nvp("is_keepalive", m_is_keepalive));
            archive(::cereal::make_nvp("fabric_header_type_ok", m.fabric_header_type_ok));
            archive(::cereal::make_nvp("fabric_init_cfg_table_hit", m.fabric_init_cfg_table_hit));
            archive(::cereal::make_nvp("mismatch_indications", m.mismatch_indications));
        m.is_keepalive = m_is_keepalive;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_term_error_checker_static_table_key_t& m)
{
    serializer_class<npl_fabric_term_error_checker_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_term_error_checker_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_term_error_checker_static_table_key_t& m)
{
    serializer_class<npl_fabric_term_error_checker_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_term_error_checker_static_table_key_t&);



template<>
class serializer_class<npl_fabric_term_error_checker_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_term_error_checker_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_term_error_checker_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_term_error_checker_static_table_value_t& m)
{
    serializer_class<npl_fabric_term_error_checker_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_term_error_checker_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_term_error_checker_static_table_value_t& m)
{
    serializer_class<npl_fabric_term_error_checker_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_term_error_checker_static_table_value_t&);



template<>
class serializer_class<npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t& m) {
        uint64_t m_pd_fabric_error_event_error_code = m.pd_fabric_error_event_error_code;
            archive(::cereal::make_nvp("pd_fabric_error_event_error_code", m_pd_fabric_error_event_error_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t& m) {
        uint64_t m_pd_fabric_error_event_error_code;
            archive(::cereal::make_nvp("pd_fabric_error_event_error_code", m_pd_fabric_error_event_error_code));
        m.pd_fabric_error_event_error_code = m_pd_fabric_error_event_error_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_term_error_checker_static_table_value_t::npl_fabric_term_error_checker_static_table_payloads_t&);



template<>
class serializer_class<npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t& m) {
        uint64_t m_ingress_multicast = m.ingress_multicast;
            archive(::cereal::make_nvp("ingress_multicast", m_ingress_multicast));
            archive(::cereal::make_nvp("tm_header_type", m.tm_header_type));
            archive(::cereal::make_nvp("initial_fabric_header_type", m.initial_fabric_header_type));
            archive(::cereal::make_nvp("ctrl", m.ctrl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t& m) {
        uint64_t m_ingress_multicast;
            archive(::cereal::make_nvp("ingress_multicast", m_ingress_multicast));
            archive(::cereal::make_nvp("tm_header_type", m.tm_header_type));
            archive(::cereal::make_nvp("initial_fabric_header_type", m.initial_fabric_header_type));
            archive(::cereal::make_nvp("ctrl", m.ctrl));
        m.ingress_multicast = m_ingress_multicast;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_tm_headers_table_update_fabric_local_vars_payload_t&);



template<>
class serializer_class<npl_fabric_tm_headers_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_tm_headers_table_key_t& m) {
        uint64_t m_tx_cud_prefix = m.tx_cud_prefix;
            archive(::cereal::make_nvp("fabric_oq_type", m.fabric_oq_type));
            archive(::cereal::make_nvp("tx_cud_prefix", m_tx_cud_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_tm_headers_table_key_t& m) {
        uint64_t m_tx_cud_prefix;
            archive(::cereal::make_nvp("fabric_oq_type", m.fabric_oq_type));
            archive(::cereal::make_nvp("tx_cud_prefix", m_tx_cud_prefix));
        m.tx_cud_prefix = m_tx_cud_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_tm_headers_table_key_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_tm_headers_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_tm_headers_table_key_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_tm_headers_table_key_t&);



template<>
class serializer_class<npl_fabric_tm_headers_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_tm_headers_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_tm_headers_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_tm_headers_table_value_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_tm_headers_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_tm_headers_table_value_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_tm_headers_table_value_t&);



template<>
class serializer_class<npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_fabric_local_vars", m.update_fabric_local_vars));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t& m) {
            archive(::cereal::make_nvp("update_fabric_local_vars", m.update_fabric_local_vars));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t& m)
{
    serializer_class<npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_tm_headers_table_value_t::npl_fabric_tm_headers_table_payloads_t&);



template<>
class serializer_class<npl_fabric_transmit_error_checker_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_transmit_error_checker_static_table_key_t& m) {
        uint64_t m_npu_header = m.npu_header;
        uint64_t m_expected_issu = m.expected_issu;
        uint64_t m_pkt_issu = m.pkt_issu;
            archive(::cereal::make_nvp("npu_header", m_npu_header));
            archive(::cereal::make_nvp("fabric_init_cfg_table_hit", m.fabric_init_cfg_table_hit));
            archive(::cereal::make_nvp("expected_issu", m_expected_issu));
            archive(::cereal::make_nvp("pkt_issu", m_pkt_issu));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_transmit_error_checker_static_table_key_t& m) {
        uint64_t m_npu_header;
        uint64_t m_expected_issu;
        uint64_t m_pkt_issu;
            archive(::cereal::make_nvp("npu_header", m_npu_header));
            archive(::cereal::make_nvp("fabric_init_cfg_table_hit", m.fabric_init_cfg_table_hit));
            archive(::cereal::make_nvp("expected_issu", m_expected_issu));
            archive(::cereal::make_nvp("pkt_issu", m_pkt_issu));
        m.npu_header = m_npu_header;
        m.expected_issu = m_expected_issu;
        m.pkt_issu = m_pkt_issu;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_transmit_error_checker_static_table_key_t& m)
{
    serializer_class<npl_fabric_transmit_error_checker_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_transmit_error_checker_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_transmit_error_checker_static_table_key_t& m)
{
    serializer_class<npl_fabric_transmit_error_checker_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_transmit_error_checker_static_table_key_t&);



template<>
class serializer_class<npl_fabric_transmit_error_checker_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_transmit_error_checker_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_transmit_error_checker_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_transmit_error_checker_static_table_value_t& m)
{
    serializer_class<npl_fabric_transmit_error_checker_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_transmit_error_checker_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_transmit_error_checker_static_table_value_t& m)
{
    serializer_class<npl_fabric_transmit_error_checker_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_transmit_error_checker_static_table_value_t&);



template<>
class serializer_class<npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t& m) {
        uint64_t m_fabric_error_event_error_code = m.fabric_error_event_error_code;
            archive(::cereal::make_nvp("fabric_error_event_error_code", m_fabric_error_event_error_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t& m) {
        uint64_t m_fabric_error_event_error_code;
            archive(::cereal::make_nvp("fabric_error_event_error_code", m_fabric_error_event_error_code));
        m.fabric_error_event_error_code = m_fabric_error_event_error_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t& m)
{
    serializer_class<npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fabric_transmit_error_checker_static_table_value_t::npl_fabric_transmit_error_checker_static_table_payloads_t&);



template<>
class serializer_class<npl_fb_link_2_link_bundle_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fb_link_2_link_bundle_table_key_t& m) {
            archive(::cereal::make_nvp("fe_uc_random_fb_link", m.fe_uc_random_fb_link));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fb_link_2_link_bundle_table_key_t& m) {
            archive(::cereal::make_nvp("fe_uc_random_fb_link", m.fe_uc_random_fb_link));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fb_link_2_link_bundle_table_key_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fb_link_2_link_bundle_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fb_link_2_link_bundle_table_key_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fb_link_2_link_bundle_table_key_t&);



template<>
class serializer_class<npl_fb_link_2_link_bundle_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fb_link_2_link_bundle_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fb_link_2_link_bundle_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fb_link_2_link_bundle_table_value_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fb_link_2_link_bundle_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fb_link_2_link_bundle_table_value_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fb_link_2_link_bundle_table_value_t&);



template<>
class serializer_class<npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t& m) {
            archive(::cereal::make_nvp("fb_link_2_link_bundle_table_result", m.fb_link_2_link_bundle_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t& m) {
            archive(::cereal::make_nvp("fb_link_2_link_bundle_table_result", m.fb_link_2_link_bundle_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t& m)
{
    serializer_class<npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fb_link_2_link_bundle_table_value_t::npl_fb_link_2_link_bundle_table_payloads_t&);



template<>
class serializer_class<npl_fe_broadcast_bmp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_broadcast_bmp_table_key_t& m) {
            archive(::cereal::make_nvp("random_bc_bmp_entry", m.random_bc_bmp_entry));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_broadcast_bmp_table_key_t& m) {
            archive(::cereal::make_nvp("random_bc_bmp_entry", m.random_bc_bmp_entry));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_broadcast_bmp_table_key_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_broadcast_bmp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_broadcast_bmp_table_key_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_broadcast_bmp_table_key_t&);



template<>
class serializer_class<npl_fe_broadcast_bmp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_broadcast_bmp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_broadcast_bmp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_broadcast_bmp_table_value_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_broadcast_bmp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_broadcast_bmp_table_value_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_broadcast_bmp_table_value_t&);



template<>
class serializer_class<npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t& m) {
            archive(::cereal::make_nvp("fe_broadcast_bmp_table_result", m.fe_broadcast_bmp_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t& m) {
            archive(::cereal::make_nvp("fe_broadcast_bmp_table_result", m.fe_broadcast_bmp_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t& m)
{
    serializer_class<npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_broadcast_bmp_table_value_t::npl_fe_broadcast_bmp_table_payloads_t&);



template<>
class serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t& m) {
            archive(::cereal::make_nvp("fe_uc_bundle_selected_link", m.fe_uc_bundle_selected_link));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t& m) {
            archive(::cereal::make_nvp("fe_uc_bundle_selected_link", m.fe_uc_bundle_selected_link));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_key_t&);



template<>
class serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t&);



template<>
class serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("fe_rlb_uc_tx_fb_link_to_oq_map_table_result", m.fe_rlb_uc_tx_fb_link_to_oq_map_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("fe_rlb_uc_tx_fb_link_to_oq_map_table_result", m.fe_rlb_uc_tx_fb_link_to_oq_map_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t& m)
{
    serializer_class<npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_value_t::npl_fe_rlb_uc_tx_fb_link_to_oq_map_table_payloads_t&);



template<>
class serializer_class<npl_fe_smcid_threshold_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_smcid_threshold_table_key_t& m) {
        uint64_t m_dummy = m.dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_smcid_threshold_table_key_t& m) {
        uint64_t m_dummy;
            archive(::cereal::make_nvp("dummy", m_dummy));
        m.dummy = m_dummy;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_smcid_threshold_table_key_t& m)
{
    serializer_class<npl_fe_smcid_threshold_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_smcid_threshold_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_smcid_threshold_table_key_t& m)
{
    serializer_class<npl_fe_smcid_threshold_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_smcid_threshold_table_key_t&);



template<>
class serializer_class<npl_fe_smcid_threshold_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_smcid_threshold_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_smcid_threshold_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_smcid_threshold_table_value_t& m)
{
    serializer_class<npl_fe_smcid_threshold_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_smcid_threshold_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_smcid_threshold_table_value_t& m)
{
    serializer_class<npl_fe_smcid_threshold_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_smcid_threshold_table_value_t&);



template<>
class serializer_class<npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t& m) {
            archive(::cereal::make_nvp("smcid_threshold", m.smcid_threshold));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t& m) {
            archive(::cereal::make_nvp("smcid_threshold", m.smcid_threshold));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t& m)
{
    serializer_class<npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t& m)
{
    serializer_class<npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_smcid_threshold_table_value_t::npl_fe_smcid_threshold_table_payloads_t&);



template<>
class serializer_class<npl_fe_smcid_to_mcid_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_smcid_to_mcid_table_key_t& m) {
        uint64_t m_system_mcid_17_3 = m.system_mcid_17_3;
            archive(::cereal::make_nvp("system_mcid_17_3", m_system_mcid_17_3));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_smcid_to_mcid_table_key_t& m) {
        uint64_t m_system_mcid_17_3;
            archive(::cereal::make_nvp("system_mcid_17_3", m_system_mcid_17_3));
        m.system_mcid_17_3 = m_system_mcid_17_3;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_smcid_to_mcid_table_key_t& m)
{
    serializer_class<npl_fe_smcid_to_mcid_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_smcid_to_mcid_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_smcid_to_mcid_table_key_t& m)
{
    serializer_class<npl_fe_smcid_to_mcid_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_smcid_to_mcid_table_key_t&);



template<>
class serializer_class<npl_fe_smcid_to_mcid_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_smcid_to_mcid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_smcid_to_mcid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_smcid_to_mcid_table_value_t& m)
{
    serializer_class<npl_fe_smcid_to_mcid_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_smcid_to_mcid_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_smcid_to_mcid_table_value_t& m)
{
    serializer_class<npl_fe_smcid_to_mcid_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_smcid_to_mcid_table_value_t&);



template<>
class serializer_class<npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t& m) {
            archive(::cereal::make_nvp("mcid_array", m.mcid_array));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t& m) {
            archive(::cereal::make_nvp("mcid_array", m.mcid_array));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t& m)
{
    serializer_class<npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t& m)
{
    serializer_class<npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_smcid_to_mcid_table_value_t::npl_fe_smcid_to_mcid_table_payloads_t&);



template<>
class serializer_class<npl_fe_uc_link_bundle_desc_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_key_t& m) {
        uint64_t m_fb_link_2_link_bundle_table_result_bundle_num = m.fb_link_2_link_bundle_table_result_bundle_num;
            archive(::cereal::make_nvp("fb_link_2_link_bundle_table_result_bundle_num", m_fb_link_2_link_bundle_table_result_bundle_num));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_uc_link_bundle_desc_table_key_t& m) {
        uint64_t m_fb_link_2_link_bundle_table_result_bundle_num;
            archive(::cereal::make_nvp("fb_link_2_link_bundle_table_result_bundle_num", m_fb_link_2_link_bundle_table_result_bundle_num));
        m.fb_link_2_link_bundle_table_result_bundle_num = m_fb_link_2_link_bundle_table_result_bundle_num;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_key_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_uc_link_bundle_desc_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_uc_link_bundle_desc_table_key_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_uc_link_bundle_desc_table_key_t&);



template<>
class serializer_class<npl_fe_uc_link_bundle_desc_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_uc_link_bundle_desc_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_value_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_uc_link_bundle_desc_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_uc_link_bundle_desc_table_value_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_uc_link_bundle_desc_table_value_t&);



template<>
class serializer_class<npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t& m) {
            archive(::cereal::make_nvp("fe_uc_link_bundle_desc_table_result", m.fe_uc_link_bundle_desc_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t& m) {
            archive(::cereal::make_nvp("fe_uc_link_bundle_desc_table_result", m.fe_uc_link_bundle_desc_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t& m)
{
    serializer_class<npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fe_uc_link_bundle_desc_table_value_t::npl_fe_uc_link_bundle_desc_table_payloads_t&);



template<>
class serializer_class<npl_fi_core_tcam_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_core_tcam_table_key_t& m) {
        uint64_t m_fi_macro = m.fi_macro;
        uint64_t m_header_data = m.header_data;
            archive(::cereal::make_nvp("fi_macro", m_fi_macro));
            archive(::cereal::make_nvp("header_data", m_header_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_core_tcam_table_key_t& m) {
        uint64_t m_fi_macro;
        uint64_t m_header_data;
            archive(::cereal::make_nvp("fi_macro", m_fi_macro));
            archive(::cereal::make_nvp("header_data", m_header_data));
        m.fi_macro = m_fi_macro;
        m.header_data = m_header_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_fi_core_tcam_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_core_tcam_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_fi_core_tcam_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_core_tcam_table_key_t&);



template<>
class serializer_class<npl_fi_core_tcam_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_fi_core_tcam_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_core_tcam_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_fi_core_tcam_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_core_tcam_table_value_t&);



template<>
class serializer_class<npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("fi_core_tcam_assoc_data", m.fi_core_tcam_assoc_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("fi_core_tcam_assoc_data", m.fi_core_tcam_assoc_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_core_tcam_table_value_t::npl_fi_core_tcam_table_payloads_t&);



template<>
class serializer_class<npl_fi_macro_config_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_macro_config_table_key_t& m) {
        uint64_t m_fi_macro = m.fi_macro;
            archive(::cereal::make_nvp("fi_macro", m_fi_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_macro_config_table_key_t& m) {
        uint64_t m_fi_macro;
            archive(::cereal::make_nvp("fi_macro", m_fi_macro));
        m.fi_macro = m_fi_macro;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_macro_config_table_key_t& m)
{
    serializer_class<npl_fi_macro_config_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_macro_config_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_macro_config_table_key_t& m)
{
    serializer_class<npl_fi_macro_config_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_macro_config_table_key_t&);



template<>
class serializer_class<npl_fi_macro_config_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_macro_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_macro_config_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_macro_config_table_value_t& m)
{
    serializer_class<npl_fi_macro_config_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_macro_config_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_macro_config_table_value_t& m)
{
    serializer_class<npl_fi_macro_config_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_macro_config_table_value_t&);



template<>
class serializer_class<npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("fi_macro_config_data", m.fi_macro_config_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t& m) {
            archive(::cereal::make_nvp("fi_macro_config_data", m.fi_macro_config_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t& m)
{
    serializer_class<npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t& m)
{
    serializer_class<npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fi_macro_config_table_value_t::npl_fi_macro_config_table_payloads_t&);



template<>
class serializer_class<npl_filb_voq_mapping_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_filb_voq_mapping_key_t& m) {
        uint64_t m_rxpdr_output_voq_nr = m.rxpdr_output_voq_nr;
            archive(::cereal::make_nvp("rxpdr_output_voq_nr", m_rxpdr_output_voq_nr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_filb_voq_mapping_key_t& m) {
        uint64_t m_rxpdr_output_voq_nr;
            archive(::cereal::make_nvp("rxpdr_output_voq_nr", m_rxpdr_output_voq_nr));
        m.rxpdr_output_voq_nr = m_rxpdr_output_voq_nr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_filb_voq_mapping_key_t& m)
{
    serializer_class<npl_filb_voq_mapping_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_filb_voq_mapping_key_t&);

template <class Archive>
void
load(Archive& archive, npl_filb_voq_mapping_key_t& m)
{
    serializer_class<npl_filb_voq_mapping_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_filb_voq_mapping_key_t&);



template<>
class serializer_class<npl_filb_voq_mapping_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_filb_voq_mapping_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_filb_voq_mapping_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_filb_voq_mapping_value_t& m)
{
    serializer_class<npl_filb_voq_mapping_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_filb_voq_mapping_value_t&);

template <class Archive>
void
load(Archive& archive, npl_filb_voq_mapping_value_t& m)
{
    serializer_class<npl_filb_voq_mapping_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_filb_voq_mapping_value_t&);



template<>
class serializer_class<npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t& m) {
            archive(::cereal::make_nvp("filb_voq_mapping_result", m.filb_voq_mapping_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t& m) {
            archive(::cereal::make_nvp("filb_voq_mapping_result", m.filb_voq_mapping_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t& m)
{
    serializer_class<npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t& m)
{
    serializer_class<npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_filb_voq_mapping_value_t::npl_filb_voq_mapping_payloads_t&);



template<>
class serializer_class<npl_first_ene_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_first_ene_static_table_key_t& m) {
            archive(::cereal::make_nvp("first_macro_code", m.first_macro_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_first_ene_static_table_key_t& m) {
            archive(::cereal::make_nvp("first_macro_code", m.first_macro_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_first_ene_static_table_key_t& m)
{
    serializer_class<npl_first_ene_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_first_ene_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_first_ene_static_table_key_t& m)
{
    serializer_class<npl_first_ene_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_first_ene_static_table_key_t&);



template<>
class serializer_class<npl_first_ene_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_first_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_first_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_first_ene_static_table_value_t& m)
{
    serializer_class<npl_first_ene_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_first_ene_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_first_ene_static_table_value_t& m)
{
    serializer_class<npl_first_ene_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_first_ene_static_table_value_t&);



template<>
class serializer_class<npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("first_ene_macro", m.first_ene_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("first_ene_macro", m.first_ene_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t& m)
{
    serializer_class<npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t& m)
{
    serializer_class<npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_first_ene_static_table_value_t::npl_first_ene_static_table_payloads_t&);



template<>
class serializer_class<npl_frm_db_fabric_routing_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_frm_db_fabric_routing_table_key_t& m) {
        uint64_t m_egress_device_id = m.egress_device_id;
            archive(::cereal::make_nvp("egress_device_id", m_egress_device_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_frm_db_fabric_routing_table_key_t& m) {
        uint64_t m_egress_device_id;
            archive(::cereal::make_nvp("egress_device_id", m_egress_device_id));
        m.egress_device_id = m_egress_device_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_frm_db_fabric_routing_table_key_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_frm_db_fabric_routing_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_frm_db_fabric_routing_table_key_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_frm_db_fabric_routing_table_key_t&);



template<>
class serializer_class<npl_frm_db_fabric_routing_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_frm_db_fabric_routing_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_frm_db_fabric_routing_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_frm_db_fabric_routing_table_value_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_frm_db_fabric_routing_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_frm_db_fabric_routing_table_value_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_frm_db_fabric_routing_table_value_t&);



template<>
class serializer_class<npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t& m) {
            archive(::cereal::make_nvp("frm_db_fabric_routing_table_result", m.frm_db_fabric_routing_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t& m) {
            archive(::cereal::make_nvp("frm_db_fabric_routing_table_result", m.frm_db_fabric_routing_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t& m)
{
    serializer_class<npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_frm_db_fabric_routing_table_value_t::npl_frm_db_fabric_routing_table_payloads_t&);



template<>
class serializer_class<npl_fwd_destination_to_tm_result_data_found_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_destination_to_tm_result_data_found_payload_t& m) {
        uint64_t m_tx_cud = m.tx_cud;
        uint64_t m_dest_slice_id = m.dest_slice_id;
        uint64_t m_dest_pif = m.dest_pif;
        uint64_t m_dest_ifg = m.dest_ifg;
            archive(::cereal::make_nvp("tx_cud", m_tx_cud));
            archive(::cereal::make_nvp("dest_slice_id", m_dest_slice_id));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
            archive(::cereal::make_nvp("dest_ifg", m_dest_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_destination_to_tm_result_data_found_payload_t& m) {
        uint64_t m_tx_cud;
        uint64_t m_dest_slice_id;
        uint64_t m_dest_pif;
        uint64_t m_dest_ifg;
            archive(::cereal::make_nvp("tx_cud", m_tx_cud));
            archive(::cereal::make_nvp("dest_slice_id", m_dest_slice_id));
            archive(::cereal::make_nvp("dest_pif", m_dest_pif));
            archive(::cereal::make_nvp("dest_ifg", m_dest_ifg));
        m.tx_cud = m_tx_cud;
        m.dest_slice_id = m_dest_slice_id;
        m.dest_pif = m_dest_pif;
        m.dest_ifg = m_dest_ifg;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_destination_to_tm_result_data_found_payload_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_found_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_destination_to_tm_result_data_found_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_destination_to_tm_result_data_found_payload_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_found_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_destination_to_tm_result_data_found_payload_t&);



template<>
class serializer_class<npl_fwd_destination_to_tm_result_data_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_destination_to_tm_result_data_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_raw = m.rxpp_pd_fwd_destination_raw;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_raw", m_rxpp_pd_fwd_destination_raw));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_destination_to_tm_result_data_key_t& m) {
        uint64_t m_rxpp_pd_fwd_destination_raw;
            archive(::cereal::make_nvp("rxpp_pd_fwd_destination_raw", m_rxpp_pd_fwd_destination_raw));
        m.rxpp_pd_fwd_destination_raw = m_rxpp_pd_fwd_destination_raw;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_destination_to_tm_result_data_key_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_destination_to_tm_result_data_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_destination_to_tm_result_data_key_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_destination_to_tm_result_data_key_t&);



template<>
class serializer_class<npl_fwd_destination_to_tm_result_data_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_destination_to_tm_result_data_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_destination_to_tm_result_data_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_destination_to_tm_result_data_value_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_destination_to_tm_result_data_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_destination_to_tm_result_data_value_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_destination_to_tm_result_data_value_t&);



template<>
class serializer_class<npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t& m) {
            archive(::cereal::make_nvp("found", m.found));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t& m)
{
    serializer_class<npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_destination_to_tm_result_data_value_t::npl_fwd_destination_to_tm_result_data_payloads_t&);



template<>
class serializer_class<npl_fwd_type_to_ive_enable_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_type_to_ive_enable_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_npe_to_npe_metadata_fwd_header_type", m.txpp_npe_to_npe_metadata_fwd_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_type_to_ive_enable_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_npe_to_npe_metadata_fwd_header_type", m.txpp_npe_to_npe_metadata_fwd_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_type_to_ive_enable_table_key_t& m)
{
    serializer_class<npl_fwd_type_to_ive_enable_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_type_to_ive_enable_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_type_to_ive_enable_table_key_t& m)
{
    serializer_class<npl_fwd_type_to_ive_enable_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_type_to_ive_enable_table_key_t&);



template<>
class serializer_class<npl_fwd_type_to_ive_enable_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_type_to_ive_enable_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_type_to_ive_enable_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_type_to_ive_enable_table_value_t& m)
{
    serializer_class<npl_fwd_type_to_ive_enable_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_type_to_ive_enable_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_type_to_ive_enable_table_value_t& m)
{
    serializer_class<npl_fwd_type_to_ive_enable_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_type_to_ive_enable_table_value_t&);



template<>
class serializer_class<npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_type_to_ive_enable", m.fwd_type_to_ive_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_type_to_ive_enable", m.fwd_type_to_ive_enable));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t& m)
{
    serializer_class<npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t& m)
{
    serializer_class<npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_type_to_ive_enable_table_value_t::npl_fwd_type_to_ive_enable_table_payloads_t&);



template<>
class serializer_class<npl_get_ecm_meter_ptr_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_ecm_meter_ptr_table_key_t& m) {
        uint64_t m_tm_h_ecn = m.tm_h_ecn;
        uint64_t m_tm_h_dp_0 = m.tm_h_dp_0;
            archive(::cereal::make_nvp("tm_h_ecn", m_tm_h_ecn));
            archive(::cereal::make_nvp("tm_h_dp_0", m_tm_h_dp_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_ecm_meter_ptr_table_key_t& m) {
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
save(Archive& archive, const npl_get_ecm_meter_ptr_table_key_t& m)
{
    serializer_class<npl_get_ecm_meter_ptr_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_ecm_meter_ptr_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_get_ecm_meter_ptr_table_key_t& m)
{
    serializer_class<npl_get_ecm_meter_ptr_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_ecm_meter_ptr_table_key_t&);



template<>
class serializer_class<npl_get_ecm_meter_ptr_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_ecm_meter_ptr_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_ecm_meter_ptr_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_ecm_meter_ptr_table_value_t& m)
{
    serializer_class<npl_get_ecm_meter_ptr_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_ecm_meter_ptr_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_get_ecm_meter_ptr_table_value_t& m)
{
    serializer_class<npl_get_ecm_meter_ptr_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_ecm_meter_ptr_table_value_t&);



template<>
class serializer_class<npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t& m) {
            archive(::cereal::make_nvp("stat_meter_ptr", m.stat_meter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t& m) {
            archive(::cereal::make_nvp("stat_meter_ptr", m.stat_meter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t& m)
{
    serializer_class<npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t& m)
{
    serializer_class<npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_ecm_meter_ptr_table_value_t::npl_get_ecm_meter_ptr_table_payloads_t&);



template<>
class serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t& m) {
        uint64_t m_enable_sr_dm_accounting = m.enable_sr_dm_accounting;
        uint64_t m_enable_transparent_ptp = m.enable_transparent_ptp;
            archive(::cereal::make_nvp("enable_sr_dm_accounting", m_enable_sr_dm_accounting));
            archive(::cereal::make_nvp("enable_transparent_ptp", m_enable_transparent_ptp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t& m) {
        uint64_t m_enable_sr_dm_accounting;
        uint64_t m_enable_transparent_ptp;
            archive(::cereal::make_nvp("enable_sr_dm_accounting", m_enable_sr_dm_accounting));
            archive(::cereal::make_nvp("enable_transparent_ptp", m_enable_transparent_ptp));
        m.enable_sr_dm_accounting = m_enable_sr_dm_accounting;
        m.enable_transparent_ptp = m_enable_transparent_ptp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t& m)
{
    serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t& m)
{
    serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_key_t&);



template<>
class serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t& m)
{
    serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t& m)
{
    serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t&);



template<>
class serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ingress_ptp_info_and_is_slp_dm_cmpressed_fields", m.ingress_ptp_info_and_is_slp_dm_cmpressed_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ingress_ptp_info_and_is_slp_dm_cmpressed_fields", m.ingress_ptp_info_and_is_slp_dm_cmpressed_fields));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t& m)
{
    serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t& m)
{
    serializer_class<npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_ingress_ptp_info_and_is_slp_dm_static_table_value_t::npl_get_ingress_ptp_info_and_is_slp_dm_static_table_payloads_t&);



template<>
class serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_l2_rtf_conf_set_and_init_stages_key_t& m) {
        uint64_t m_rtf_conf_set_ptr = m.rtf_conf_set_ptr;
            archive(::cereal::make_nvp("rtf_conf_set_ptr", m_rtf_conf_set_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_l2_rtf_conf_set_and_init_stages_key_t& m) {
        uint64_t m_rtf_conf_set_ptr;
            archive(::cereal::make_nvp("rtf_conf_set_ptr", m_rtf_conf_set_ptr));
        m.rtf_conf_set_ptr = m_rtf_conf_set_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_l2_rtf_conf_set_and_init_stages_key_t& m)
{
    serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_l2_rtf_conf_set_and_init_stages_key_t&);

template <class Archive>
void
load(Archive& archive, npl_get_l2_rtf_conf_set_and_init_stages_key_t& m)
{
    serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_l2_rtf_conf_set_and_init_stages_key_t&);



template<>
class serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_l2_rtf_conf_set_and_init_stages_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_l2_rtf_conf_set_and_init_stages_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_l2_rtf_conf_set_and_init_stages_value_t& m)
{
    serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_l2_rtf_conf_set_and_init_stages_value_t&);

template <class Archive>
void
load(Archive& archive, npl_get_l2_rtf_conf_set_and_init_stages_value_t& m)
{
    serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_l2_rtf_conf_set_and_init_stages_value_t&);



template<>
class serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t& m) {
            archive(::cereal::make_nvp("l2_rtf_conf_set_and_init_stages", m.l2_rtf_conf_set_and_init_stages));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t& m) {
            archive(::cereal::make_nvp("l2_rtf_conf_set_and_init_stages", m.l2_rtf_conf_set_and_init_stages));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t& m)
{
    serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t& m)
{
    serializer_class<npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_l2_rtf_conf_set_and_init_stages_value_t::npl_get_l2_rtf_conf_set_and_init_stages_payloads_t&);



template<>
class serializer_class<npl_get_non_comp_mc_value_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_non_comp_mc_value_static_table_key_t& m) {
        uint64_t m_packet_type_bit0 = m.packet_type_bit0;
        uint64_t m_not_comp_single_src = m.not_comp_single_src;
            archive(::cereal::make_nvp("packet_type_bit0", m_packet_type_bit0));
            archive(::cereal::make_nvp("not_comp_single_src", m_not_comp_single_src));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_non_comp_mc_value_static_table_key_t& m) {
        uint64_t m_packet_type_bit0;
        uint64_t m_not_comp_single_src;
            archive(::cereal::make_nvp("packet_type_bit0", m_packet_type_bit0));
            archive(::cereal::make_nvp("not_comp_single_src", m_not_comp_single_src));
        m.packet_type_bit0 = m_packet_type_bit0;
        m.not_comp_single_src = m_not_comp_single_src;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_non_comp_mc_value_static_table_key_t& m)
{
    serializer_class<npl_get_non_comp_mc_value_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_non_comp_mc_value_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_get_non_comp_mc_value_static_table_key_t& m)
{
    serializer_class<npl_get_non_comp_mc_value_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_non_comp_mc_value_static_table_key_t&);



template<>
class serializer_class<npl_get_non_comp_mc_value_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_non_comp_mc_value_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_non_comp_mc_value_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_non_comp_mc_value_static_table_value_t& m)
{
    serializer_class<npl_get_non_comp_mc_value_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_non_comp_mc_value_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_get_non_comp_mc_value_static_table_value_t& m)
{
    serializer_class<npl_get_non_comp_mc_value_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_non_comp_mc_value_static_table_value_t&);



template<>
class serializer_class<npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t& m) {
        uint64_t m_non_comp_mc_trap = m.non_comp_mc_trap;
            archive(::cereal::make_nvp("non_comp_mc_trap", m_non_comp_mc_trap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t& m) {
        uint64_t m_non_comp_mc_trap;
            archive(::cereal::make_nvp("non_comp_mc_trap", m_non_comp_mc_trap));
        m.non_comp_mc_trap = m_non_comp_mc_trap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t& m)
{
    serializer_class<npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t& m)
{
    serializer_class<npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_get_non_comp_mc_value_static_table_value_t::npl_get_non_comp_mc_value_static_table_payloads_t&);



template<>
class serializer_class<npl_gre_proto_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_gre_proto_static_table_key_t& m) {
        uint64_t m_proto = m.proto;
        uint64_t m_label_present = m.label_present;
            archive(::cereal::make_nvp("proto", m_proto));
            archive(::cereal::make_nvp("label_present", m_label_present));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_gre_proto_static_table_key_t& m) {
        uint64_t m_proto;
        uint64_t m_label_present;
            archive(::cereal::make_nvp("proto", m_proto));
            archive(::cereal::make_nvp("label_present", m_label_present));
        m.proto = m_proto;
        m.label_present = m_label_present;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_gre_proto_static_table_key_t& m)
{
    serializer_class<npl_gre_proto_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_gre_proto_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_gre_proto_static_table_key_t& m)
{
    serializer_class<npl_gre_proto_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_gre_proto_static_table_key_t&);



template<>
class serializer_class<npl_gre_proto_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_gre_proto_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_gre_proto_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_gre_proto_static_table_value_t& m)
{
    serializer_class<npl_gre_proto_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_gre_proto_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_gre_proto_static_table_value_t& m)
{
    serializer_class<npl_gre_proto_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_gre_proto_static_table_value_t&);



template<>
class serializer_class<npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t& m) {
        uint64_t m_gre_proto = m.gre_proto;
            archive(::cereal::make_nvp("gre_proto", m_gre_proto));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t& m) {
        uint64_t m_gre_proto;
            archive(::cereal::make_nvp("gre_proto", m_gre_proto));
        m.gre_proto = m_gre_proto;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t& m)
{
    serializer_class<npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t& m)
{
    serializer_class<npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_gre_proto_static_table_value_t::npl_gre_proto_static_table_payloads_t&);



template<>
class serializer_class<npl_hmc_cgm_cgm_lut_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_cgm_lut_table_key_t& m) {
        uint64_t m_queue_size_level = m.queue_size_level;
        uint64_t m_shared_pool_th_level = m.shared_pool_th_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("queue_size_level", m_queue_size_level));
            archive(::cereal::make_nvp("shared_pool_th_level", m_shared_pool_th_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_cgm_lut_table_key_t& m) {
        uint64_t m_queue_size_level;
        uint64_t m_shared_pool_th_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("queue_size_level", m_queue_size_level));
            archive(::cereal::make_nvp("shared_pool_th_level", m_shared_pool_th_level));
        m.queue_size_level = m_queue_size_level;
        m.shared_pool_th_level = m_shared_pool_th_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_cgm_lut_table_key_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_cgm_lut_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_cgm_lut_table_key_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_cgm_lut_table_key_t&);



template<>
class serializer_class<npl_hmc_cgm_cgm_lut_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_cgm_lut_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_cgm_lut_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_cgm_lut_table_value_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_cgm_lut_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_cgm_lut_table_value_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_cgm_lut_table_value_t&);



template<>
class serializer_class<npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t& m) {
            archive(::cereal::make_nvp("hmc_cgm_cgm_lut_results", m.hmc_cgm_cgm_lut_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t& m) {
            archive(::cereal::make_nvp("hmc_cgm_cgm_lut_results", m.hmc_cgm_cgm_lut_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t& m)
{
    serializer_class<npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_cgm_lut_table_value_t::npl_hmc_cgm_cgm_lut_table_payloads_t&);



template<>
class serializer_class<npl_hmc_cgm_profile_global_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_profile_global_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_profile_global_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_profile_global_table_key_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_profile_global_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_profile_global_table_key_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_profile_global_table_key_t&);



template<>
class serializer_class<npl_hmc_cgm_profile_global_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_profile_global_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_profile_global_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_profile_global_table_value_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_profile_global_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_profile_global_table_value_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_profile_global_table_value_t&);



template<>
class serializer_class<npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t& m) {
            archive(::cereal::make_nvp("hmc_cgm_profile_global_results", m.hmc_cgm_profile_global_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t& m) {
            archive(::cereal::make_nvp("hmc_cgm_profile_global_results", m.hmc_cgm_profile_global_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t& m)
{
    serializer_class<npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_hmc_cgm_profile_global_table_value_t::npl_hmc_cgm_profile_global_table_payloads_t&);



template<>
class serializer_class<npl_ibm_cmd_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_cmd_table_key_t& m) {
        uint64_t m_rxpp_to_txpp_local_vars_mirror_command = m.rxpp_to_txpp_local_vars_mirror_command;
            archive(::cereal::make_nvp("rxpp_to_txpp_local_vars_mirror_command", m_rxpp_to_txpp_local_vars_mirror_command));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_cmd_table_key_t& m) {
        uint64_t m_rxpp_to_txpp_local_vars_mirror_command;
            archive(::cereal::make_nvp("rxpp_to_txpp_local_vars_mirror_command", m_rxpp_to_txpp_local_vars_mirror_command));
        m.rxpp_to_txpp_local_vars_mirror_command = m_rxpp_to_txpp_local_vars_mirror_command;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_cmd_table_key_t& m)
{
    serializer_class<npl_ibm_cmd_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_cmd_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_cmd_table_key_t& m)
{
    serializer_class<npl_ibm_cmd_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_cmd_table_key_t&);



template<>
class serializer_class<npl_ibm_cmd_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_cmd_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_cmd_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_cmd_table_value_t& m)
{
    serializer_class<npl_ibm_cmd_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_cmd_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_cmd_table_value_t& m)
{
    serializer_class<npl_ibm_cmd_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_cmd_table_value_t&);



}

