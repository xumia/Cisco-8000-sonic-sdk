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

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_db_access_lu_data_t&);
template <class Archive> void load(Archive&, npl_db_access_lu_data_t&);

template <class Archive> void save(Archive&, const npl_fi_tcam_hardwired_result_t&);
template <class Archive> void load(Archive&, npl_fi_tcam_hardwired_result_t&);

template <class Archive> void save(Archive&, const npl_flc_header_types_array_data_t&);
template <class Archive> void load(Archive&, npl_flc_header_types_array_data_t&);

template <class Archive> void save(Archive&, const npl_flc_map_header_type_mask_id_data_t&);
template <class Archive> void load(Archive&, npl_flc_map_header_type_mask_id_data_t&);

template <class Archive> void save(Archive&, const npl_flc_map_header_type_mask_id_t&);
template <class Archive> void load(Archive&, npl_flc_map_header_type_mask_id_t&);

template <class Archive> void save(Archive&, const npl_flc_map_header_type_mask_l_data_t&);
template <class Archive> void load(Archive&, npl_flc_map_header_type_mask_l_data_t&);

template <class Archive> void save(Archive&, const npl_flc_map_header_type_mask_lm_key_t&);
template <class Archive> void load(Archive&, npl_flc_map_header_type_mask_lm_key_t&);

template <class Archive> void save(Archive&, const npl_flc_map_header_type_mask_m_data_t&);
template <class Archive> void load(Archive&, npl_flc_map_header_type_mask_m_data_t&);

template <class Archive> void save(Archive&, const npl_flc_map_header_type_mask_s_data_t&);
template <class Archive> void load(Archive&, npl_flc_map_header_type_mask_s_data_t&);

template <class Archive> void save(Archive&, const npl_flc_map_header_type_mask_s_key_t&);
template <class Archive> void load(Archive&, npl_flc_map_header_type_mask_s_key_t&);

template <class Archive> void save(Archive&, const npl_flc_range_comp_profile_data_t&);
template <class Archive> void load(Archive&, npl_flc_range_comp_profile_data_t&);

template <class Archive> void save(Archive&, const npl_flc_range_comp_profile_sel_t&);
template <class Archive> void load(Archive&, npl_flc_range_comp_profile_sel_t&);

template <class Archive> void save(Archive&, const npl_flc_range_comp_ranges_data_t&);
template <class Archive> void load(Archive&, npl_flc_range_comp_ranges_data_t&);

template <class Archive> void save(Archive&, const npl_flc_range_comp_ranges_key_t&);
template <class Archive> void load(Archive&, npl_flc_range_comp_ranges_key_t&);

template <class Archive> void save(Archive&, const npl_frm_db_fabric_routing_table_result_t&);
template <class Archive> void load(Archive&, npl_frm_db_fabric_routing_table_result_t&);

template <class Archive> void save(Archive&, const npl_hmc_cgm_profile_global_results_t&);
template <class Archive> void load(Archive&, npl_hmc_cgm_profile_global_results_t&);

template <class Archive> void save(Archive&, const npl_ibm_cmd_table_result_t&);
template <class Archive> void load(Archive&, npl_ibm_cmd_table_result_t&);

template <class Archive> void save(Archive&, const npl_ifgb_tc_lut_results_t&);
template <class Archive> void load(Archive&, npl_ifgb_tc_lut_results_t&);

template <class Archive> void save(Archive&, const npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t&);
template <class Archive> void load(Archive&, npl_ingress_ptp_info_and_is_slp_dm_cmpressed_fields_t&);

template <class Archive> void save(Archive&, const npl_ingress_punt_mc_expand_encap_t&);
template <class Archive> void load(Archive&, npl_ingress_punt_mc_expand_encap_t&);

template <class Archive> void save(Archive&, const npl_ingress_qos_result_t&);
template <class Archive> void load(Archive&, npl_ingress_qos_result_t&);

template <class Archive> void save(Archive&, const npl_initial_pd_nw_rx_data_t&);
template <class Archive> void load(Archive&, npl_initial_pd_nw_rx_data_t&);

template <class Archive> void save(Archive&, const npl_ive_enable_t&);
template <class Archive> void load(Archive&, npl_ive_enable_t&);

template <class Archive> void save(Archive&, const npl_l2_rtf_conf_set_and_init_stages_t&);
template <class Archive> void load(Archive&, npl_l2_rtf_conf_set_and_init_stages_t&);

template <class Archive> void save(Archive&, const npl_punt_app_encap_t&);
template <class Archive> void load(Archive&, npl_punt_app_encap_t&);

template <class Archive> void save(Archive&, const npl_rtf_payload_t&);
template <class Archive> void load(Archive&, npl_rtf_payload_t&);

template <class Archive> void save(Archive&, const npl_slice_and_source_if_t&);
template <class Archive> void load(Archive&, npl_slice_and_source_if_t&);

template <class Archive> void save(Archive&, const npl_source_if_t&);
template <class Archive> void load(Archive&, npl_source_if_t&);

template <class Archive> void save(Archive&, const npl_ud_key_t&);
template <class Archive> void load(Archive&, npl_ud_key_t&);

template <class Archive> void save(Archive&, const npl_voq_profile_len&);
template <class Archive> void load(Archive&, npl_voq_profile_len&);

template<>
class serializer_class<npl_flc_header_types_array_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_header_types_array_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_header_types_array_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_header_types_array_table_value_t& m)
{
    serializer_class<npl_flc_header_types_array_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_header_types_array_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_header_types_array_table_value_t& m)
{
    serializer_class<npl_flc_header_types_array_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_header_types_array_table_value_t&);



template<>
class serializer_class<npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_header_types_array_data", m.flc_header_types_array_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_header_types_array_data", m.flc_header_types_array_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t& m)
{
    serializer_class<npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t& m)
{
    serializer_class<npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_header_types_array_table_value_t::npl_flc_header_types_array_table_payloads_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_id_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_id_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_id_key", m.flc_map_header_type_mask_id_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_id_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_id_key", m.flc_map_header_type_mask_id_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_id_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_id_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_id_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_id_table_key_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_id_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_id_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_id_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_id_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_id_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_id_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_id_table_value_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_id_data", m.flc_map_header_type_mask_id_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_id_data", m.flc_map_header_type_mask_id_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_id_table_value_t::npl_flc_map_header_type_mask_id_table_payloads_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_l_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_l_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_l_key", m.flc_map_header_type_mask_l_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_l_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_l_key", m.flc_map_header_type_mask_l_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_l_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_l_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_l_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_l_table_key_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_l_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_l_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_l_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_l_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_l_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_l_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_l_table_value_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_l_data", m.flc_map_header_type_mask_l_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_l_data", m.flc_map_header_type_mask_l_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_l_table_value_t::npl_flc_map_header_type_mask_l_table_payloads_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_m_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_m_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_m_key", m.flc_map_header_type_mask_m_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_m_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_m_key", m.flc_map_header_type_mask_m_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_m_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_m_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_m_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_m_table_key_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_m_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_m_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_m_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_m_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_m_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_m_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_m_table_value_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_m_data", m.flc_map_header_type_mask_m_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_m_data", m.flc_map_header_type_mask_m_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_m_table_value_t::npl_flc_map_header_type_mask_m_table_payloads_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_s_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_s_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_s_key", m.flc_map_header_type_mask_s_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_s_table_key_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_s_key", m.flc_map_header_type_mask_s_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_s_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_s_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_s_table_key_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_s_table_key_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_s_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_s_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_s_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_s_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_s_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_s_table_value_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_s_table_value_t&);



template<>
class serializer_class<npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_s_data", m.flc_map_header_type_mask_s_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_map_header_type_mask_s_data", m.flc_map_header_type_mask_s_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t& m)
{
    serializer_class<npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_map_header_type_mask_s_table_value_t::npl_flc_map_header_type_mask_s_table_payloads_t&);



template<>
class serializer_class<npl_flc_q_range_comp_profile_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_q_range_comp_profile_table_key_t& m) {
            archive(::cereal::make_nvp("flc_q_range_comp_profile_key", m.flc_q_range_comp_profile_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_q_range_comp_profile_table_key_t& m) {
            archive(::cereal::make_nvp("flc_q_range_comp_profile_key", m.flc_q_range_comp_profile_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_q_range_comp_profile_table_key_t& m)
{
    serializer_class<npl_flc_q_range_comp_profile_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_q_range_comp_profile_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_q_range_comp_profile_table_key_t& m)
{
    serializer_class<npl_flc_q_range_comp_profile_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_q_range_comp_profile_table_key_t&);



template<>
class serializer_class<npl_flc_q_range_comp_profile_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_q_range_comp_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_q_range_comp_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_q_range_comp_profile_table_value_t& m)
{
    serializer_class<npl_flc_q_range_comp_profile_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_q_range_comp_profile_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_q_range_comp_profile_table_value_t& m)
{
    serializer_class<npl_flc_q_range_comp_profile_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_q_range_comp_profile_table_value_t&);



template<>
class serializer_class<npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_q_range_comp_profile_data", m.flc_q_range_comp_profile_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_q_range_comp_profile_data", m.flc_q_range_comp_profile_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t& m)
{
    serializer_class<npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t& m)
{
    serializer_class<npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_q_range_comp_profile_table_value_t::npl_flc_q_range_comp_profile_table_payloads_t&);



template<>
class serializer_class<npl_flc_range_comp_ranges_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_range_comp_ranges_table_key_t& m) {
            archive(::cereal::make_nvp("flc_range_comp_ranges_key", m.flc_range_comp_ranges_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_range_comp_ranges_table_key_t& m) {
            archive(::cereal::make_nvp("flc_range_comp_ranges_key", m.flc_range_comp_ranges_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_range_comp_ranges_table_key_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_range_comp_ranges_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_range_comp_ranges_table_key_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_range_comp_ranges_table_key_t&);



template<>
class serializer_class<npl_flc_range_comp_ranges_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_range_comp_ranges_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_range_comp_ranges_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_range_comp_ranges_table_value_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_range_comp_ranges_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_range_comp_ranges_table_value_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_range_comp_ranges_table_value_t&);



template<>
class serializer_class<npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_range_comp_ranges_data", m.flc_range_comp_ranges_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t& m) {
            archive(::cereal::make_nvp("flc_range_comp_ranges_data", m.flc_range_comp_ranges_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t& m)
{
    serializer_class<npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_flc_range_comp_ranges_table_value_t::npl_flc_range_comp_ranges_table_payloads_t&);



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
class serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_and_encap_types_to_field_a_offset_table_key_t& m) {
        uint64_t m_txpp_first_macro_table_key_fwd_type = m.txpp_first_macro_table_key_fwd_type;
        uint64_t m_txpp_first_macro_table_key_encap_type = m.txpp_first_macro_table_key_encap_type;
            archive(::cereal::make_nvp("txpp_first_macro_table_key_fwd_type", m_txpp_first_macro_table_key_fwd_type));
            archive(::cereal::make_nvp("txpp_first_macro_table_key_encap_type", m_txpp_first_macro_table_key_encap_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_and_encap_types_to_field_a_offset_table_key_t& m) {
        uint64_t m_txpp_first_macro_table_key_fwd_type;
        uint64_t m_txpp_first_macro_table_key_encap_type;
            archive(::cereal::make_nvp("txpp_first_macro_table_key_fwd_type", m_txpp_first_macro_table_key_fwd_type));
            archive(::cereal::make_nvp("txpp_first_macro_table_key_encap_type", m_txpp_first_macro_table_key_encap_type));
        m.txpp_first_macro_table_key_fwd_type = m_txpp_first_macro_table_key_fwd_type;
        m.txpp_first_macro_table_key_encap_type = m_txpp_first_macro_table_key_encap_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_and_encap_types_to_field_a_offset_table_key_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_and_encap_types_to_field_a_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_and_encap_types_to_field_a_offset_table_key_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_and_encap_types_to_field_a_offset_table_key_t&);



template<>
class serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_and_encap_types_to_field_a_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_and_encap_types_to_field_a_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_and_encap_types_to_field_a_offset_table_value_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_and_encap_types_to_field_a_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_and_encap_types_to_field_a_offset_table_value_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_and_encap_types_to_field_a_offset_table_value_t&);



template<>
class serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t& m) {
        uint64_t m_txpp_first_macro_local_vars_field_a_offset_in_nibble = m.txpp_first_macro_local_vars_field_a_offset_in_nibble;
            archive(::cereal::make_nvp("txpp_first_macro_local_vars_field_a_offset_in_nibble", m_txpp_first_macro_local_vars_field_a_offset_in_nibble));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t& m) {
        uint64_t m_txpp_first_macro_local_vars_field_a_offset_in_nibble;
            archive(::cereal::make_nvp("txpp_first_macro_local_vars_field_a_offset_in_nibble", m_txpp_first_macro_local_vars_field_a_offset_in_nibble));
        m.txpp_first_macro_local_vars_field_a_offset_in_nibble = m_txpp_first_macro_local_vars_field_a_offset_in_nibble;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_and_encap_types_to_field_a_offset_table_value_t::npl_fwd_and_encap_types_to_field_a_offset_table_payloads_t&);



template<>
class serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_and_encap_types_to_field_b_offset_table_key_t& m) {
        uint64_t m_txpp_first_macro_table_key_fwd_type = m.txpp_first_macro_table_key_fwd_type;
        uint64_t m_txpp_first_macro_table_key_encap_type = m.txpp_first_macro_table_key_encap_type;
            archive(::cereal::make_nvp("txpp_first_macro_table_key_fwd_type", m_txpp_first_macro_table_key_fwd_type));
            archive(::cereal::make_nvp("txpp_first_macro_table_key_encap_type", m_txpp_first_macro_table_key_encap_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_and_encap_types_to_field_b_offset_table_key_t& m) {
        uint64_t m_txpp_first_macro_table_key_fwd_type;
        uint64_t m_txpp_first_macro_table_key_encap_type;
            archive(::cereal::make_nvp("txpp_first_macro_table_key_fwd_type", m_txpp_first_macro_table_key_fwd_type));
            archive(::cereal::make_nvp("txpp_first_macro_table_key_encap_type", m_txpp_first_macro_table_key_encap_type));
        m.txpp_first_macro_table_key_fwd_type = m_txpp_first_macro_table_key_fwd_type;
        m.txpp_first_macro_table_key_encap_type = m_txpp_first_macro_table_key_encap_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_and_encap_types_to_field_b_offset_table_key_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_and_encap_types_to_field_b_offset_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_and_encap_types_to_field_b_offset_table_key_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_and_encap_types_to_field_b_offset_table_key_t&);



template<>
class serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_and_encap_types_to_field_b_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_and_encap_types_to_field_b_offset_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_and_encap_types_to_field_b_offset_table_value_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_and_encap_types_to_field_b_offset_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_and_encap_types_to_field_b_offset_table_value_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_and_encap_types_to_field_b_offset_table_value_t&);



template<>
class serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t& m) {
        uint64_t m_txpp_first_macro_local_vars_field_b_offset_in_nibble = m.txpp_first_macro_local_vars_field_b_offset_in_nibble;
            archive(::cereal::make_nvp("txpp_first_macro_local_vars_field_b_offset_in_nibble", m_txpp_first_macro_local_vars_field_b_offset_in_nibble));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t& m) {
        uint64_t m_txpp_first_macro_local_vars_field_b_offset_in_nibble;
            archive(::cereal::make_nvp("txpp_first_macro_local_vars_field_b_offset_in_nibble", m_txpp_first_macro_local_vars_field_b_offset_in_nibble));
        m.txpp_first_macro_local_vars_field_b_offset_in_nibble = m_txpp_first_macro_local_vars_field_b_offset_in_nibble;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t& m)
{
    serializer_class<npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_and_encap_types_to_field_b_offset_table_value_t::npl_fwd_and_encap_types_to_field_b_offset_table_payloads_t&);



template<>
class serializer_class<npl_fwd_bucket_a_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_a_lu_data_selector_key_t& m) {
        uint64_t m_lu_a_key_index = m.lu_a_key_index;
            archive(::cereal::make_nvp("lu_a_dest", m.lu_a_dest));
            archive(::cereal::make_nvp("lu_a_key_index", m_lu_a_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_a_lu_data_selector_key_t& m) {
        uint64_t m_lu_a_key_index;
            archive(::cereal::make_nvp("lu_a_dest", m.lu_a_dest));
            archive(::cereal::make_nvp("lu_a_key_index", m_lu_a_key_index));
        m.lu_a_key_index = m_lu_a_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_a_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_a_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_a_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_a_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_a_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_a_lu_data_selector_key_t&);



template<>
class serializer_class<npl_fwd_bucket_a_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_a_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_a_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_a_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_a_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_a_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_a_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_a_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_a_lu_data_selector_value_t&);



template<>
class serializer_class<npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_a_lu_data", m.fwd_bucket_a_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_a_lu_data", m.fwd_bucket_a_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_a_lu_data_selector_value_t::npl_fwd_bucket_a_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_fwd_bucket_b_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_b_lu_data_selector_key_t& m) {
        uint64_t m_lu_b_key_index = m.lu_b_key_index;
            archive(::cereal::make_nvp("lu_b_dest", m.lu_b_dest));
            archive(::cereal::make_nvp("lu_b_key_index", m_lu_b_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_b_lu_data_selector_key_t& m) {
        uint64_t m_lu_b_key_index;
            archive(::cereal::make_nvp("lu_b_dest", m.lu_b_dest));
            archive(::cereal::make_nvp("lu_b_key_index", m_lu_b_key_index));
        m.lu_b_key_index = m_lu_b_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_b_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_b_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_b_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_b_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_b_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_b_lu_data_selector_key_t&);



template<>
class serializer_class<npl_fwd_bucket_b_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_b_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_b_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_b_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_b_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_b_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_b_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_b_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_b_lu_data_selector_value_t&);



template<>
class serializer_class<npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_b_lu_data", m.fwd_bucket_b_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_b_lu_data", m.fwd_bucket_b_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_b_lu_data_selector_value_t::npl_fwd_bucket_b_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_fwd_bucket_c_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_c_lu_data_selector_key_t& m) {
        uint64_t m_lu_c_key_index = m.lu_c_key_index;
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_c_key_index", m_lu_c_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_c_lu_data_selector_key_t& m) {
        uint64_t m_lu_c_key_index;
            archive(::cereal::make_nvp("lu_c_dest", m.lu_c_dest));
            archive(::cereal::make_nvp("lu_c_key_index", m_lu_c_key_index));
        m.lu_c_key_index = m_lu_c_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_c_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_c_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_c_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_c_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_c_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_c_lu_data_selector_key_t&);



template<>
class serializer_class<npl_fwd_bucket_c_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_c_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_c_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_c_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_c_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_c_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_c_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_c_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_c_lu_data_selector_value_t&);



template<>
class serializer_class<npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_c_lu_data", m.fwd_bucket_c_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_c_lu_data", m.fwd_bucket_c_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_c_lu_data_selector_value_t::npl_fwd_bucket_c_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_fwd_bucket_d_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_d_lu_data_selector_key_t& m) {
        uint64_t m_lu_d_key_index = m.lu_d_key_index;
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
            archive(::cereal::make_nvp("lu_d_key_index", m_lu_d_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_d_lu_data_selector_key_t& m) {
        uint64_t m_lu_d_key_index;
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
            archive(::cereal::make_nvp("lu_d_key_index", m_lu_d_key_index));
        m.lu_d_key_index = m_lu_d_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_d_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_d_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_d_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_d_lu_data_selector_key_t& m)
{
    serializer_class<npl_fwd_bucket_d_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_d_lu_data_selector_key_t&);



template<>
class serializer_class<npl_fwd_bucket_d_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_d_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_d_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_d_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_d_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_d_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_d_lu_data_selector_value_t& m)
{
    serializer_class<npl_fwd_bucket_d_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_d_lu_data_selector_value_t&);



template<>
class serializer_class<npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_d_lu_data", m.fwd_bucket_d_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("fwd_bucket_d_lu_data", m.fwd_bucket_d_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_fwd_bucket_d_lu_data_selector_value_t::npl_fwd_bucket_d_lu_data_selector_payloads_t&);



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



template<>
class serializer_class<npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_cmd_table_result", m.ibm_cmd_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_cmd_table_result", m.ibm_cmd_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t& m)
{
    serializer_class<npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t& m)
{
    serializer_class<npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_cmd_table_value_t::npl_ibm_cmd_table_payloads_t&);



template<>
class serializer_class<npl_ibm_mc_cmd_to_encap_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_mc_cmd_to_encap_data_table_key_t& m) {
        uint64_t m_tx_fabric_tx_cud_20_16_ = m.tx_fabric_tx_cud_20_16_;
            archive(::cereal::make_nvp("tx_fabric_tx_cud_20_16_", m_tx_fabric_tx_cud_20_16_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_mc_cmd_to_encap_data_table_key_t& m) {
        uint64_t m_tx_fabric_tx_cud_20_16_;
            archive(::cereal::make_nvp("tx_fabric_tx_cud_20_16_", m_tx_fabric_tx_cud_20_16_));
        m.tx_fabric_tx_cud_20_16_ = m_tx_fabric_tx_cud_20_16_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_mc_cmd_to_encap_data_table_key_t& m)
{
    serializer_class<npl_ibm_mc_cmd_to_encap_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_mc_cmd_to_encap_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_mc_cmd_to_encap_data_table_key_t& m)
{
    serializer_class<npl_ibm_mc_cmd_to_encap_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_mc_cmd_to_encap_data_table_key_t&);



template<>
class serializer_class<npl_ibm_mc_cmd_to_encap_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_mc_cmd_to_encap_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_mc_cmd_to_encap_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_mc_cmd_to_encap_data_table_value_t& m)
{
    serializer_class<npl_ibm_mc_cmd_to_encap_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_mc_cmd_to_encap_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_mc_cmd_to_encap_data_table_value_t& m)
{
    serializer_class<npl_ibm_mc_cmd_to_encap_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_mc_cmd_to_encap_data_table_value_t&);



template<>
class serializer_class<npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_mc_fabric_encap_msb", m.ibm_mc_fabric_encap_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_mc_fabric_encap_msb", m.ibm_mc_fabric_encap_msb));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t& m)
{
    serializer_class<npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t& m)
{
    serializer_class<npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_mc_cmd_to_encap_data_table_value_t::npl_ibm_mc_cmd_to_encap_data_table_payloads_t&);



template<>
class serializer_class<npl_ibm_uc_cmd_to_encap_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_uc_cmd_to_encap_data_table_key_t& m) {
        uint64_t m_tx_fabric_tx_cud_4_0_ = m.tx_fabric_tx_cud_4_0_;
            archive(::cereal::make_nvp("tx_fabric_tx_cud_4_0_", m_tx_fabric_tx_cud_4_0_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_uc_cmd_to_encap_data_table_key_t& m) {
        uint64_t m_tx_fabric_tx_cud_4_0_;
            archive(::cereal::make_nvp("tx_fabric_tx_cud_4_0_", m_tx_fabric_tx_cud_4_0_));
        m.tx_fabric_tx_cud_4_0_ = m_tx_fabric_tx_cud_4_0_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_uc_cmd_to_encap_data_table_key_t& m)
{
    serializer_class<npl_ibm_uc_cmd_to_encap_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_uc_cmd_to_encap_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_uc_cmd_to_encap_data_table_key_t& m)
{
    serializer_class<npl_ibm_uc_cmd_to_encap_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_uc_cmd_to_encap_data_table_key_t&);



template<>
class serializer_class<npl_ibm_uc_cmd_to_encap_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_uc_cmd_to_encap_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_uc_cmd_to_encap_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_uc_cmd_to_encap_data_table_value_t& m)
{
    serializer_class<npl_ibm_uc_cmd_to_encap_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_uc_cmd_to_encap_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_uc_cmd_to_encap_data_table_value_t& m)
{
    serializer_class<npl_ibm_uc_cmd_to_encap_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_uc_cmd_to_encap_data_table_value_t&);



template<>
class serializer_class<npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_uc_fabric_encap", m.ibm_uc_fabric_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_uc_fabric_encap", m.ibm_uc_fabric_encap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t& m)
{
    serializer_class<npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t& m)
{
    serializer_class<npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ibm_uc_cmd_to_encap_data_table_value_t::npl_ibm_uc_cmd_to_encap_data_table_payloads_t&);



template<>
class serializer_class<npl_ifgb_tc_lut_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ifgb_tc_lut_table_key_t& m) {
        uint64_t m_ifg = m.ifg;
        uint64_t m_serdes_pair = m.serdes_pair;
        uint64_t m_port = m.port;
        uint64_t m_protocol = m.protocol;
        uint64_t m_tpid = m.tpid;
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("serdes_pair", m_serdes_pair));
            archive(::cereal::make_nvp("port", m_port));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("tpid", m_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ifgb_tc_lut_table_key_t& m) {
        uint64_t m_ifg;
        uint64_t m_serdes_pair;
        uint64_t m_port;
        uint64_t m_protocol;
        uint64_t m_tpid;
            archive(::cereal::make_nvp("ifg", m_ifg));
            archive(::cereal::make_nvp("serdes_pair", m_serdes_pair));
            archive(::cereal::make_nvp("port", m_port));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("tpid", m_tpid));
        m.ifg = m_ifg;
        m.serdes_pair = m_serdes_pair;
        m.port = m_port;
        m.protocol = m_protocol;
        m.tpid = m_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ifgb_tc_lut_table_key_t& m)
{
    serializer_class<npl_ifgb_tc_lut_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ifgb_tc_lut_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ifgb_tc_lut_table_key_t& m)
{
    serializer_class<npl_ifgb_tc_lut_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ifgb_tc_lut_table_key_t&);



template<>
class serializer_class<npl_ifgb_tc_lut_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ifgb_tc_lut_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ifgb_tc_lut_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ifgb_tc_lut_table_value_t& m)
{
    serializer_class<npl_ifgb_tc_lut_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ifgb_tc_lut_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ifgb_tc_lut_table_value_t& m)
{
    serializer_class<npl_ifgb_tc_lut_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ifgb_tc_lut_table_value_t&);



template<>
class serializer_class<npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t& m) {
            archive(::cereal::make_nvp("ifgb_tc_lut_results", m.ifgb_tc_lut_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t& m) {
            archive(::cereal::make_nvp("ifgb_tc_lut_results", m.ifgb_tc_lut_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t& m)
{
    serializer_class<npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t& m)
{
    serializer_class<npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ifgb_tc_lut_table_value_t::npl_ifgb_tc_lut_table_payloads_t&);



template<>
class serializer_class<npl_ingress_ip_qos_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_ip_qos_mapping_table_key_t& m) {
        uint64_t m_l3_qos_mapping_key = m.l3_qos_mapping_key;
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("l3_qos_mapping_key", m_l3_qos_mapping_key));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_ip_qos_mapping_table_key_t& m) {
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
save(Archive& archive, const npl_ingress_ip_qos_mapping_table_key_t& m)
{
    serializer_class<npl_ingress_ip_qos_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_ip_qos_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_ip_qos_mapping_table_key_t& m)
{
    serializer_class<npl_ingress_ip_qos_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_ip_qos_mapping_table_key_t&);



template<>
class serializer_class<npl_ingress_ip_qos_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_ip_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_ip_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_ip_qos_mapping_table_value_t& m)
{
    serializer_class<npl_ingress_ip_qos_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_ip_qos_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_ip_qos_mapping_table_value_t& m)
{
    serializer_class<npl_ingress_ip_qos_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_ip_qos_mapping_table_value_t&);



template<>
class serializer_class<npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_qos_mapping_result", m.ip_qos_mapping_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_qos_mapping_result", m.ip_qos_mapping_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_ip_qos_mapping_table_value_t::npl_ingress_ip_qos_mapping_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_eth_db1_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_eth_db1_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_eth_db1_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_eth_db1_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_eth_db1_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_eth_db1_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_eth_db1_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_eth_db1_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_eth_db1_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_eth_db1_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_eth_db1_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_eth_db1_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_eth_db1_160_f0_table_value_t::npl_ingress_rtf_eth_db1_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_eth_db2_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_eth_db2_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_eth_db2_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_eth_db2_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_eth_db2_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_eth_db2_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_eth_db2_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_eth_db2_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_eth_db2_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_eth_db2_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_eth_db2_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_eth_db2_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_eth_db2_160_f0_table_value_t::npl_ingress_rtf_eth_db2_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_160_f0_table_value_t::npl_ingress_rtf_ipv4_db1_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_160_f1_table_value_t::npl_ingress_rtf_ipv4_db1_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db1_320_f0_table_value_t::npl_ingress_rtf_ipv4_db1_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_160_f0_table_value_t::npl_ingress_rtf_ipv4_db2_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_160_f1_table_value_t::npl_ingress_rtf_ipv4_db2_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db2_320_f0_table_value_t::npl_ingress_rtf_ipv4_db2_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_160_f0_table_value_t::npl_ingress_rtf_ipv4_db3_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_160_f1_table_value_t::npl_ingress_rtf_ipv4_db3_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db3_320_f0_table_value_t::npl_ingress_rtf_ipv4_db3_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_160_f0_table_value_t::npl_ingress_rtf_ipv4_db4_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_160_f1_table_value_t::npl_ingress_rtf_ipv4_db4_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv4_db4_320_f0_table_value_t::npl_ingress_rtf_ipv4_db4_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_160_f0_table_value_t::npl_ingress_rtf_ipv6_db1_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_160_f1_table_value_t::npl_ingress_rtf_ipv6_db1_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db1_320_f0_table_value_t::npl_ingress_rtf_ipv6_db1_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_160_f0_table_value_t::npl_ingress_rtf_ipv6_db2_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_160_f1_table_value_t::npl_ingress_rtf_ipv6_db2_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db2_320_f0_table_value_t::npl_ingress_rtf_ipv6_db2_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_160_f0_table_value_t::npl_ingress_rtf_ipv6_db3_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_160_f1_table_value_t::npl_ingress_rtf_ipv6_db3_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db3_320_f0_table_value_t::npl_ingress_rtf_ipv6_db3_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_160_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_160_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_160_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_160_f0_table_value_t::npl_ingress_rtf_ipv6_db4_160_f0_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_160_f1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f1_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_160_f1_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_160_f1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload_f1", m.rtf_payload_f1));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_160_f1_table_value_t::npl_ingress_rtf_ipv6_db4_160_f1_table_payloads_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& m) {
            archive(::cereal::make_nvp("ud_key", m.ud_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_320_f0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_320_f0_table_key_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_320_f0_table_key_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_320_f0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t&);



template<>
class serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t& m) {
            archive(::cereal::make_nvp("rtf_payload", m.rtf_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t& m)
{
    serializer_class<npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ingress_rtf_ipv6_db4_320_f0_table_value_t::npl_ingress_rtf_ipv6_db4_320_f0_table_payloads_t&);



template<>
class serializer_class<npl_inject_down_select_ene_static_table_inject_down_ene_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_select_ene_static_table_inject_down_ene_payload_t& m) {
        uint64_t m_dma_decap_header_type = m.dma_decap_header_type;
            archive(::cereal::make_nvp("ene_macro_id", m.ene_macro_id));
            archive(::cereal::make_nvp("dma_decap_header_type", m_dma_decap_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_select_ene_static_table_inject_down_ene_payload_t& m) {
        uint64_t m_dma_decap_header_type;
            archive(::cereal::make_nvp("ene_macro_id", m.ene_macro_id));
            archive(::cereal::make_nvp("dma_decap_header_type", m_dma_decap_header_type));
        m.dma_decap_header_type = m_dma_decap_header_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_select_ene_static_table_inject_down_ene_payload_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_inject_down_ene_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_select_ene_static_table_inject_down_ene_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_select_ene_static_table_inject_down_ene_payload_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_inject_down_ene_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_select_ene_static_table_inject_down_ene_payload_t&);



template<>
class serializer_class<npl_inject_down_select_ene_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_select_ene_static_table_key_t& m) {
        uint64_t m_dsp_is_dma = m.dsp_is_dma;
            archive(::cereal::make_nvp("dsp_is_dma", m_dsp_is_dma));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("inject_down_encap", m.inject_down_encap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_select_ene_static_table_key_t& m) {
        uint64_t m_dsp_is_dma;
            archive(::cereal::make_nvp("dsp_is_dma", m_dsp_is_dma));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("inject_down_encap", m.inject_down_encap));
        m.dsp_is_dma = m_dsp_is_dma;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_select_ene_static_table_key_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_select_ene_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_select_ene_static_table_key_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_select_ene_static_table_key_t&);



template<>
class serializer_class<npl_inject_down_select_ene_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_select_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_select_ene_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_select_ene_static_table_value_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_select_ene_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_select_ene_static_table_value_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_select_ene_static_table_value_t&);



template<>
class serializer_class<npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("inject_down_ene", m.inject_down_ene));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("inject_down_ene", m.inject_down_ene));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t& m)
{
    serializer_class<npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_select_ene_static_table_value_t::npl_inject_down_select_ene_static_table_payloads_t&);



template<>
class serializer_class<npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t& m) {
            archive(::cereal::make_nvp("per_pif_trap_mode", m.per_pif_trap_mode));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t& m) {
            archive(::cereal::make_nvp("per_pif_trap_mode", m.per_pif_trap_mode));
            archive(::cereal::make_nvp("counter_ptr", m.counter_ptr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_tx_redirect_counter_table_counter_meter_found_payload_t&);



template<>
class serializer_class<npl_inject_down_tx_redirect_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_key_t& m) {
        uint64_t m_tx_redirect_code = m.tx_redirect_code;
            archive(::cereal::make_nvp("tx_redirect_code", m_tx_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_tx_redirect_counter_table_key_t& m) {
        uint64_t m_tx_redirect_code;
            archive(::cereal::make_nvp("tx_redirect_code", m_tx_redirect_code));
        m.tx_redirect_code = m_tx_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_key_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_tx_redirect_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_tx_redirect_counter_table_key_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_tx_redirect_counter_table_key_t&);



template<>
class serializer_class<npl_inject_down_tx_redirect_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_tx_redirect_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_value_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_tx_redirect_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_tx_redirect_counter_table_value_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_tx_redirect_counter_table_value_t&);



template<>
class serializer_class<npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_meter_found", m.counter_meter_found));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("counter_meter_found", m.counter_meter_found));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t& m)
{
    serializer_class<npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_down_tx_redirect_counter_table_value_t::npl_inject_down_tx_redirect_counter_table_payloads_t&);



template<>
class serializer_class<npl_inject_mact_ldb_to_output_lr_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_mact_ldb_to_output_lr_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_mact_ldb_to_output_lr_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_mact_ldb_to_output_lr_key_t& m)
{
    serializer_class<npl_inject_mact_ldb_to_output_lr_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_mact_ldb_to_output_lr_key_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_mact_ldb_to_output_lr_key_t& m)
{
    serializer_class<npl_inject_mact_ldb_to_output_lr_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_mact_ldb_to_output_lr_key_t&);



template<>
class serializer_class<npl_inject_mact_ldb_to_output_lr_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_mact_ldb_to_output_lr_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_mact_ldb_to_output_lr_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_mact_ldb_to_output_lr_value_t& m)
{
    serializer_class<npl_inject_mact_ldb_to_output_lr_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_mact_ldb_to_output_lr_value_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_mact_ldb_to_output_lr_value_t& m)
{
    serializer_class<npl_inject_mact_ldb_to_output_lr_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_mact_ldb_to_output_lr_value_t&);



template<>
class serializer_class<npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t& m) {
        uint64_t m_output_learn_record_mact_ldb = m.output_learn_record_mact_ldb;
            archive(::cereal::make_nvp("output_learn_record_mact_ldb", m_output_learn_record_mact_ldb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t& m) {
        uint64_t m_output_learn_record_mact_ldb;
            archive(::cereal::make_nvp("output_learn_record_mact_ldb", m_output_learn_record_mact_ldb));
        m.output_learn_record_mact_ldb = m_output_learn_record_mact_ldb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t& m)
{
    serializer_class<npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t& m)
{
    serializer_class<npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_mact_ldb_to_output_lr_value_t::npl_inject_mact_ldb_to_output_lr_payloads_t&);



template<>
class serializer_class<npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t& m) {
            archive(::cereal::make_nvp("slice_and_source_if", m.slice_and_source_if));
            archive(::cereal::make_nvp("init_data", m.init_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t& m) {
            archive(::cereal::make_nvp("slice_and_source_if", m.slice_and_source_if));
            archive(::cereal::make_nvp("init_data", m.init_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_pif_ifg_init_data_table_write_init_data_for_pif_ifg_payload_t&);



template<>
class serializer_class<npl_inject_up_pif_ifg_init_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_key_t& m) {
        uint64_t m_initial_slice_id = m.initial_slice_id;
            archive(::cereal::make_nvp("initial_slice_id", m_initial_slice_id));
            archive(::cereal::make_nvp("source_if", m.source_if));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_key_t& m) {
        uint64_t m_initial_slice_id;
            archive(::cereal::make_nvp("initial_slice_id", m_initial_slice_id));
            archive(::cereal::make_nvp("source_if", m.source_if));
        m.initial_slice_id = m_initial_slice_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_key_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_pif_ifg_init_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_key_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_pif_ifg_init_data_table_key_t&);



template<>
class serializer_class<npl_inject_up_pif_ifg_init_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_value_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_pif_ifg_init_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_value_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_pif_ifg_init_data_table_value_t&);



template<>
class serializer_class<npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("write_init_data_for_pif_ifg", m.write_init_data_for_pif_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("write_init_data_for_pif_ifg", m.write_init_data_for_pif_ifg));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t& m)
{
    serializer_class<npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_pif_ifg_init_data_table_value_t::npl_inject_up_pif_ifg_init_data_table_payloads_t&);



template<>
class serializer_class<npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t& m) {
            archive(::cereal::make_nvp("init_data", m.init_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t& m) {
            archive(::cereal::make_nvp("init_data", m.init_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_ssp_init_data_table_write_init_data_for_ssp_payload_t&);



template<>
class serializer_class<npl_inject_up_ssp_init_data_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_ssp_init_data_table_key_t& m) {
        uint64_t m_up_ssp = m.up_ssp;
            archive(::cereal::make_nvp("up_ssp", m_up_ssp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_ssp_init_data_table_key_t& m) {
        uint64_t m_up_ssp;
            archive(::cereal::make_nvp("up_ssp", m_up_ssp));
        m.up_ssp = m_up_ssp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_ssp_init_data_table_key_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_ssp_init_data_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_ssp_init_data_table_key_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_ssp_init_data_table_key_t&);



template<>
class serializer_class<npl_inject_up_ssp_init_data_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_ssp_init_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_ssp_init_data_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_ssp_init_data_table_value_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_ssp_init_data_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_ssp_init_data_table_value_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_ssp_init_data_table_value_t&);



template<>
class serializer_class<npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("write_init_data_for_ssp", m.write_init_data_for_ssp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t& m) {
            archive(::cereal::make_nvp("write_init_data_for_ssp", m.write_init_data_for_ssp));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t& m)
{
    serializer_class<npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inject_up_ssp_init_data_table_value_t::npl_inject_up_ssp_init_data_table_payloads_t&);



template<>
class serializer_class<npl_inner_tpid_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inner_tpid_table_key_t& m) {
        uint64_t m_tpid_ptr = m.tpid_ptr;
            archive(::cereal::make_nvp("tpid_ptr", m_tpid_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inner_tpid_table_key_t& m) {
        uint64_t m_tpid_ptr;
            archive(::cereal::make_nvp("tpid_ptr", m_tpid_ptr));
        m.tpid_ptr = m_tpid_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inner_tpid_table_key_t& m)
{
    serializer_class<npl_inner_tpid_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inner_tpid_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_inner_tpid_table_key_t& m)
{
    serializer_class<npl_inner_tpid_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inner_tpid_table_key_t&);



template<>
class serializer_class<npl_inner_tpid_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inner_tpid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inner_tpid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inner_tpid_table_value_t& m)
{
    serializer_class<npl_inner_tpid_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inner_tpid_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_inner_tpid_table_value_t& m)
{
    serializer_class<npl_inner_tpid_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inner_tpid_table_value_t&);



template<>
class serializer_class<npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t& m) {
        uint64_t m_tpid = m.tpid;
            archive(::cereal::make_nvp("tpid", m_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t& m) {
        uint64_t m_tpid;
            archive(::cereal::make_nvp("tpid", m_tpid));
        m.tpid = m_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t& m)
{
    serializer_class<npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t& m)
{
    serializer_class<npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_inner_tpid_table_value_t::npl_inner_tpid_table_payloads_t&);



template<>
class serializer_class<npl_ip_fi_core_tcam_table_next_header_info_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_next_header_info_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_fi_core_tcam_table_next_header_info_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_next_header_info_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_fi_core_tcam_table_next_header_info_payload_t&);



}

