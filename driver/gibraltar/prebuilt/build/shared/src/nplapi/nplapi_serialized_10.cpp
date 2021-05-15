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

template <class Archive> void save(Archive&, const npl_counter_offset_t&);
template <class Archive> void load(Archive&, npl_counter_offset_t&);

template <class Archive> void save(Archive&, const npl_counter_ptr_t&);
template <class Archive> void load(Archive&, npl_counter_ptr_t&);

template <class Archive> void save(Archive&, const npl_db_access_lu_data_t&);
template <class Archive> void load(Archive&, npl_db_access_lu_data_t&);

template <class Archive> void save(Archive&, const npl_dlp_profile_local_vars_t&);
template <class Archive> void load(Archive&, npl_dlp_profile_local_vars_t&);

template <class Archive> void save(Archive&, const npl_dlp_profile_union_t&);
template <class Archive> void load(Archive&, npl_dlp_profile_union_t&);

template <class Archive> void save(Archive&, const npl_egress_qos_result_t&);
template <class Archive> void load(Archive&, npl_egress_qos_result_t&);

template <class Archive> void save(Archive&, const npl_fi_tcam_hardwired_result_t&);
template <class Archive> void load(Archive&, npl_fi_tcam_hardwired_result_t&);

template <class Archive> void save(Archive&, const npl_ibm_enables_table_result_t&);
template <class Archive> void load(Archive&, npl_ibm_enables_table_result_t&);

template <class Archive> void save(Archive&, const npl_lm_command_t&);
template <class Archive> void load(Archive&, npl_lm_command_t&);

template <class Archive> void save(Archive&, const npl_pcp_dei_t&);
template <class Archive> void load(Archive&, npl_pcp_dei_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_ibm_tc_map_result_t&);
template <class Archive> void load(Archive&, npl_rxpdr_ibm_tc_map_result_t&);

template <class Archive> void save(Archive&, const npl_ts_cmd_trans_t&);
template <class Archive> void load(Archive&, npl_ts_cmd_trans_t&);

template <class Archive> void save(Archive&, const npl_ts_command_t&);
template <class Archive> void load(Archive&, npl_ts_command_t&);

template <class Archive> void save(Archive&, const npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t&);
template <class Archive> void load(Archive&, npl_tx_punt_local_var_t_anonymous_union_ene_eth_or_npu_host_data_t&);

template <class Archive> void save(Archive&, const npl_tx_punt_nw_encap_ptr_t&);
template <class Archive> void load(Archive&, npl_tx_punt_nw_encap_ptr_t&);

template <class Archive> void save(Archive&, const npl_txpp_em_dlp_profile_mapping_key_t&);
template <class Archive> void load(Archive&, npl_txpp_em_dlp_profile_mapping_key_t&);

template <class Archive> void save(Archive&, const npl_txpp_first_macro_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_first_macro_table_key_t&);

template <class Archive> void save(Archive&, const npl_vni_table_result_t&);
template <class Archive> void load(Archive&, npl_vni_table_result_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_drop_color_probability_selector_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_drop_color_probability_selector_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_result_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_result_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_mark_color_probability_selector_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_mark_color_probability_selector_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_pd_consumption_lut_for_deq_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_pd_consumption_lut_for_enq_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_buff_region_thresholds_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_buff_region_thresholds_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_slice_cgm_profile_result_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_slice_cgm_profile_result_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_wred_probability_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_wred_probability_results_t&);

template <class Archive> void save(Archive&, const npl_voq_profile_len&);
template <class Archive> void load(Archive&, npl_voq_profile_len&);

template <class Archive> void save(Archive&, const npl_vxlan_dlp_specific_t&);
template <class Archive> void load(Archive&, npl_vxlan_dlp_specific_t&);

template<>
class serializer_class<npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_c_lu_data", m.trans_bucket_c_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_c_lu_data", m.trans_bucket_c_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_c_lu_data_selector_value_t::npl_transmit_bucket_c_lu_data_selector_payloads_t&);



template<>
class serializer_class<npl_transmit_bucket_d_lu_data_selector_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_d_lu_data_selector_key_t& m) {
        uint64_t m_lu_d_key_index = m.lu_d_key_index;
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
            archive(::cereal::make_nvp("lu_d_key_index", m_lu_d_key_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_d_lu_data_selector_key_t& m) {
        uint64_t m_lu_d_key_index;
            archive(::cereal::make_nvp("lu_d_dest", m.lu_d_dest));
            archive(::cereal::make_nvp("lu_d_key_index", m_lu_d_key_index));
        m.lu_d_key_index = m_lu_d_key_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_d_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_d_lu_data_selector_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_d_lu_data_selector_key_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_d_lu_data_selector_key_t& m)
{
    serializer_class<npl_transmit_bucket_d_lu_data_selector_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_d_lu_data_selector_key_t&);



template<>
class serializer_class<npl_transmit_bucket_d_lu_data_selector_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_d_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_d_lu_data_selector_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_d_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_d_lu_data_selector_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_d_lu_data_selector_value_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_d_lu_data_selector_value_t& m)
{
    serializer_class<npl_transmit_bucket_d_lu_data_selector_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_d_lu_data_selector_value_t&);



template<>
class serializer_class<npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_d_lu_data", m.trans_bucket_d_lu_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t& m) {
            archive(::cereal::make_nvp("trans_bucket_d_lu_data", m.trans_bucket_d_lu_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t& m)
{
    serializer_class<npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_transmit_bucket_d_lu_data_selector_value_t::npl_transmit_bucket_d_lu_data_selector_payloads_t&);



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
class serializer_class<npl_tx_counters_bank_id_map_config_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_bank_id_map_config_key_t& m) {
        uint64_t m_npu_bank_id = m.npu_bank_id;
        uint64_t m_ifg = m.ifg;
            archive(::cereal::make_nvp("npu_bank_id", m_npu_bank_id));
            archive(::cereal::make_nvp("ifg", m_ifg));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_bank_id_map_config_key_t& m) {
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
save(Archive& archive, const npl_tx_counters_bank_id_map_config_key_t& m)
{
    serializer_class<npl_tx_counters_bank_id_map_config_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_counters_bank_id_map_config_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_counters_bank_id_map_config_key_t& m)
{
    serializer_class<npl_tx_counters_bank_id_map_config_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_counters_bank_id_map_config_key_t&);



template<>
class serializer_class<npl_tx_counters_bank_id_map_config_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_bank_id_map_config_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_bank_id_map_config_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_counters_bank_id_map_config_value_t& m)
{
    serializer_class<npl_tx_counters_bank_id_map_config_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_counters_bank_id_map_config_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_counters_bank_id_map_config_value_t& m)
{
    serializer_class<npl_tx_counters_bank_id_map_config_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_counters_bank_id_map_config_value_t&);



template<>
class serializer_class<npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t& m) {
        uint64_t m_counter_bank_id = m.counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t& m) {
        uint64_t m_counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
        m.counter_bank_id = m_counter_bank_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t& m)
{
    serializer_class<npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t& m)
{
    serializer_class<npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_counters_bank_id_map_config_value_t::npl_tx_counters_bank_id_map_config_payloads_t&);



template<>
class serializer_class<npl_tx_counters_block_config_table_config_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_counters_block_config_table_config_payload_t& m) {
        uint64_t m_inc_addr_for_set = m.inc_addr_for_set;
            archive(::cereal::make_nvp("inc_addr_for_set", m_inc_addr_for_set));
            archive(::cereal::make_nvp("bank_set_type", m.bank_set_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_block_config_table_config_payload_t& m) {
        uint64_t m_inc_addr_for_set;
            archive(::cereal::make_nvp("inc_addr_for_set", m_inc_addr_for_set));
            archive(::cereal::make_nvp("bank_set_type", m.bank_set_type));
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
        uint64_t m_counter_bank_id = m.counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_counters_block_config_table_key_t& m) {
        uint64_t m_counter_bank_id;
            archive(::cereal::make_nvp("counter_bank_id", m_counter_bank_id));
        m.counter_bank_id = m_counter_bank_id;
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



template<>
class serializer_class<npl_tx_redirect_code_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_redirect_code_table_key_t& m) {
        uint64_t m_tx_redirect_code = m.tx_redirect_code;
            archive(::cereal::make_nvp("tx_redirect_code", m_tx_redirect_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_redirect_code_table_key_t& m) {
        uint64_t m_tx_redirect_code;
            archive(::cereal::make_nvp("tx_redirect_code", m_tx_redirect_code));
        m.tx_redirect_code = m_tx_redirect_code;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_redirect_code_table_key_t& m)
{
    serializer_class<npl_tx_redirect_code_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_redirect_code_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_redirect_code_table_key_t& m)
{
    serializer_class<npl_tx_redirect_code_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_redirect_code_table_key_t&);



template<>
class serializer_class<npl_tx_redirect_code_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_redirect_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_redirect_code_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_redirect_code_table_value_t& m)
{
    serializer_class<npl_tx_redirect_code_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_redirect_code_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_redirect_code_table_value_t& m)
{
    serializer_class<npl_tx_redirect_code_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_redirect_code_table_value_t&);



template<>
class serializer_class<npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("tx_redirect_action", m.tx_redirect_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t& m) {
            archive(::cereal::make_nvp("tx_redirect_action", m.tx_redirect_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t& m)
{
    serializer_class<npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t& m)
{
    serializer_class<npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_tx_redirect_code_table_value_t::npl_tx_redirect_code_table_payloads_t&);



template<>
class serializer_class<npl_txpdr_mc_list_size_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpdr_mc_list_size_table_key_t& m) {
        uint64_t m_rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid = m.rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid;
            archive(::cereal::make_nvp("rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid", m_rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpdr_mc_list_size_table_key_t& m) {
        uint64_t m_rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid;
            archive(::cereal::make_nvp("rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid", m_rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid));
        m.rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid = m_rxpdr_output_rxrq_cud_rxrq_cud_encoding_mcid_mcid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpdr_mc_list_size_table_key_t& m)
{
    serializer_class<npl_txpdr_mc_list_size_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpdr_mc_list_size_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpdr_mc_list_size_table_key_t& m)
{
    serializer_class<npl_txpdr_mc_list_size_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpdr_mc_list_size_table_key_t&);



template<>
class serializer_class<npl_txpdr_mc_list_size_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpdr_mc_list_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpdr_mc_list_size_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpdr_mc_list_size_table_value_t& m)
{
    serializer_class<npl_txpdr_mc_list_size_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpdr_mc_list_size_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpdr_mc_list_size_table_value_t& m)
{
    serializer_class<npl_txpdr_mc_list_size_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpdr_mc_list_size_table_value_t&);



template<>
class serializer_class<npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t& m) {
        uint64_t m_txpdr_local_vars_mc_group_size = m.txpdr_local_vars_mc_group_size;
            archive(::cereal::make_nvp("txpdr_local_vars_mc_group_size", m_txpdr_local_vars_mc_group_size));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t& m) {
        uint64_t m_txpdr_local_vars_mc_group_size;
            archive(::cereal::make_nvp("txpdr_local_vars_mc_group_size", m_txpdr_local_vars_mc_group_size));
        m.txpdr_local_vars_mc_group_size = m_txpdr_local_vars_mc_group_size;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t& m)
{
    serializer_class<npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t& m)
{
    serializer_class<npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpdr_mc_list_size_table_value_t::npl_txpdr_mc_list_size_table_payloads_t&);



template<>
class serializer_class<npl_txpdr_tc_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpdr_tc_map_table_key_t& m) {
        uint64_t m_txpdr_local_vars_tc_map_profile = m.txpdr_local_vars_tc_map_profile;
        uint64_t m_rxpp_pd_tc = m.rxpp_pd_tc;
            archive(::cereal::make_nvp("txpdr_local_vars_tc_map_profile", m_txpdr_local_vars_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpdr_tc_map_table_key_t& m) {
        uint64_t m_txpdr_local_vars_tc_map_profile;
        uint64_t m_rxpp_pd_tc;
            archive(::cereal::make_nvp("txpdr_local_vars_tc_map_profile", m_txpdr_local_vars_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
        m.txpdr_local_vars_tc_map_profile = m_txpdr_local_vars_tc_map_profile;
        m.rxpp_pd_tc = m_rxpp_pd_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpdr_tc_map_table_key_t& m)
{
    serializer_class<npl_txpdr_tc_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpdr_tc_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpdr_tc_map_table_key_t& m)
{
    serializer_class<npl_txpdr_tc_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpdr_tc_map_table_key_t&);



template<>
class serializer_class<npl_txpdr_tc_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpdr_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpdr_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpdr_tc_map_table_value_t& m)
{
    serializer_class<npl_txpdr_tc_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpdr_tc_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpdr_tc_map_table_value_t& m)
{
    serializer_class<npl_txpdr_tc_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpdr_tc_map_table_value_t&);



template<>
class serializer_class<npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t& m) {
        uint64_t m_txpdr_local_vars_tc_offset = m.txpdr_local_vars_tc_offset;
            archive(::cereal::make_nvp("txpdr_local_vars_tc_offset", m_txpdr_local_vars_tc_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t& m) {
        uint64_t m_txpdr_local_vars_tc_offset;
            archive(::cereal::make_nvp("txpdr_local_vars_tc_offset", m_txpdr_local_vars_tc_offset));
        m.txpdr_local_vars_tc_offset = m_txpdr_local_vars_tc_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t& m)
{
    serializer_class<npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t& m)
{
    serializer_class<npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpdr_tc_map_table_value_t::npl_txpdr_tc_map_table_payloads_t&);



template<>
class serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_dlp_profile_key_construct_parameters_table_key_t& m) {
        uint64_t m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ = m.packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_fwd_header_type", m.packet_protocol_layer_0__tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_", m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_dlp_profile_key_construct_parameters_table_key_t& m) {
        uint64_t m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_fwd_header_type", m.packet_protocol_layer_0__tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_", m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_));
        m.packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ = m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_dlp_profile_key_construct_parameters_table_key_t& m)
{
    serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_dlp_profile_key_construct_parameters_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_dlp_profile_key_construct_parameters_table_key_t& m)
{
    serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_dlp_profile_key_construct_parameters_table_key_t&);



template<>
class serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_dlp_profile_key_construct_parameters_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_dlp_profile_key_construct_parameters_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_dlp_profile_key_construct_parameters_table_value_t& m)
{
    serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_dlp_profile_key_construct_parameters_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_dlp_profile_key_construct_parameters_table_value_t& m)
{
    serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_dlp_profile_key_construct_parameters_table_value_t&);



template<>
class serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t& m) {
            archive(::cereal::make_nvp("dlp_profile_local_vars", m.dlp_profile_local_vars));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t& m) {
            archive(::cereal::make_nvp("dlp_profile_local_vars", m.dlp_profile_local_vars));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t& m)
{
    serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t& m)
{
    serializer_class<npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_dlp_profile_key_construct_parameters_table_value_t::npl_txpp_dlp_profile_key_construct_parameters_table_payloads_t&);



template<>
class serializer_class<npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t& m) {
        uint64_t m_dlp_attributes = m.dlp_attributes;
            archive(::cereal::make_nvp("dlp_profile", m.dlp_profile));
            archive(::cereal::make_nvp("dlp_attributes", m_dlp_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t& m) {
        uint64_t m_dlp_attributes;
            archive(::cereal::make_nvp("dlp_profile", m.dlp_profile));
            archive(::cereal::make_nvp("dlp_attributes", m_dlp_attributes));
        m.dlp_attributes = m_dlp_attributes;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_em_dlp_profile_mapping_table_init_tx_profile_data_payload_t&);



template<>
class serializer_class<npl_txpp_em_dlp_profile_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_em_dlp_profile_mapping_key", m.txpp_em_dlp_profile_mapping_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_em_dlp_profile_mapping_key", m.txpp_em_dlp_profile_mapping_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_key_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_em_dlp_profile_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_key_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_em_dlp_profile_mapping_table_key_t&);



template<>
class serializer_class<npl_txpp_em_dlp_profile_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_value_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_em_dlp_profile_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_value_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_em_dlp_profile_mapping_table_value_t&);



template<>
class serializer_class<npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_tx_profile_data", m.init_tx_profile_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_tx_profile_data", m.init_tx_profile_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t& m)
{
    serializer_class<npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_em_dlp_profile_mapping_table_value_t::npl_txpp_em_dlp_profile_mapping_table_payloads_t&);



template<>
class serializer_class<npl_txpp_encap_qos_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_encap_qos_mapping_table_key_t& m) {
        uint64_t m_packet_protocol_layer_none__tx_npu_header_slp_qos_id = m.packet_protocol_layer_none__tx_npu_header_slp_qos_id;
        uint64_t m_pd_tx_out_color = m.pd_tx_out_color;
        uint64_t m_packet_protocol_layer_none__tx_npu_header_encap_qos_tag = m.packet_protocol_layer_none__tx_npu_header_encap_qos_tag;
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_slp_qos_id", m_packet_protocol_layer_none__tx_npu_header_slp_qos_id));
            archive(::cereal::make_nvp("pd_tx_out_color", m_pd_tx_out_color));
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_encap_qos_tag", m_packet_protocol_layer_none__tx_npu_header_encap_qos_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_encap_qos_mapping_table_key_t& m) {
        uint64_t m_packet_protocol_layer_none__tx_npu_header_slp_qos_id;
        uint64_t m_pd_tx_out_color;
        uint64_t m_packet_protocol_layer_none__tx_npu_header_encap_qos_tag;
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_slp_qos_id", m_packet_protocol_layer_none__tx_npu_header_slp_qos_id));
            archive(::cereal::make_nvp("pd_tx_out_color", m_pd_tx_out_color));
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_encap_qos_tag", m_packet_protocol_layer_none__tx_npu_header_encap_qos_tag));
        m.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_packet_protocol_layer_none__tx_npu_header_slp_qos_id;
        m.pd_tx_out_color = m_pd_tx_out_color;
        m.packet_protocol_layer_none__tx_npu_header_encap_qos_tag = m_packet_protocol_layer_none__tx_npu_header_encap_qos_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_encap_qos_mapping_table_key_t& m)
{
    serializer_class<npl_txpp_encap_qos_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_encap_qos_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_encap_qos_mapping_table_key_t& m)
{
    serializer_class<npl_txpp_encap_qos_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_encap_qos_mapping_table_key_t&);



template<>
class serializer_class<npl_txpp_encap_qos_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_encap_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_encap_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_encap_qos_mapping_table_value_t& m)
{
    serializer_class<npl_txpp_encap_qos_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_encap_qos_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_encap_qos_mapping_table_value_t& m)
{
    serializer_class<npl_txpp_encap_qos_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_encap_qos_mapping_table_value_t&);



template<>
class serializer_class<npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t& m) {
        uint64_t m_txpp_npu_header_encap_qos_tag = m.txpp_npu_header_encap_qos_tag;
            archive(::cereal::make_nvp("txpp_npu_header_encap_qos_tag", m_txpp_npu_header_encap_qos_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t& m) {
        uint64_t m_txpp_npu_header_encap_qos_tag;
            archive(::cereal::make_nvp("txpp_npu_header_encap_qos_tag", m_txpp_npu_header_encap_qos_tag));
        m.txpp_npu_header_encap_qos_tag = m_txpp_npu_header_encap_qos_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_encap_qos_mapping_table_value_t::npl_txpp_encap_qos_mapping_table_payloads_t&);



template<>
class serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_first_enc_type_to_second_enc_type_offset_key_t& m) {
        uint64_t m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ = m.packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_", m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_first_enc_type_to_second_enc_type_offset_key_t& m) {
        uint64_t m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_", m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_));
        m.packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ = m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_first_enc_type_to_second_enc_type_offset_key_t& m)
{
    serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_first_enc_type_to_second_enc_type_offset_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_first_enc_type_to_second_enc_type_offset_key_t& m)
{
    serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_first_enc_type_to_second_enc_type_offset_key_t&);



template<>
class serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_first_enc_type_to_second_enc_type_offset_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_first_enc_type_to_second_enc_type_offset_value_t& m)
{
    serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_first_enc_type_to_second_enc_type_offset_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t& m)
{
    serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t&);



template<>
class serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t& m) {
            archive(::cereal::make_nvp("txpp_first_encap_is_wide", m.txpp_first_encap_is_wide));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t& m) {
            archive(::cereal::make_nvp("txpp_first_encap_is_wide", m.txpp_first_encap_is_wide));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t& m)
{
    serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t& m)
{
    serializer_class<npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_first_enc_type_to_second_enc_type_offset_value_t::npl_txpp_first_enc_type_to_second_enc_type_offset_payloads_t&);



template<>
class serializer_class<npl_txpp_fwd_qos_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_fwd_qos_mapping_table_key_t& m) {
        uint64_t m_packet_protocol_layer_none__tx_npu_header_slp_qos_id = m.packet_protocol_layer_none__tx_npu_header_slp_qos_id;
        uint64_t m_pd_tx_out_color = m.pd_tx_out_color;
        uint64_t m_packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = m.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag;
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_slp_qos_id", m_packet_protocol_layer_none__tx_npu_header_slp_qos_id));
            archive(::cereal::make_nvp("pd_tx_out_color", m_pd_tx_out_color));
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_fwd_qos_tag", m_packet_protocol_layer_none__tx_npu_header_fwd_qos_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_fwd_qos_mapping_table_key_t& m) {
        uint64_t m_packet_protocol_layer_none__tx_npu_header_slp_qos_id;
        uint64_t m_pd_tx_out_color;
        uint64_t m_packet_protocol_layer_none__tx_npu_header_fwd_qos_tag;
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_slp_qos_id", m_packet_protocol_layer_none__tx_npu_header_slp_qos_id));
            archive(::cereal::make_nvp("pd_tx_out_color", m_pd_tx_out_color));
            archive(::cereal::make_nvp("packet_protocol_layer_none__tx_npu_header_fwd_qos_tag", m_packet_protocol_layer_none__tx_npu_header_fwd_qos_tag));
        m.packet_protocol_layer_none__tx_npu_header_slp_qos_id = m_packet_protocol_layer_none__tx_npu_header_slp_qos_id;
        m.pd_tx_out_color = m_pd_tx_out_color;
        m.packet_protocol_layer_none__tx_npu_header_fwd_qos_tag = m_packet_protocol_layer_none__tx_npu_header_fwd_qos_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_fwd_qos_mapping_table_key_t& m)
{
    serializer_class<npl_txpp_fwd_qos_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_fwd_qos_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_fwd_qos_mapping_table_key_t& m)
{
    serializer_class<npl_txpp_fwd_qos_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_fwd_qos_mapping_table_key_t&);



template<>
class serializer_class<npl_txpp_fwd_qos_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_fwd_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_fwd_qos_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_fwd_qos_mapping_table_value_t& m)
{
    serializer_class<npl_txpp_fwd_qos_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_fwd_qos_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_fwd_qos_mapping_table_value_t& m)
{
    serializer_class<npl_txpp_fwd_qos_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_fwd_qos_mapping_table_value_t&);



template<>
class serializer_class<npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t& m) {
        uint64_t m_txpp_npu_header_fwd_qos_tag = m.txpp_npu_header_fwd_qos_tag;
            archive(::cereal::make_nvp("txpp_npu_header_fwd_qos_tag", m_txpp_npu_header_fwd_qos_tag));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t& m) {
        uint64_t m_txpp_npu_header_fwd_qos_tag;
            archive(::cereal::make_nvp("txpp_npu_header_fwd_qos_tag", m_txpp_npu_header_fwd_qos_tag));
        m.txpp_npu_header_fwd_qos_tag = m_txpp_npu_header_fwd_qos_tag;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t& m)
{
    serializer_class<npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_fwd_qos_mapping_table_value_t::npl_txpp_fwd_qos_mapping_table_payloads_t&);



template<>
class serializer_class<npl_txpp_ibm_enables_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_ibm_enables_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_ibm_enables_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_ibm_enables_table_key_t& m)
{
    serializer_class<npl_txpp_ibm_enables_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_ibm_enables_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_ibm_enables_table_key_t& m)
{
    serializer_class<npl_txpp_ibm_enables_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_ibm_enables_table_key_t&);



template<>
class serializer_class<npl_txpp_ibm_enables_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_ibm_enables_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_ibm_enables_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_ibm_enables_table_value_t& m)
{
    serializer_class<npl_txpp_ibm_enables_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_ibm_enables_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_ibm_enables_table_value_t& m)
{
    serializer_class<npl_txpp_ibm_enables_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_ibm_enables_table_value_t&);



template<>
class serializer_class<npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_enables_table_result", m.ibm_enables_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t& m) {
            archive(::cereal::make_nvp("ibm_enables_table_result", m.ibm_enables_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t& m)
{
    serializer_class<npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t& m)
{
    serializer_class<npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_ibm_enables_table_value_t::npl_txpp_ibm_enables_table_payloads_t&);



template<>
class serializer_class<npl_txpp_initial_npe_macro_table_init_tx_data_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_initial_npe_macro_table_init_tx_data_payload_t& m) {
        uint64_t m_np_macro_id = m.np_macro_id;
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_initial_npe_macro_table_init_tx_data_payload_t& m) {
        uint64_t m_np_macro_id;
            archive(::cereal::make_nvp("np_macro_id", m_np_macro_id));
        m.np_macro_id = m_np_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_initial_npe_macro_table_init_tx_data_payload_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_init_tx_data_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_initial_npe_macro_table_init_tx_data_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_initial_npe_macro_table_init_tx_data_payload_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_init_tx_data_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_initial_npe_macro_table_init_tx_data_payload_t&);



template<>
class serializer_class<npl_txpp_initial_npe_macro_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_initial_npe_macro_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_first_macro_table_key", m.txpp_first_macro_table_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_initial_npe_macro_table_key_t& m) {
            archive(::cereal::make_nvp("txpp_first_macro_table_key", m.txpp_first_macro_table_key));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_initial_npe_macro_table_key_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_initial_npe_macro_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_initial_npe_macro_table_key_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_initial_npe_macro_table_key_t&);



template<>
class serializer_class<npl_txpp_initial_npe_macro_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_initial_npe_macro_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_initial_npe_macro_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_initial_npe_macro_table_value_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_initial_npe_macro_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_initial_npe_macro_table_value_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_initial_npe_macro_table_value_t&);



template<>
class serializer_class<npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_tx_data", m.init_tx_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t& m) {
            archive(::cereal::make_nvp("init_tx_data", m.init_tx_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t& m)
{
    serializer_class<npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_initial_npe_macro_table_value_t::npl_txpp_initial_npe_macro_table_payloads_t&);



template<>
class serializer_class<npl_txpp_mapping_qos_tag_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_mapping_qos_tag_table_key_t& m) {
        uint64_t m_qos_tag = m.qos_tag;
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("qos_tag", m_qos_tag));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_mapping_qos_tag_table_key_t& m) {
        uint64_t m_qos_tag;
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("qos_tag", m_qos_tag));
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.qos_tag = m_qos_tag;
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_mapping_qos_tag_table_key_t& m)
{
    serializer_class<npl_txpp_mapping_qos_tag_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_mapping_qos_tag_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_mapping_qos_tag_table_key_t& m)
{
    serializer_class<npl_txpp_mapping_qos_tag_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_mapping_qos_tag_table_key_t&);



template<>
class serializer_class<npl_txpp_mapping_qos_tag_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_mapping_qos_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_mapping_qos_tag_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_mapping_qos_tag_table_value_t& m)
{
    serializer_class<npl_txpp_mapping_qos_tag_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_mapping_qos_tag_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_mapping_qos_tag_table_value_t& m)
{
    serializer_class<npl_txpp_mapping_qos_tag_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_mapping_qos_tag_table_value_t&);



template<>
class serializer_class<npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("egress_qos_result", m.egress_qos_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t& m) {
            archive(::cereal::make_nvp("egress_qos_result", m.egress_qos_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t& m)
{
    serializer_class<npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t& m)
{
    serializer_class<npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_mapping_qos_tag_table_value_t::npl_txpp_mapping_qos_tag_table_payloads_t&);



template<>
class serializer_class<npl_uc_ibm_tc_map_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_uc_ibm_tc_map_table_key_t& m) {
        uint64_t m_ibm_cmd_table_result_tc_map_profile = m.ibm_cmd_table_result_tc_map_profile;
        uint64_t m_rxpp_pd_tc = m.rxpp_pd_tc;
            archive(::cereal::make_nvp("ibm_cmd_table_result_tc_map_profile", m_ibm_cmd_table_result_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_uc_ibm_tc_map_table_key_t& m) {
        uint64_t m_ibm_cmd_table_result_tc_map_profile;
        uint64_t m_rxpp_pd_tc;
            archive(::cereal::make_nvp("ibm_cmd_table_result_tc_map_profile", m_ibm_cmd_table_result_tc_map_profile));
            archive(::cereal::make_nvp("rxpp_pd_tc", m_rxpp_pd_tc));
        m.ibm_cmd_table_result_tc_map_profile = m_ibm_cmd_table_result_tc_map_profile;
        m.rxpp_pd_tc = m_rxpp_pd_tc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_uc_ibm_tc_map_table_key_t& m)
{
    serializer_class<npl_uc_ibm_tc_map_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_uc_ibm_tc_map_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_uc_ibm_tc_map_table_key_t& m)
{
    serializer_class<npl_uc_ibm_tc_map_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_uc_ibm_tc_map_table_key_t&);



template<>
class serializer_class<npl_uc_ibm_tc_map_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_uc_ibm_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_uc_ibm_tc_map_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_uc_ibm_tc_map_table_value_t& m)
{
    serializer_class<npl_uc_ibm_tc_map_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_uc_ibm_tc_map_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_uc_ibm_tc_map_table_value_t& m)
{
    serializer_class<npl_uc_ibm_tc_map_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_uc_ibm_tc_map_table_value_t&);



template<>
class serializer_class<npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("rxpdr_ibm_tc_map_result", m.rxpdr_ibm_tc_map_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t& m) {
            archive(::cereal::make_nvp("rxpdr_ibm_tc_map_result", m.rxpdr_ibm_tc_map_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t& m)
{
    serializer_class<npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t& m)
{
    serializer_class<npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_uc_ibm_tc_map_table_value_t::npl_uc_ibm_tc_map_table_payloads_t&);



template<>
class serializer_class<npl_udp_fi_core_tcam_table_next_header_info_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_udp_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_udp_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_udp_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_next_header_info_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_udp_fi_core_tcam_table_next_header_info_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_udp_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_next_header_info_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_udp_fi_core_tcam_table_next_header_info_payload_t&);



template<>
class serializer_class<npl_udp_fi_core_tcam_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_udp_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid = m.ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_udp_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
        m.ethertype_or_tpid = m_ethertype_or_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_udp_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_udp_fi_core_tcam_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_udp_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_udp_fi_core_tcam_table_key_t&);



template<>
class serializer_class<npl_udp_fi_core_tcam_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_udp_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_udp_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_udp_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_udp_fi_core_tcam_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_udp_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_udp_fi_core_tcam_table_value_t&);



template<>
class serializer_class<npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_udp_fi_core_tcam_table_value_t::npl_udp_fi_core_tcam_table_payloads_t&);



template<>
class serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& m) {
        uint64_t m_ipsa_dest_prefix = m.ipsa_dest_prefix;
            archive(::cereal::make_nvp("ipsa_dest_prefix", m_ipsa_dest_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_urpf_ipsa_dest_is_lpts_static_table_key_t& m) {
        uint64_t m_ipsa_dest_prefix;
            archive(::cereal::make_nvp("ipsa_dest_prefix", m_ipsa_dest_prefix));
        m.ipsa_dest_prefix = m_ipsa_dest_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t& m)
{
    serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_urpf_ipsa_dest_is_lpts_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_urpf_ipsa_dest_is_lpts_static_table_key_t& m)
{
    serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_urpf_ipsa_dest_is_lpts_static_table_key_t&);



template<>
class serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_urpf_ipsa_dest_is_lpts_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_urpf_ipsa_dest_is_lpts_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_urpf_ipsa_dest_is_lpts_static_table_value_t& m)
{
    serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_urpf_ipsa_dest_is_lpts_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_urpf_ipsa_dest_is_lpts_static_table_value_t& m)
{
    serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_urpf_ipsa_dest_is_lpts_static_table_value_t&);



template<>
class serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t& m) {
        uint64_t m_is_lpts_prefix = m.is_lpts_prefix;
            archive(::cereal::make_nvp("is_lpts_prefix", m_is_lpts_prefix));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t& m) {
        uint64_t m_is_lpts_prefix;
            archive(::cereal::make_nvp("is_lpts_prefix", m_is_lpts_prefix));
        m.is_lpts_prefix = m_is_lpts_prefix;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t& m)
{
    serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t& m)
{
    serializer_class<npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_urpf_ipsa_dest_is_lpts_static_table_value_t::npl_urpf_ipsa_dest_is_lpts_static_table_payloads_t&);



template<>
class serializer_class<npl_vlan0_fi_core_tcam_table_next_header_info_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan0_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan0_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan0_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_next_header_info_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan0_fi_core_tcam_table_next_header_info_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan0_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_next_header_info_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan0_fi_core_tcam_table_next_header_info_payload_t&);



template<>
class serializer_class<npl_vlan0_fi_core_tcam_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan0_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid = m.ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan0_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
        m.ethertype_or_tpid = m_ethertype_or_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan0_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan0_fi_core_tcam_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan0_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan0_fi_core_tcam_table_key_t&);



template<>
class serializer_class<npl_vlan0_fi_core_tcam_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan0_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan0_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan0_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan0_fi_core_tcam_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan0_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan0_fi_core_tcam_table_value_t&);



template<>
class serializer_class<npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan0_fi_core_tcam_table_value_t::npl_vlan0_fi_core_tcam_table_payloads_t&);



template<>
class serializer_class<npl_vlan1_fi_core_tcam_table_next_header_info_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan1_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan1_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan1_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_next_header_info_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan1_fi_core_tcam_table_next_header_info_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan1_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_next_header_info_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan1_fi_core_tcam_table_next_header_info_payload_t&);



template<>
class serializer_class<npl_vlan1_fi_core_tcam_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan1_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid = m.ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan1_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
        m.ethertype_or_tpid = m_ethertype_or_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan1_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan1_fi_core_tcam_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan1_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan1_fi_core_tcam_table_key_t&);



template<>
class serializer_class<npl_vlan1_fi_core_tcam_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan1_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan1_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan1_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan1_fi_core_tcam_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan1_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan1_fi_core_tcam_table_value_t&);



template<>
class serializer_class<npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan1_fi_core_tcam_table_value_t::npl_vlan1_fi_core_tcam_table_payloads_t&);



template<>
class serializer_class<npl_vlan_edit_tpid1_profile_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_edit_tpid1_profile_hw_table_key_t& m) {
        uint64_t m_vlan_edit_info_tpid_profile = m.vlan_edit_info_tpid_profile;
            archive(::cereal::make_nvp("vlan_edit_info_tpid_profile", m_vlan_edit_info_tpid_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_edit_tpid1_profile_hw_table_key_t& m) {
        uint64_t m_vlan_edit_info_tpid_profile;
            archive(::cereal::make_nvp("vlan_edit_info_tpid_profile", m_vlan_edit_info_tpid_profile));
        m.vlan_edit_info_tpid_profile = m_vlan_edit_info_tpid_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_edit_tpid1_profile_hw_table_key_t& m)
{
    serializer_class<npl_vlan_edit_tpid1_profile_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_edit_tpid1_profile_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_edit_tpid1_profile_hw_table_key_t& m)
{
    serializer_class<npl_vlan_edit_tpid1_profile_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_edit_tpid1_profile_hw_table_key_t&);



template<>
class serializer_class<npl_vlan_edit_tpid1_profile_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_edit_tpid1_profile_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_edit_tpid1_profile_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_edit_tpid1_profile_hw_table_value_t& m)
{
    serializer_class<npl_vlan_edit_tpid1_profile_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_edit_tpid1_profile_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_edit_tpid1_profile_hw_table_value_t& m)
{
    serializer_class<npl_vlan_edit_tpid1_profile_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_edit_tpid1_profile_hw_table_value_t&);



template<>
class serializer_class<npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t& m) {
        uint64_t m_vlan_edit_info_tpid1 = m.vlan_edit_info_tpid1;
            archive(::cereal::make_nvp("vlan_edit_info_tpid1", m_vlan_edit_info_tpid1));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t& m) {
        uint64_t m_vlan_edit_info_tpid1;
            archive(::cereal::make_nvp("vlan_edit_info_tpid1", m_vlan_edit_info_tpid1));
        m.vlan_edit_info_tpid1 = m_vlan_edit_info_tpid1;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t& m)
{
    serializer_class<npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t& m)
{
    serializer_class<npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_edit_tpid1_profile_hw_table_value_t::npl_vlan_edit_tpid1_profile_hw_table_payloads_t&);



template<>
class serializer_class<npl_vlan_edit_tpid2_profile_hw_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_edit_tpid2_profile_hw_table_key_t& m) {
        uint64_t m_vlan_edit_info_tpid_profile = m.vlan_edit_info_tpid_profile;
            archive(::cereal::make_nvp("vlan_edit_info_tpid_profile", m_vlan_edit_info_tpid_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_edit_tpid2_profile_hw_table_key_t& m) {
        uint64_t m_vlan_edit_info_tpid_profile;
            archive(::cereal::make_nvp("vlan_edit_info_tpid_profile", m_vlan_edit_info_tpid_profile));
        m.vlan_edit_info_tpid_profile = m_vlan_edit_info_tpid_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_edit_tpid2_profile_hw_table_key_t& m)
{
    serializer_class<npl_vlan_edit_tpid2_profile_hw_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_edit_tpid2_profile_hw_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_edit_tpid2_profile_hw_table_key_t& m)
{
    serializer_class<npl_vlan_edit_tpid2_profile_hw_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_edit_tpid2_profile_hw_table_key_t&);



template<>
class serializer_class<npl_vlan_edit_tpid2_profile_hw_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_edit_tpid2_profile_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_edit_tpid2_profile_hw_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_edit_tpid2_profile_hw_table_value_t& m)
{
    serializer_class<npl_vlan_edit_tpid2_profile_hw_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_edit_tpid2_profile_hw_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_edit_tpid2_profile_hw_table_value_t& m)
{
    serializer_class<npl_vlan_edit_tpid2_profile_hw_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_edit_tpid2_profile_hw_table_value_t&);



template<>
class serializer_class<npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t& m) {
        uint64_t m_vlan_edit_info_tpid2 = m.vlan_edit_info_tpid2;
            archive(::cereal::make_nvp("vlan_edit_info_tpid2", m_vlan_edit_info_tpid2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t& m) {
        uint64_t m_vlan_edit_info_tpid2;
            archive(::cereal::make_nvp("vlan_edit_info_tpid2", m_vlan_edit_info_tpid2));
        m.vlan_edit_info_tpid2 = m_vlan_edit_info_tpid2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t& m)
{
    serializer_class<npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t& m)
{
    serializer_class<npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_edit_tpid2_profile_hw_table_value_t::npl_vlan_edit_tpid2_profile_hw_table_payloads_t&);



template<>
class serializer_class<npl_vlan_format_table_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_format_table_update_payload_t& m) {
        uint64_t m_vid_from_port = m.vid_from_port;
        uint64_t m_pcp_dei_from_port = m.pcp_dei_from_port;
        uint64_t m_dummy_bit = m.dummy_bit;
        uint64_t m_enable_l3_qos = m.enable_l3_qos;
            archive(::cereal::make_nvp("vid_from_port", m_vid_from_port));
            archive(::cereal::make_nvp("mac_termination_type", m.mac_termination_type));
            archive(::cereal::make_nvp("sm_selector", m.sm_selector));
            archive(::cereal::make_nvp("sm_logical_db", m.sm_logical_db));
            archive(::cereal::make_nvp("pcp_dei_from_port", m_pcp_dei_from_port));
            archive(::cereal::make_nvp("dummy_bit", m_dummy_bit));
            archive(::cereal::make_nvp("enable_l3_qos", m_enable_l3_qos));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_format_table_update_payload_t& m) {
        uint64_t m_vid_from_port;
        uint64_t m_pcp_dei_from_port;
        uint64_t m_dummy_bit;
        uint64_t m_enable_l3_qos;
            archive(::cereal::make_nvp("vid_from_port", m_vid_from_port));
            archive(::cereal::make_nvp("mac_termination_type", m.mac_termination_type));
            archive(::cereal::make_nvp("sm_selector", m.sm_selector));
            archive(::cereal::make_nvp("sm_logical_db", m.sm_logical_db));
            archive(::cereal::make_nvp("pcp_dei_from_port", m_pcp_dei_from_port));
            archive(::cereal::make_nvp("dummy_bit", m_dummy_bit));
            archive(::cereal::make_nvp("enable_l3_qos", m_enable_l3_qos));
        m.vid_from_port = m_vid_from_port;
        m.pcp_dei_from_port = m_pcp_dei_from_port;
        m.dummy_bit = m_dummy_bit;
        m.enable_l3_qos = m_enable_l3_qos;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_format_table_update_payload_t& m)
{
    serializer_class<npl_vlan_format_table_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_format_table_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_format_table_update_payload_t& m)
{
    serializer_class<npl_vlan_format_table_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_format_table_update_payload_t&);



template<>
class serializer_class<npl_vlan_format_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_format_table_key_t& m) {
        uint64_t m_vlan_profile = m.vlan_profile;
        uint64_t m_is_priority = m.is_priority;
            archive(::cereal::make_nvp("vlan_profile", m_vlan_profile));
            archive(::cereal::make_nvp("header_1_type", m.header_1_type));
            archive(::cereal::make_nvp("header_2_type", m.header_2_type));
            archive(::cereal::make_nvp("is_priority", m_is_priority));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_format_table_key_t& m) {
        uint64_t m_vlan_profile;
        uint64_t m_is_priority;
            archive(::cereal::make_nvp("vlan_profile", m_vlan_profile));
            archive(::cereal::make_nvp("header_1_type", m.header_1_type));
            archive(::cereal::make_nvp("header_2_type", m.header_2_type));
            archive(::cereal::make_nvp("is_priority", m_is_priority));
        m.vlan_profile = m_vlan_profile;
        m.is_priority = m_is_priority;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_format_table_key_t& m)
{
    serializer_class<npl_vlan_format_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_format_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_format_table_key_t& m)
{
    serializer_class<npl_vlan_format_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_format_table_key_t&);



template<>
class serializer_class<npl_vlan_format_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_format_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_format_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_format_table_value_t& m)
{
    serializer_class<npl_vlan_format_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_format_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_format_table_value_t& m)
{
    serializer_class<npl_vlan_format_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_format_table_value_t&);



template<>
class serializer_class<npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t& m)
{
    serializer_class<npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t& m)
{
    serializer_class<npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_format_table_value_t::npl_vlan_format_table_payloads_t&);



template<>
class serializer_class<npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t& m) {
            archive(::cereal::make_nvp("payload", m.payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_pe_fi_core_tcam_table_next_header_info_payload_t&);



template<>
class serializer_class<npl_vlan_pe_fi_core_tcam_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid = m.ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
        m.ethertype_or_tpid = m_ethertype_or_tpid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_pe_fi_core_tcam_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_pe_fi_core_tcam_table_key_t&);



template<>
class serializer_class<npl_vlan_pe_fi_core_tcam_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_pe_fi_core_tcam_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_pe_fi_core_tcam_table_value_t&);



template<>
class serializer_class<npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vlan_pe_fi_core_tcam_table_value_t::npl_vlan_pe_fi_core_tcam_table_payloads_t&);



template<>
class serializer_class<npl_vni_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vni_table_key_t& m) {
        uint64_t m_vni = m.vni;
            archive(::cereal::make_nvp("vni", m_vni));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vni_table_key_t& m) {
        uint64_t m_vni;
            archive(::cereal::make_nvp("vni", m_vni));
        m.vni = m_vni;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vni_table_key_t& m)
{
    serializer_class<npl_vni_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vni_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vni_table_key_t& m)
{
    serializer_class<npl_vni_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vni_table_key_t&);



template<>
class serializer_class<npl_vni_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vni_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vni_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vni_table_value_t& m)
{
    serializer_class<npl_vni_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vni_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vni_table_value_t& m)
{
    serializer_class<npl_vni_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vni_table_value_t&);



template<>
class serializer_class<npl_vni_table_value_t::npl_vni_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vni_table_value_t::npl_vni_table_payloads_t& m) {
            archive(::cereal::make_nvp("vni_table_result", m.vni_table_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vni_table_value_t::npl_vni_table_payloads_t& m) {
            archive(::cereal::make_nvp("vni_table_result", m.vni_table_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vni_table_value_t::npl_vni_table_payloads_t& m)
{
    serializer_class<npl_vni_table_value_t::npl_vni_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vni_table_value_t::npl_vni_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vni_table_value_t::npl_vni_table_payloads_t& m)
{
    serializer_class<npl_vni_table_value_t::npl_vni_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vni_table_value_t::npl_vni_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t& m) {
        uint64_t m_buffer_pool_available_level = m.buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level = m.buffer_voq_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t& m) {
        uint64_t m_buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
        m.buffer_pool_available_level = m_buffer_pool_available_level;
        m.buffer_voq_size_level = m_buffer_voq_size_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_buffers_consumption_lut_for_deq_result", m.voq_cgm_slice_buffers_consumption_lut_for_deq_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_buffers_consumption_lut_for_deq_result", m.voq_cgm_slice_buffers_consumption_lut_for_deq_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_deq_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_buffer_pool_available_level = m.buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level = m.buffer_voq_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
        m.buffer_pool_available_level = m_buffer_pool_available_level;
        m.buffer_voq_size_level = m_buffer_voq_size_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_buffers_consumption_lut_for_enq_result", m.voq_cgm_slice_buffers_consumption_lut_for_enq_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_buffers_consumption_lut_for_enq_result", m.voq_cgm_slice_buffers_consumption_lut_for_enq_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_drop_green_probability_selector_table_key_t& m) {
        uint64_t m_packet_size_range = m.packet_size_range;
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_drop_green_probability_selector_table_key_t& m) {
        uint64_t m_packet_size_range;
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
        m.packet_size_range = m_packet_size_range;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_drop_green_probability_selector_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_drop_green_probability_selector_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_drop_green_probability_selector_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_drop_green_probability_selector_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_drop_green_probability_selector_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_drop_green_probability_selector_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_drop_green_probability_selector_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_drop_green_probability_selector_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_drop_green_probability_selector_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_drop_green_probability_selector_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_drop_color_probability_selector_results", m.voq_cgm_slice_drop_color_probability_selector_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_drop_color_probability_selector_results", m.voq_cgm_slice_drop_color_probability_selector_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_drop_green_probability_selector_table_value_t::npl_voq_cgm_slice_drop_green_probability_selector_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t& m) {
        uint64_t m_packet_size_range = m.packet_size_range;
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t& m) {
        uint64_t m_packet_size_range;
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
        m.packet_size_range = m_packet_size_range;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_drop_yellow_probability_selector_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_drop_color_probability_selector_results", m.voq_cgm_slice_drop_color_probability_selector_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_drop_color_probability_selector_results", m.voq_cgm_slice_drop_color_probability_selector_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_drop_yellow_probability_selector_table_value_t::npl_voq_cgm_slice_drop_yellow_probability_selector_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_all_evicted_voq_buff_consump_level = m.all_evicted_voq_buff_consump_level;
        uint64_t m_evicted_profile_id = m.evicted_profile_id;
        uint64_t m_buffer_pool_available_level = m.buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level = m.buffer_voq_size_level;
            archive(::cereal::make_nvp("all_evicted_voq_buff_consump_level", m_all_evicted_voq_buff_consump_level));
            archive(::cereal::make_nvp("evicted_profile_id", m_evicted_profile_id));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_all_evicted_voq_buff_consump_level;
        uint64_t m_evicted_profile_id;
        uint64_t m_buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level;
            archive(::cereal::make_nvp("all_evicted_voq_buff_consump_level", m_all_evicted_voq_buff_consump_level));
            archive(::cereal::make_nvp("evicted_profile_id", m_evicted_profile_id));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
        m.all_evicted_voq_buff_consump_level = m_all_evicted_voq_buff_consump_level;
        m.evicted_profile_id = m_evicted_profile_id;
        m.buffer_pool_available_level = m_buffer_pool_available_level;
        m.buffer_voq_size_level = m_buffer_voq_size_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results", m.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results", m.voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_evicted_buffers_consumption_lut_for_enq_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t& m) {
        uint64_t m_all_evicted_voq_buff_consump_level = m.all_evicted_voq_buff_consump_level;
        uint64_t m_free_dram_cntx = m.free_dram_cntx;
            archive(::cereal::make_nvp("all_evicted_voq_buff_consump_level", m_all_evicted_voq_buff_consump_level));
            archive(::cereal::make_nvp("free_dram_cntx", m_free_dram_cntx));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t& m) {
        uint64_t m_all_evicted_voq_buff_consump_level;
        uint64_t m_free_dram_cntx;
            archive(::cereal::make_nvp("all_evicted_voq_buff_consump_level", m_all_evicted_voq_buff_consump_level));
            archive(::cereal::make_nvp("free_dram_cntx", m_free_dram_cntx));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
        m.all_evicted_voq_buff_consump_level = m_all_evicted_voq_buff_consump_level;
        m.free_dram_cntx = m_free_dram_cntx;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_eviction_ok_lut_for_enq_table_results", m.voq_cgm_slice_eviction_ok_lut_for_enq_table_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_eviction_ok_lut_for_enq_table_results", m.voq_cgm_slice_eviction_ok_lut_for_enq_table_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_value_t::npl_voq_cgm_slice_eviction_ok_lut_for_enq_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_mark_probability_selector_table_key_t& m) {
        uint64_t m_packet_size_range = m.packet_size_range;
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_mark_probability_selector_table_key_t& m) {
        uint64_t m_packet_size_range;
            archive(::cereal::make_nvp("packet_size_range", m_packet_size_range));
            archive(::cereal::make_nvp("profile_id", m.profile_id));
        m.packet_size_range = m_packet_size_range;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_mark_probability_selector_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_mark_probability_selector_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_mark_probability_selector_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_mark_probability_selector_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_mark_probability_selector_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_mark_probability_selector_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_mark_probability_selector_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_mark_probability_selector_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_mark_probability_selector_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_mark_probability_selector_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_mark_color_probability_selector_results", m.voq_cgm_slice_mark_color_probability_selector_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_mark_color_probability_selector_results", m.voq_cgm_slice_mark_color_probability_selector_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_mark_probability_selector_table_value_t::npl_voq_cgm_slice_mark_probability_selector_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t& m) {
        uint64_t m_pd_pool_available_level = m.pd_pool_available_level;
        uint64_t m_pd_voq_fill_level = m.pd_voq_fill_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("pd_pool_available_level", m_pd_pool_available_level));
            archive(::cereal::make_nvp("pd_voq_fill_level", m_pd_voq_fill_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t& m) {
        uint64_t m_pd_pool_available_level;
        uint64_t m_pd_voq_fill_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("pd_pool_available_level", m_pd_pool_available_level));
            archive(::cereal::make_nvp("pd_voq_fill_level", m_pd_voq_fill_level));
        m.pd_pool_available_level = m_pd_pool_available_level;
        m.pd_voq_fill_level = m_pd_voq_fill_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_pd_consumption_lut_for_deq_result", m.voq_cgm_slice_pd_consumption_lut_for_deq_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_pd_consumption_lut_for_deq_result", m.voq_cgm_slice_pd_consumption_lut_for_deq_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_deq_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_pd_pool_available_level = m.pd_pool_available_level;
        uint64_t m_pd_voq_fill_level = m.pd_voq_fill_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("pd_pool_available_level", m_pd_pool_available_level));
            archive(::cereal::make_nvp("pd_voq_fill_level", m_pd_voq_fill_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_pd_pool_available_level;
        uint64_t m_pd_voq_fill_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("pd_pool_available_level", m_pd_pool_available_level));
            archive(::cereal::make_nvp("pd_voq_fill_level", m_pd_voq_fill_level));
        m.pd_pool_available_level = m_pd_pool_available_level;
        m.pd_voq_fill_level = m_pd_voq_fill_level;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_pd_consumption_lut_for_enq_result", m.voq_cgm_slice_pd_consumption_lut_for_enq_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_pd_consumption_lut_for_enq_result", m.voq_cgm_slice_pd_consumption_lut_for_enq_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_value_t::npl_voq_cgm_slice_pd_consumption_lut_for_enq_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_buff_region_thresholds_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_profile_buff_region_thresholds_results", m.voq_cgm_slice_profile_buff_region_thresholds_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_profile_buff_region_thresholds_results", m.voq_cgm_slice_profile_buff_region_thresholds_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_buff_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_buff_region_thresholds_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results", m.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results", m.voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_region_thresholds_results", m.voq_cgm_slice_profile_pkt_region_thresholds_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_profile_pkt_region_thresholds_results", m.voq_cgm_slice_profile_pkt_region_thresholds_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_profile_pkt_region_thresholds_table_value_t::npl_voq_cgm_slice_profile_pkt_region_thresholds_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_slice_cgm_profile_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_slice_cgm_profile_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_slice_cgm_profile_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_slice_cgm_profile_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_slice_cgm_profile_result", m.voq_cgm_slice_slice_cgm_profile_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_slice_cgm_profile_result", m.voq_cgm_slice_slice_cgm_profile_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_slice_cgm_profile_table_value_t::npl_voq_cgm_slice_slice_cgm_profile_table_payloads_t&);



template<>
class serializer_class<npl_voq_cgm_wred_probability_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_wred_probability_table_key_t& m) {
        uint64_t m_region_id = m.region_id;
            archive(::cereal::make_nvp("region_id", m_region_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_wred_probability_table_key_t& m) {
        uint64_t m_region_id;
            archive(::cereal::make_nvp("region_id", m_region_id));
        m.region_id = m_region_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_wred_probability_table_key_t& m)
{
    serializer_class<npl_voq_cgm_wred_probability_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_wred_probability_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_wred_probability_table_key_t& m)
{
    serializer_class<npl_voq_cgm_wred_probability_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_wred_probability_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_wred_probability_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_wred_probability_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_wred_probability_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_wred_probability_table_value_t& m)
{
    serializer_class<npl_voq_cgm_wred_probability_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_wred_probability_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_wred_probability_table_value_t& m)
{
    serializer_class<npl_voq_cgm_wred_probability_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_wred_probability_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_wred_probability_results", m.voq_cgm_wred_probability_results));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_wred_probability_results", m.voq_cgm_wred_probability_results));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_wred_probability_table_value_t::npl_voq_cgm_wred_probability_table_payloads_t&);



template<>
class serializer_class<npl_vsid_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vsid_table_key_t& m) {
        uint64_t m_vsid = m.vsid;
            archive(::cereal::make_nvp("vsid", m_vsid));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vsid_table_key_t& m) {
        uint64_t m_vsid;
            archive(::cereal::make_nvp("vsid", m_vsid));
        m.vsid = m_vsid;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vsid_table_key_t& m)
{
    serializer_class<npl_vsid_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vsid_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vsid_table_key_t& m)
{
    serializer_class<npl_vsid_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vsid_table_key_t&);



template<>
class serializer_class<npl_vsid_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vsid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vsid_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vsid_table_value_t& m)
{
    serializer_class<npl_vsid_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vsid_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vsid_table_value_t& m)
{
    serializer_class<npl_vsid_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vsid_table_value_t&);



template<>
class serializer_class<npl_vsid_table_value_t::npl_vsid_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vsid_table_value_t::npl_vsid_table_payloads_t& m) {
        uint64_t m_l2_relay_attributes_id = m.l2_relay_attributes_id;
            archive(::cereal::make_nvp("l2_relay_attributes_id", m_l2_relay_attributes_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vsid_table_value_t::npl_vsid_table_payloads_t& m) {
        uint64_t m_l2_relay_attributes_id;
            archive(::cereal::make_nvp("l2_relay_attributes_id", m_l2_relay_attributes_id));
        m.l2_relay_attributes_id = m_l2_relay_attributes_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vsid_table_value_t::npl_vsid_table_payloads_t& m)
{
    serializer_class<npl_vsid_table_value_t::npl_vsid_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vsid_table_value_t::npl_vsid_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vsid_table_value_t::npl_vsid_table_payloads_t& m)
{
    serializer_class<npl_vsid_table_value_t::npl_vsid_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vsid_table_value_t::npl_vsid_table_payloads_t&);



template<>
class serializer_class<npl_vxlan_l2_dlp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vxlan_l2_dlp_table_key_t& m) {
        uint64_t m_l2_dlp_id_key_id = m.l2_dlp_id_key_id;
            archive(::cereal::make_nvp("l2_dlp_id_key_id", m_l2_dlp_id_key_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vxlan_l2_dlp_table_key_t& m) {
        uint64_t m_l2_dlp_id_key_id;
            archive(::cereal::make_nvp("l2_dlp_id_key_id", m_l2_dlp_id_key_id));
        m.l2_dlp_id_key_id = m_l2_dlp_id_key_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vxlan_l2_dlp_table_key_t& m)
{
    serializer_class<npl_vxlan_l2_dlp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vxlan_l2_dlp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_vxlan_l2_dlp_table_key_t& m)
{
    serializer_class<npl_vxlan_l2_dlp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vxlan_l2_dlp_table_key_t&);



template<>
class serializer_class<npl_vxlan_l2_dlp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vxlan_l2_dlp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vxlan_l2_dlp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vxlan_l2_dlp_table_value_t& m)
{
    serializer_class<npl_vxlan_l2_dlp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vxlan_l2_dlp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_vxlan_l2_dlp_table_value_t& m)
{
    serializer_class<npl_vxlan_l2_dlp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vxlan_l2_dlp_table_value_t&);



template<>
class serializer_class<npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t& m) {
            archive(::cereal::make_nvp("vxlan_tunnel_attributes", m.vxlan_tunnel_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t& m) {
            archive(::cereal::make_nvp("vxlan_tunnel_attributes", m.vxlan_tunnel_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t& m)
{
    serializer_class<npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t& m)
{
    serializer_class<npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_vxlan_l2_dlp_table_value_t::npl_vxlan_l2_dlp_table_payloads_t&);



template<>
class serializer_class<silicon_one::nplapi_tables_static_init> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const silicon_one::nplapi_tables_static_init& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, silicon_one::nplapi_tables_static_init& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const silicon_one::nplapi_tables_static_init& m)
{
    serializer_class<silicon_one::nplapi_tables_static_init>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const silicon_one::nplapi_tables_static_init&);

template <class Archive>
void
load(Archive& archive, silicon_one::nplapi_tables_static_init& m)
{
    serializer_class<silicon_one::nplapi_tables_static_init>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, silicon_one::nplapi_tables_static_init&);



template<>
class serializer_class<field_structure> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const field_structure& m) {
            archive(::cereal::make_nvp("field_type", m.field_type));
            archive(::cereal::make_nvp("flat_value", m.flat_value));
            archive(::cereal::make_nvp("subfields", m.subfields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, field_structure& m) {
            archive(::cereal::make_nvp("field_type", m.field_type));
            archive(::cereal::make_nvp("flat_value", m.flat_value));
            archive(::cereal::make_nvp("subfields", m.subfields));
    }
};
template <class Archive>
void
save(Archive& archive, const field_structure& m)
{
    serializer_class<field_structure>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const field_structure&);

template <class Archive>
void
load(Archive& archive, field_structure& m)
{
    serializer_class<field_structure>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, field_structure&);



template<>
class serializer_class<npl_additional_mpls_labels_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_additional_mpls_labels_offset_t& m) {
            archive(::cereal::make_nvp("ene_three_labels_jump_offset", m.ene_three_labels_jump_offset));
            archive(::cereal::make_nvp("ene_four_labels_jump_offset", m.ene_four_labels_jump_offset));
            archive(::cereal::make_nvp("ene_five_labels_jump_offset", m.ene_five_labels_jump_offset));
            archive(::cereal::make_nvp("ene_six_labels_jump_offset", m.ene_six_labels_jump_offset));
            archive(::cereal::make_nvp("ene_seven_labels_jump_offset", m.ene_seven_labels_jump_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_additional_mpls_labels_offset_t& m) {
            archive(::cereal::make_nvp("ene_three_labels_jump_offset", m.ene_three_labels_jump_offset));
            archive(::cereal::make_nvp("ene_four_labels_jump_offset", m.ene_four_labels_jump_offset));
            archive(::cereal::make_nvp("ene_five_labels_jump_offset", m.ene_five_labels_jump_offset));
            archive(::cereal::make_nvp("ene_six_labels_jump_offset", m.ene_six_labels_jump_offset));
            archive(::cereal::make_nvp("ene_seven_labels_jump_offset", m.ene_seven_labels_jump_offset));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_additional_mpls_labels_offset_t& m)
{
    serializer_class<npl_additional_mpls_labels_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_additional_mpls_labels_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_additional_mpls_labels_offset_t& m)
{
    serializer_class<npl_additional_mpls_labels_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_additional_mpls_labels_offset_t&);



template<>
class serializer_class<npl_all_reachable_vector_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_all_reachable_vector_result_t& m) {
            archive(::cereal::make_nvp("reachable", m.reachable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_all_reachable_vector_result_t& m) {
            archive(::cereal::make_nvp("reachable", m.reachable));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_all_reachable_vector_result_t& m)
{
    serializer_class<npl_all_reachable_vector_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_all_reachable_vector_result_t&);

template <class Archive>
void
load(Archive& archive, npl_all_reachable_vector_result_t& m)
{
    serializer_class<npl_all_reachable_vector_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_all_reachable_vector_result_t&);



template<>
class serializer_class<npl_app_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_app_traps_t& m) {
        uint64_t m_sgacl_drop = m.sgacl_drop;
        uint64_t m_sgacl_log = m.sgacl_log;
        uint64_t m_ip_inactivity = m.ip_inactivity;
            archive(::cereal::make_nvp("sgacl_drop", m_sgacl_drop));
            archive(::cereal::make_nvp("sgacl_log", m_sgacl_log));
            archive(::cereal::make_nvp("ip_inactivity", m_ip_inactivity));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_app_traps_t& m) {
        uint64_t m_sgacl_drop;
        uint64_t m_sgacl_log;
        uint64_t m_ip_inactivity;
            archive(::cereal::make_nvp("sgacl_drop", m_sgacl_drop));
            archive(::cereal::make_nvp("sgacl_log", m_sgacl_log));
            archive(::cereal::make_nvp("ip_inactivity", m_ip_inactivity));
        m.sgacl_drop = m_sgacl_drop;
        m.sgacl_log = m_sgacl_log;
        m.ip_inactivity = m_ip_inactivity;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_app_traps_t& m)
{
    serializer_class<npl_app_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_app_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_app_traps_t& m)
{
    serializer_class<npl_app_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_app_traps_t&);



template<>
class serializer_class<npl_aux_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_aux_table_key_t& m) {
        uint64_t m_rd_address = m.rd_address;
            archive(::cereal::make_nvp("rd_address", m_rd_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_aux_table_key_t& m) {
        uint64_t m_rd_address;
            archive(::cereal::make_nvp("rd_address", m_rd_address));
        m.rd_address = m_rd_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_aux_table_key_t& m)
{
    serializer_class<npl_aux_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_aux_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_aux_table_key_t& m)
{
    serializer_class<npl_aux_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_aux_table_key_t&);



template<>
class serializer_class<npl_aux_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_aux_table_result_t& m) {
        uint64_t m_packet_header_type = m.packet_header_type;
        uint64_t m_count_phase = m.count_phase;
            archive(::cereal::make_nvp("packet_header_type", m_packet_header_type));
            archive(::cereal::make_nvp("count_phase", m_count_phase));
            archive(::cereal::make_nvp("aux_data", m.aux_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_aux_table_result_t& m) {
        uint64_t m_packet_header_type;
        uint64_t m_count_phase;
            archive(::cereal::make_nvp("packet_header_type", m_packet_header_type));
            archive(::cereal::make_nvp("count_phase", m_count_phase));
            archive(::cereal::make_nvp("aux_data", m.aux_data));
        m.packet_header_type = m_packet_header_type;
        m.count_phase = m_count_phase;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_aux_table_result_t& m)
{
    serializer_class<npl_aux_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_aux_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_aux_table_result_t& m)
{
    serializer_class<npl_aux_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_aux_table_result_t&);



template<>
class serializer_class<npl_base_voq_nr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_base_voq_nr_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_base_voq_nr_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_base_voq_nr_t& m)
{
    serializer_class<npl_base_voq_nr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_base_voq_nr_t&);

template <class Archive>
void
load(Archive& archive, npl_base_voq_nr_t& m)
{
    serializer_class<npl_base_voq_nr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_base_voq_nr_t&);



template<>
class serializer_class<npl_bd_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bd_attributes_t& m) {
        uint64_t m_sgacl_enforcement = m.sgacl_enforcement;
        uint64_t m_l2_lpts_attributes = m.l2_lpts_attributes;
        uint64_t m_flush_all_macs = m.flush_all_macs;
            archive(::cereal::make_nvp("sgacl_enforcement", m_sgacl_enforcement));
            archive(::cereal::make_nvp("l2_lpts_attributes", m_l2_lpts_attributes));
            archive(::cereal::make_nvp("flush_all_macs", m_flush_all_macs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bd_attributes_t& m) {
        uint64_t m_sgacl_enforcement;
        uint64_t m_l2_lpts_attributes;
        uint64_t m_flush_all_macs;
            archive(::cereal::make_nvp("sgacl_enforcement", m_sgacl_enforcement));
            archive(::cereal::make_nvp("l2_lpts_attributes", m_l2_lpts_attributes));
            archive(::cereal::make_nvp("flush_all_macs", m_flush_all_macs));
        m.sgacl_enforcement = m_sgacl_enforcement;
        m.l2_lpts_attributes = m_l2_lpts_attributes;
        m.flush_all_macs = m_flush_all_macs;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bd_attributes_t& m)
{
    serializer_class<npl_bd_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bd_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_bd_attributes_t& m)
{
    serializer_class<npl_bd_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bd_attributes_t&);



template<>
class serializer_class<npl_bfd_aux_ipv4_trans_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_aux_ipv4_trans_payload_t& m) {
        uint64_t m_sip = m.sip;
            archive(::cereal::make_nvp("sip", m_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_aux_ipv4_trans_payload_t& m) {
        uint64_t m_sip;
            archive(::cereal::make_nvp("sip", m_sip));
        m.sip = m_sip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_aux_ipv4_trans_payload_t& m)
{
    serializer_class<npl_bfd_aux_ipv4_trans_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_aux_ipv4_trans_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_aux_ipv4_trans_payload_t& m)
{
    serializer_class<npl_bfd_aux_ipv4_trans_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_aux_ipv4_trans_payload_t&);



template<>
class serializer_class<npl_bfd_aux_ipv6_trans_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_aux_ipv6_trans_payload_t& m) {
        uint64_t m_ipv6_dip_b = m.ipv6_dip_b;
            archive(::cereal::make_nvp("ipv6_dip_b", m_ipv6_dip_b));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_aux_ipv6_trans_payload_t& m) {
        uint64_t m_ipv6_dip_b;
            archive(::cereal::make_nvp("ipv6_dip_b", m_ipv6_dip_b));
        m.ipv6_dip_b = m_ipv6_dip_b;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_aux_ipv6_trans_payload_t& m)
{
    serializer_class<npl_bfd_aux_ipv6_trans_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_aux_ipv6_trans_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_aux_ipv6_trans_payload_t& m)
{
    serializer_class<npl_bfd_aux_ipv6_trans_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_aux_ipv6_trans_payload_t&);



template<>
class serializer_class<npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t& m) {
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t& m) {
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t& m)
{
    serializer_class<npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t& m)
{
    serializer_class<npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_aux_transmit_payload_t_anonymous_union_prot_trans_t&);



template<>
class serializer_class<npl_bfd_em_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_em_t& m) {
        uint64_t m_rmep_id = m.rmep_id;
        uint64_t m_mep_id = m.mep_id;
        uint64_t m_access_rmep = m.access_rmep;
        uint64_t m_mp_data_select = m.mp_data_select;
        uint64_t m_access_mp = m.access_mp;
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("mep_id", m_mep_id));
            archive(::cereal::make_nvp("access_rmep", m_access_rmep));
            archive(::cereal::make_nvp("mp_data_select", m_mp_data_select));
            archive(::cereal::make_nvp("access_mp", m_access_mp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_em_t& m) {
        uint64_t m_rmep_id;
        uint64_t m_mep_id;
        uint64_t m_access_rmep;
        uint64_t m_mp_data_select;
        uint64_t m_access_mp;
            archive(::cereal::make_nvp("rmep_id", m_rmep_id));
            archive(::cereal::make_nvp("mep_id", m_mep_id));
            archive(::cereal::make_nvp("access_rmep", m_access_rmep));
            archive(::cereal::make_nvp("mp_data_select", m_mp_data_select));
            archive(::cereal::make_nvp("access_mp", m_access_mp));
        m.rmep_id = m_rmep_id;
        m.mep_id = m_mep_id;
        m.access_rmep = m_access_rmep;
        m.mp_data_select = m_mp_data_select;
        m.access_mp = m_access_mp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_em_t& m)
{
    serializer_class<npl_bfd_em_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_em_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_em_t& m)
{
    serializer_class<npl_bfd_em_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_em_t&);



template<>
class serializer_class<npl_bfd_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_flags_t& m) {
        uint64_t m_poll = m.poll;
        uint64_t m_final = m.final;
        uint64_t m_ctrl_plane_independent = m.ctrl_plane_independent;
        uint64_t m_auth_present = m.auth_present;
        uint64_t m_demand = m.demand;
        uint64_t m_multipoint = m.multipoint;
            archive(::cereal::make_nvp("poll", m_poll));
            archive(::cereal::make_nvp("final", m_final));
            archive(::cereal::make_nvp("ctrl_plane_independent", m_ctrl_plane_independent));
            archive(::cereal::make_nvp("auth_present", m_auth_present));
            archive(::cereal::make_nvp("demand", m_demand));
            archive(::cereal::make_nvp("multipoint", m_multipoint));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_flags_t& m) {
        uint64_t m_poll;
        uint64_t m_final;
        uint64_t m_ctrl_plane_independent;
        uint64_t m_auth_present;
        uint64_t m_demand;
        uint64_t m_multipoint;
            archive(::cereal::make_nvp("poll", m_poll));
            archive(::cereal::make_nvp("final", m_final));
            archive(::cereal::make_nvp("ctrl_plane_independent", m_ctrl_plane_independent));
            archive(::cereal::make_nvp("auth_present", m_auth_present));
            archive(::cereal::make_nvp("demand", m_demand));
            archive(::cereal::make_nvp("multipoint", m_multipoint));
        m.poll = m_poll;
        m.final = m_final;
        m.ctrl_plane_independent = m_ctrl_plane_independent;
        m.auth_present = m_auth_present;
        m.demand = m_demand;
        m.multipoint = m_multipoint;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_flags_t& m)
{
    serializer_class<npl_bfd_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_flags_t& m)
{
    serializer_class<npl_bfd_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_flags_t&);



template<>
class serializer_class<npl_bfd_inject_ttl_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_inject_ttl_t& m) {
        uint64_t m_ttl = m.ttl;
            archive(::cereal::make_nvp("ttl", m_ttl));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_inject_ttl_t& m) {
        uint64_t m_ttl;
            archive(::cereal::make_nvp("ttl", m_ttl));
        m.ttl = m_ttl;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_inject_ttl_t& m)
{
    serializer_class<npl_bfd_inject_ttl_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_inject_ttl_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_inject_ttl_t& m)
{
    serializer_class<npl_bfd_inject_ttl_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_inject_ttl_t&);



template<>
class serializer_class<npl_bfd_ipv4_prot_shared_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv4_prot_shared_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv4_prot_shared_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv4_prot_shared_t& m)
{
    serializer_class<npl_bfd_ipv4_prot_shared_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv4_prot_shared_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv4_prot_shared_t& m)
{
    serializer_class<npl_bfd_ipv4_prot_shared_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv4_prot_shared_t&);



template<>
class serializer_class<npl_bfd_ipv6_prot_shared_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_prot_shared_t& m) {
        uint64_t m_ipv6_dip_c = m.ipv6_dip_c;
            archive(::cereal::make_nvp("ipv6_dip_c", m_ipv6_dip_c));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_prot_shared_t& m) {
        uint64_t m_ipv6_dip_c;
            archive(::cereal::make_nvp("ipv6_dip_c", m_ipv6_dip_c));
        m.ipv6_dip_c = m_ipv6_dip_c;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_prot_shared_t& m)
{
    serializer_class<npl_bfd_ipv6_prot_shared_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_prot_shared_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_prot_shared_t& m)
{
    serializer_class<npl_bfd_ipv6_prot_shared_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_prot_shared_t&);



template<>
class serializer_class<npl_bfd_ipv6_selector_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_ipv6_selector_t& m) {
        uint64_t m_data = m.data;
            archive(::cereal::make_nvp("data", m_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_ipv6_selector_t& m) {
        uint64_t m_data;
            archive(::cereal::make_nvp("data", m_data));
        m.data = m_data;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_ipv6_selector_t& m)
{
    serializer_class<npl_bfd_ipv6_selector_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_ipv6_selector_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_ipv6_selector_t& m)
{
    serializer_class<npl_bfd_ipv6_selector_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_ipv6_selector_t&);



template<>
class serializer_class<npl_bfd_local_ipv6_sip_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_local_ipv6_sip_t& m) {
        uint64_t m_sip = m.sip;
            archive(::cereal::make_nvp("sip", m_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_local_ipv6_sip_t& m) {
        uint64_t m_sip;
            archive(::cereal::make_nvp("sip", m_sip));
        m.sip = m_sip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_local_ipv6_sip_t& m)
{
    serializer_class<npl_bfd_local_ipv6_sip_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_local_ipv6_sip_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_local_ipv6_sip_t& m)
{
    serializer_class<npl_bfd_local_ipv6_sip_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_local_ipv6_sip_t&);



template<>
class serializer_class<npl_bfd_mp_ipv4_transport_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_ipv4_transport_t& m) {
        uint64_t m_dip = m.dip;
        uint64_t m_checksum = m.checksum;
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("checksum", m_checksum));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_ipv4_transport_t& m) {
        uint64_t m_dip;
        uint64_t m_checksum;
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("checksum", m_checksum));
        m.dip = m_dip;
        m.checksum = m_checksum;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_ipv4_transport_t& m)
{
    serializer_class<npl_bfd_mp_ipv4_transport_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_ipv4_transport_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_ipv4_transport_t& m)
{
    serializer_class<npl_bfd_mp_ipv4_transport_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_ipv4_transport_t&);



template<>
class serializer_class<npl_bfd_mp_ipv6_transport_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_ipv6_transport_t& m) {
        uint64_t m_ipv6_dip_a = m.ipv6_dip_a;
            archive(::cereal::make_nvp("ipv6_dip_a", m_ipv6_dip_a));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_ipv6_transport_t& m) {
        uint64_t m_ipv6_dip_a;
            archive(::cereal::make_nvp("ipv6_dip_a", m_ipv6_dip_a));
        m.ipv6_dip_a = m_ipv6_dip_a;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_ipv6_transport_t& m)
{
    serializer_class<npl_bfd_mp_ipv6_transport_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_ipv6_transport_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_ipv6_transport_t& m)
{
    serializer_class<npl_bfd_mp_ipv6_transport_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_ipv6_transport_t&);



template<>
class serializer_class<npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t& m) {
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t& m) {
            archive(::cereal::make_nvp("ipv4", m.ipv4));
            archive(::cereal::make_nvp("ipv6", m.ipv6));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t& m)
{
    serializer_class<npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_shared_msb_t_anonymous_union_trans_data_t&);



template<>
class serializer_class<npl_bfd_mp_table_transmit_b_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_mp_table_transmit_b_payload_t& m) {
        uint64_t m_local_state_and_flags = m.local_state_and_flags;
        uint64_t m_sip_selector = m.sip_selector;
            archive(::cereal::make_nvp("local_state_and_flags", m_local_state_and_flags));
            archive(::cereal::make_nvp("sip_selector", m_sip_selector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_mp_table_transmit_b_payload_t& m) {
        uint64_t m_local_state_and_flags;
        uint64_t m_sip_selector;
            archive(::cereal::make_nvp("local_state_and_flags", m_local_state_and_flags));
            archive(::cereal::make_nvp("sip_selector", m_sip_selector));
        m.local_state_and_flags = m_local_state_and_flags;
        m.sip_selector = m_sip_selector;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_mp_table_transmit_b_payload_t& m)
{
    serializer_class<npl_bfd_mp_table_transmit_b_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_mp_table_transmit_b_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_mp_table_transmit_b_payload_t& m)
{
    serializer_class<npl_bfd_mp_table_transmit_b_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_mp_table_transmit_b_payload_t&);



template<>
class serializer_class<npl_bfd_transport_and_label_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bfd_transport_and_label_t& m) {
        uint64_t m_requires_label = m.requires_label;
            archive(::cereal::make_nvp("transport", m.transport));
            archive(::cereal::make_nvp("requires_label", m_requires_label));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bfd_transport_and_label_t& m) {
        uint64_t m_requires_label;
            archive(::cereal::make_nvp("transport", m.transport));
            archive(::cereal::make_nvp("requires_label", m_requires_label));
        m.requires_label = m_requires_label;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bfd_transport_and_label_t& m)
{
    serializer_class<npl_bfd_transport_and_label_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bfd_transport_and_label_t&);

template <class Archive>
void
load(Archive& archive, npl_bfd_transport_and_label_t& m)
{
    serializer_class<npl_bfd_transport_and_label_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bfd_transport_and_label_t&);



template<>
class serializer_class<npl_bool_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bool_t& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bool_t& m) {
            archive(::cereal::make_nvp("val", m.val));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bool_t& m)
{
    serializer_class<npl_bool_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bool_t&);

template <class Archive>
void
load(Archive& archive, npl_bool_t& m)
{
    serializer_class<npl_bool_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bool_t&);



template<>
class serializer_class<npl_burst_size_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_burst_size_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_burst_size_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_burst_size_len_t& m)
{
    serializer_class<npl_burst_size_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_burst_size_len_t&);

template <class Archive>
void
load(Archive& archive, npl_burst_size_len_t& m)
{
    serializer_class<npl_burst_size_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_burst_size_len_t&);



template<>
class serializer_class<npl_bvn_profile_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_bvn_profile_t& m) {
        uint64_t m_lp_over_lag = m.lp_over_lag;
        uint64_t m_tc_map_profile = m.tc_map_profile;
            archive(::cereal::make_nvp("lp_over_lag", m_lp_over_lag));
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bvn_profile_t& m) {
        uint64_t m_lp_over_lag;
        uint64_t m_tc_map_profile;
            archive(::cereal::make_nvp("lp_over_lag", m_lp_over_lag));
            archive(::cereal::make_nvp("tc_map_profile", m_tc_map_profile));
        m.lp_over_lag = m_lp_over_lag;
        m.tc_map_profile = m_tc_map_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_bvn_profile_t& m)
{
    serializer_class<npl_bvn_profile_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_bvn_profile_t&);

template <class Archive>
void
load(Archive& archive, npl_bvn_profile_t& m)
{
    serializer_class<npl_bvn_profile_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_bvn_profile_t&);



template<>
class serializer_class<npl_calc_checksum_enable_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_calc_checksum_enable_t& m) {
        uint64_t m_enable = m.enable;
            archive(::cereal::make_nvp("enable", m_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_calc_checksum_enable_t& m) {
        uint64_t m_enable;
            archive(::cereal::make_nvp("enable", m_enable));
        m.enable = m_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_calc_checksum_enable_t& m)
{
    serializer_class<npl_calc_checksum_enable_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_calc_checksum_enable_t&);

template <class Archive>
void
load(Archive& archive, npl_calc_checksum_enable_t& m)
{
    serializer_class<npl_calc_checksum_enable_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_calc_checksum_enable_t&);



template<>
class serializer_class<npl_color_aware_mode_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_color_aware_mode_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_color_aware_mode_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_color_aware_mode_len_t& m)
{
    serializer_class<npl_color_aware_mode_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_color_aware_mode_len_t&);

template <class Archive>
void
load(Archive& archive, npl_color_aware_mode_len_t& m)
{
    serializer_class<npl_color_aware_mode_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_color_aware_mode_len_t&);



template<>
class serializer_class<npl_color_len_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_color_len_t& m) {
        uint64_t m_value = m.value;
            archive(::cereal::make_nvp("value", m_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_color_len_t& m) {
        uint64_t m_value;
            archive(::cereal::make_nvp("value", m_value));
        m.value = m_value;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_color_len_t& m)
{
    serializer_class<npl_color_len_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_color_len_t&);

template <class Archive>
void
load(Archive& archive, npl_color_len_t& m)
{
    serializer_class<npl_color_len_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_color_len_t&);



}

