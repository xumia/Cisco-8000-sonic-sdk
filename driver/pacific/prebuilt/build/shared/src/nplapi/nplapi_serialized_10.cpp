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

template <class Archive> void save(Archive&, const npl_dlp_profile_union_t&);
template <class Archive> void load(Archive&, npl_dlp_profile_union_t&);

template <class Archive> void save(Archive&, const npl_egress_qos_result_t&);
template <class Archive> void load(Archive&, npl_egress_qos_result_t&);

template <class Archive> void save(Archive&, const npl_ibm_enables_table_result_t&);
template <class Archive> void load(Archive&, npl_ibm_enables_table_result_t&);

template <class Archive> void save(Archive&, const npl_rxpdr_ibm_tc_map_result_t&);
template <class Archive> void load(Archive&, npl_rxpdr_ibm_tc_map_result_t&);

template <class Archive> void save(Archive&, const npl_tx_redirect_code_table_tx_redirect_action_payload_t&);
template <class Archive> void load(Archive&, npl_tx_redirect_code_table_tx_redirect_action_payload_t&);

template <class Archive> void save(Archive&, const npl_txpp_first_macro_table_key_t&);
template <class Archive> void load(Archive&, npl_txpp_first_macro_table_key_t&);

template <class Archive> void save(Archive&, const npl_vni_table_result_t&);
template <class Archive> void load(Archive&, npl_vni_table_result_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_dram_cgm_profile_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_dram_cgm_profile_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_buff_region_thresholds_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_buff_region_thresholds_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_enq_time_region_thresholds_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_profile_pkt_region_thresholds_results_t&);

template <class Archive> void save(Archive&, const npl_voq_cgm_slice_slice_cgm_profile_result_t&);
template <class Archive> void load(Archive&, npl_voq_cgm_slice_slice_cgm_profile_result_t&);

template <class Archive> void save(Archive&, const npl_voq_profile_len&);
template <class Archive> void load(Archive&, npl_voq_profile_len&);

template <class Archive> void save(Archive&, const npl_vxlan_dlp_specific_t&);
template <class Archive> void load(Archive&, npl_vxlan_dlp_specific_t&);

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
class serializer_class<npl_txpp_dlp_profile_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_dlp_profile_table_key_t& m) {
        uint64_t m_txpp_dlp_profile_info_dlp_msbs_13_12 = m.txpp_dlp_profile_info_dlp_msbs_13_12;
        uint64_t m_txpp_dlp_profile_info_dlp_msbs_11_0 = m.txpp_dlp_profile_info_dlp_msbs_11_0;
            archive(::cereal::make_nvp("txpp_dlp_profile_info_dlp_msbs_13_12", m_txpp_dlp_profile_info_dlp_msbs_13_12));
            archive(::cereal::make_nvp("txpp_dlp_profile_info_dlp_msbs_11_0", m_txpp_dlp_profile_info_dlp_msbs_11_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_dlp_profile_table_key_t& m) {
        uint64_t m_txpp_dlp_profile_info_dlp_msbs_13_12;
        uint64_t m_txpp_dlp_profile_info_dlp_msbs_11_0;
            archive(::cereal::make_nvp("txpp_dlp_profile_info_dlp_msbs_13_12", m_txpp_dlp_profile_info_dlp_msbs_13_12));
            archive(::cereal::make_nvp("txpp_dlp_profile_info_dlp_msbs_11_0", m_txpp_dlp_profile_info_dlp_msbs_11_0));
        m.txpp_dlp_profile_info_dlp_msbs_13_12 = m_txpp_dlp_profile_info_dlp_msbs_13_12;
        m.txpp_dlp_profile_info_dlp_msbs_11_0 = m_txpp_dlp_profile_info_dlp_msbs_11_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_dlp_profile_table_key_t& m)
{
    serializer_class<npl_txpp_dlp_profile_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_dlp_profile_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_dlp_profile_table_key_t& m)
{
    serializer_class<npl_txpp_dlp_profile_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_dlp_profile_table_key_t&);



template<>
class serializer_class<npl_txpp_dlp_profile_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_dlp_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_dlp_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_dlp_profile_table_value_t& m)
{
    serializer_class<npl_txpp_dlp_profile_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_dlp_profile_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_dlp_profile_table_value_t& m)
{
    serializer_class<npl_txpp_dlp_profile_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_dlp_profile_table_value_t&);



template<>
class serializer_class<npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("pd_tx_dlp_profile", m.pd_tx_dlp_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("pd_tx_dlp_profile", m.pd_tx_dlp_profile));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t& m)
{
    serializer_class<npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t& m)
{
    serializer_class<npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_dlp_profile_table_value_t::npl_txpp_dlp_profile_table_payloads_t&);



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
class serializer_class<npl_txpp_fwd_header_type_is_l2_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_fwd_header_type_is_l2_table_key_t& m) {
        uint64_t m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ = m.packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_fwd_header_type", m.packet_protocol_layer_0__tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_", m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_fwd_header_type_is_l2_table_key_t& m) {
        uint64_t m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_fwd_header_type", m.packet_protocol_layer_0__tx_npu_header_fwd_header_type));
            archive(::cereal::make_nvp("packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_", m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_));
        m.packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_ = m_packet_protocol_layer_0__tx_npu_header_encap_or_term_107_104_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_fwd_header_type_is_l2_table_key_t& m)
{
    serializer_class<npl_txpp_fwd_header_type_is_l2_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_fwd_header_type_is_l2_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_fwd_header_type_is_l2_table_key_t& m)
{
    serializer_class<npl_txpp_fwd_header_type_is_l2_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_fwd_header_type_is_l2_table_key_t&);



template<>
class serializer_class<npl_txpp_fwd_header_type_is_l2_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_fwd_header_type_is_l2_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_fwd_header_type_is_l2_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_fwd_header_type_is_l2_table_value_t& m)
{
    serializer_class<npl_txpp_fwd_header_type_is_l2_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_fwd_header_type_is_l2_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_fwd_header_type_is_l2_table_value_t& m)
{
    serializer_class<npl_txpp_fwd_header_type_is_l2_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_fwd_header_type_is_l2_table_value_t&);



template<>
class serializer_class<npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t& m) {
        uint64_t m_txpp_dlp_profile_info_fwd_header_type_is_l2 = m.txpp_dlp_profile_info_fwd_header_type_is_l2;
            archive(::cereal::make_nvp("txpp_dlp_profile_info_fwd_header_type_is_l2", m_txpp_dlp_profile_info_fwd_header_type_is_l2));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t& m) {
        uint64_t m_txpp_dlp_profile_info_fwd_header_type_is_l2;
            archive(::cereal::make_nvp("txpp_dlp_profile_info_fwd_header_type_is_l2", m_txpp_dlp_profile_info_fwd_header_type_is_l2));
        m.txpp_dlp_profile_info_fwd_header_type_is_l2 = m_txpp_dlp_profile_info_fwd_header_type_is_l2;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t& m)
{
    serializer_class<npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t& m)
{
    serializer_class<npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_txpp_fwd_header_type_is_l2_table_value_t::npl_txpp_fwd_header_type_is_l2_table_payloads_t&);



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
class serializer_class<npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_free_dram_cntx = m.free_dram_cntx;
        uint64_t m_buffer_pool_available_level = m.buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level = m.buffer_voq_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("free_dram_cntx", m_free_dram_cntx));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_buffers_consumption_lut_for_enq_table_key_t& m) {
        uint64_t m_free_dram_cntx;
        uint64_t m_buffer_pool_available_level;
        uint64_t m_buffer_voq_size_level;
            archive(::cereal::make_nvp("profile_id", m.profile_id));
            archive(::cereal::make_nvp("free_dram_cntx", m_free_dram_cntx));
            archive(::cereal::make_nvp("buffer_pool_available_level", m_buffer_pool_available_level));
            archive(::cereal::make_nvp("buffer_voq_size_level", m_buffer_voq_size_level));
        m.free_dram_cntx = m_free_dram_cntx;
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
class serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_table_key_t& m) {
            archive(::cereal::make_nvp("profile_id", m.profile_id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_dram_cgm_profile_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_table_key_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_dram_cgm_profile_table_key_t&);



template<>
class serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_dram_cgm_profile_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_table_value_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_dram_cgm_profile_table_value_t&);



template<>
class serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_dram_cgm_profile_result", m.voq_cgm_slice_dram_cgm_profile_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t& m) {
            archive(::cereal::make_nvp("voq_cgm_slice_dram_cgm_profile_result", m.voq_cgm_slice_dram_cgm_profile_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t& m)
{
    serializer_class<npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_voq_cgm_slice_dram_cgm_profile_table_value_t::npl_voq_cgm_slice_dram_cgm_profile_table_payloads_t&);



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
        uint64_t m_l2_lpts_attributes = m.l2_lpts_attributes;
        uint64_t m_flush_all_macs = m.flush_all_macs;
            archive(::cereal::make_nvp("l2_lpts_attributes", m_l2_lpts_attributes));
            archive(::cereal::make_nvp("flush_all_macs", m_flush_all_macs));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_bd_attributes_t& m) {
        uint64_t m_l2_lpts_attributes;
        uint64_t m_flush_all_macs;
            archive(::cereal::make_nvp("l2_lpts_attributes", m_l2_lpts_attributes));
            archive(::cereal::make_nvp("flush_all_macs", m_flush_all_macs));
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



template<>
class serializer_class<npl_common_cntr_5bits_offset_and_padding_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_cntr_5bits_offset_and_padding_t& m) {
        uint64_t m_offset = m.offset;
            archive(::cereal::make_nvp("offset", m_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_cntr_5bits_offset_and_padding_t& m) {
        uint64_t m_offset;
            archive(::cereal::make_nvp("offset", m_offset));
        m.offset = m_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_cntr_5bits_offset_and_padding_t& m)
{
    serializer_class<npl_common_cntr_5bits_offset_and_padding_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_cntr_5bits_offset_and_padding_t&);

template <class Archive>
void
load(Archive& archive, npl_common_cntr_5bits_offset_and_padding_t& m)
{
    serializer_class<npl_common_cntr_5bits_offset_and_padding_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_cntr_5bits_offset_and_padding_t&);



template<>
class serializer_class<npl_common_cntr_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_common_cntr_offset_t& m) {
        uint64_t m_base_cntr_offset = m.base_cntr_offset;
            archive(::cereal::make_nvp("base_cntr_offset", m_base_cntr_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_common_cntr_offset_t& m) {
        uint64_t m_base_cntr_offset;
            archive(::cereal::make_nvp("base_cntr_offset", m_base_cntr_offset));
        m.base_cntr_offset = m_base_cntr_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_common_cntr_offset_t& m)
{
    serializer_class<npl_common_cntr_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_common_cntr_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_common_cntr_offset_t& m)
{
    serializer_class<npl_common_cntr_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_common_cntr_offset_t&);



template<>
class serializer_class<npl_compound_termination_control_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_compound_termination_control_t& m) {
        uint64_t m_attempt_termination = m.attempt_termination;
            archive(::cereal::make_nvp("append_relay", m.append_relay));
            archive(::cereal::make_nvp("attempt_termination", m_attempt_termination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_compound_termination_control_t& m) {
        uint64_t m_attempt_termination;
            archive(::cereal::make_nvp("append_relay", m.append_relay));
            archive(::cereal::make_nvp("attempt_termination", m_attempt_termination));
        m.attempt_termination = m_attempt_termination;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_compound_termination_control_t& m)
{
    serializer_class<npl_compound_termination_control_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_compound_termination_control_t&);

template <class Archive>
void
load(Archive& archive, npl_compound_termination_control_t& m)
{
    serializer_class<npl_compound_termination_control_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_compound_termination_control_t&);



template<>
class serializer_class<npl_compressed_counter_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_compressed_counter_t& m) {
        uint64_t m_counter_idx = m.counter_idx;
            archive(::cereal::make_nvp("counter_idx", m_counter_idx));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_compressed_counter_t& m) {
        uint64_t m_counter_idx;
            archive(::cereal::make_nvp("counter_idx", m_counter_idx));
        m.counter_idx = m_counter_idx;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_compressed_counter_t& m)
{
    serializer_class<npl_compressed_counter_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_compressed_counter_t&);

template <class Archive>
void
load(Archive& archive, npl_compressed_counter_t& m)
{
    serializer_class<npl_compressed_counter_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_compressed_counter_t&);



template<>
class serializer_class<npl_counter_flag_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counter_flag_t& m) {
        uint64_t m_num_labels_is_3 = m.num_labels_is_3;
        uint64_t m_pad = m.pad;
            archive(::cereal::make_nvp("num_labels_is_3", m_num_labels_is_3));
            archive(::cereal::make_nvp("pad", m_pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counter_flag_t& m) {
        uint64_t m_num_labels_is_3;
        uint64_t m_pad;
            archive(::cereal::make_nvp("num_labels_is_3", m_num_labels_is_3));
            archive(::cereal::make_nvp("pad", m_pad));
        m.num_labels_is_3 = m_num_labels_is_3;
        m.pad = m_pad;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counter_flag_t& m)
{
    serializer_class<npl_counter_flag_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counter_flag_t&);

template <class Archive>
void
load(Archive& archive, npl_counter_flag_t& m)
{
    serializer_class<npl_counter_flag_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counter_flag_t&);



template<>
class serializer_class<npl_counter_offset_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counter_offset_t& m) {
        uint64_t m_offset = m.offset;
            archive(::cereal::make_nvp("offset", m_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counter_offset_t& m) {
        uint64_t m_offset;
            archive(::cereal::make_nvp("offset", m_offset));
        m.offset = m_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counter_offset_t& m)
{
    serializer_class<npl_counter_offset_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counter_offset_t&);

template <class Archive>
void
load(Archive& archive, npl_counter_offset_t& m)
{
    serializer_class<npl_counter_offset_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counter_offset_t&);



template<>
class serializer_class<npl_counter_ptr_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counter_ptr_t& m) {
        uint64_t m_update_or_read = m.update_or_read;
        uint64_t m_cb_id = m.cb_id;
        uint64_t m_cb_set_base = m.cb_set_base;
            archive(::cereal::make_nvp("update_or_read", m_update_or_read));
            archive(::cereal::make_nvp("cb_id", m_cb_id));
            archive(::cereal::make_nvp("cb_set_base", m_cb_set_base));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counter_ptr_t& m) {
        uint64_t m_update_or_read;
        uint64_t m_cb_id;
        uint64_t m_cb_set_base;
            archive(::cereal::make_nvp("update_or_read", m_update_or_read));
            archive(::cereal::make_nvp("cb_id", m_cb_id));
            archive(::cereal::make_nvp("cb_set_base", m_cb_set_base));
        m.update_or_read = m_update_or_read;
        m.cb_id = m_cb_id;
        m.cb_set_base = m_cb_set_base;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counter_ptr_t& m)
{
    serializer_class<npl_counter_ptr_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counter_ptr_t&);

template <class Archive>
void
load(Archive& archive, npl_counter_ptr_t& m)
{
    serializer_class<npl_counter_ptr_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counter_ptr_t&);



template<>
class serializer_class<npl_counters_block_config_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_block_config_t& m) {
        uint64_t m_lm_count_and_read = m.lm_count_and_read;
        uint64_t m_reset_on_max_counter_read = m.reset_on_max_counter_read;
        uint64_t m_compensation = m.compensation;
        uint64_t m_ignore_pd_compensation = m.ignore_pd_compensation;
        uint64_t m_wraparound = m.wraparound;
        uint64_t m_cpu_read_cc_wait_before_create_bubble = m.cpu_read_cc_wait_before_create_bubble;
        uint64_t m_bank_pipe_client_allocation = m.bank_pipe_client_allocation;
        uint64_t m_bank_slice_allocation = m.bank_slice_allocation;
            archive(::cereal::make_nvp("lm_count_and_read", m_lm_count_and_read));
            archive(::cereal::make_nvp("reset_on_max_counter_read", m_reset_on_max_counter_read));
            archive(::cereal::make_nvp("bank_counter_type", m.bank_counter_type));
            archive(::cereal::make_nvp("compensation", m_compensation));
            archive(::cereal::make_nvp("ignore_pd_compensation", m_ignore_pd_compensation));
            archive(::cereal::make_nvp("wraparound", m_wraparound));
            archive(::cereal::make_nvp("cpu_read_cc_wait_before_create_bubble", m_cpu_read_cc_wait_before_create_bubble));
            archive(::cereal::make_nvp("bank_pipe_client_allocation", m_bank_pipe_client_allocation));
            archive(::cereal::make_nvp("bank_slice_allocation", m_bank_slice_allocation));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_block_config_t& m) {
        uint64_t m_lm_count_and_read;
        uint64_t m_reset_on_max_counter_read;
        uint64_t m_compensation;
        uint64_t m_ignore_pd_compensation;
        uint64_t m_wraparound;
        uint64_t m_cpu_read_cc_wait_before_create_bubble;
        uint64_t m_bank_pipe_client_allocation;
        uint64_t m_bank_slice_allocation;
            archive(::cereal::make_nvp("lm_count_and_read", m_lm_count_and_read));
            archive(::cereal::make_nvp("reset_on_max_counter_read", m_reset_on_max_counter_read));
            archive(::cereal::make_nvp("bank_counter_type", m.bank_counter_type));
            archive(::cereal::make_nvp("compensation", m_compensation));
            archive(::cereal::make_nvp("ignore_pd_compensation", m_ignore_pd_compensation));
            archive(::cereal::make_nvp("wraparound", m_wraparound));
            archive(::cereal::make_nvp("cpu_read_cc_wait_before_create_bubble", m_cpu_read_cc_wait_before_create_bubble));
            archive(::cereal::make_nvp("bank_pipe_client_allocation", m_bank_pipe_client_allocation));
            archive(::cereal::make_nvp("bank_slice_allocation", m_bank_slice_allocation));
        m.lm_count_and_read = m_lm_count_and_read;
        m.reset_on_max_counter_read = m_reset_on_max_counter_read;
        m.compensation = m_compensation;
        m.ignore_pd_compensation = m_ignore_pd_compensation;
        m.wraparound = m_wraparound;
        m.cpu_read_cc_wait_before_create_bubble = m_cpu_read_cc_wait_before_create_bubble;
        m.bank_pipe_client_allocation = m_bank_pipe_client_allocation;
        m.bank_slice_allocation = m_bank_slice_allocation;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_block_config_t& m)
{
    serializer_class<npl_counters_block_config_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_block_config_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_block_config_t& m)
{
    serializer_class<npl_counters_block_config_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_block_config_t&);



template<>
class serializer_class<npl_counters_voq_block_map_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_counters_voq_block_map_result_t& m) {
        uint64_t m_map_groups_size = m.map_groups_size;
        uint64_t m_tc_profile = m.tc_profile;
        uint64_t m_counter_offset = m.counter_offset;
        uint64_t m_bank_id = m.bank_id;
            archive(::cereal::make_nvp("map_groups_size", m_map_groups_size));
            archive(::cereal::make_nvp("tc_profile", m_tc_profile));
            archive(::cereal::make_nvp("counter_offset", m_counter_offset));
            archive(::cereal::make_nvp("bank_id", m_bank_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_counters_voq_block_map_result_t& m) {
        uint64_t m_map_groups_size;
        uint64_t m_tc_profile;
        uint64_t m_counter_offset;
        uint64_t m_bank_id;
            archive(::cereal::make_nvp("map_groups_size", m_map_groups_size));
            archive(::cereal::make_nvp("tc_profile", m_tc_profile));
            archive(::cereal::make_nvp("counter_offset", m_counter_offset));
            archive(::cereal::make_nvp("bank_id", m_bank_id));
        m.map_groups_size = m_map_groups_size;
        m.tc_profile = m_tc_profile;
        m.counter_offset = m_counter_offset;
        m.bank_id = m_bank_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_counters_voq_block_map_result_t& m)
{
    serializer_class<npl_counters_voq_block_map_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_counters_voq_block_map_result_t&);

template <class Archive>
void
load(Archive& archive, npl_counters_voq_block_map_result_t& m)
{
    serializer_class<npl_counters_voq_block_map_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_counters_voq_block_map_result_t&);



template<>
class serializer_class<npl_curr_and_next_prot_type_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_curr_and_next_prot_type_t& m) {
        uint64_t m_current_proto_type = m.current_proto_type;
        uint64_t m_next_proto_type = m.next_proto_type;
            archive(::cereal::make_nvp("current_proto_type", m_current_proto_type));
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_curr_and_next_prot_type_t& m) {
        uint64_t m_current_proto_type;
        uint64_t m_next_proto_type;
            archive(::cereal::make_nvp("current_proto_type", m_current_proto_type));
            archive(::cereal::make_nvp("next_proto_type", m_next_proto_type));
        m.current_proto_type = m_current_proto_type;
        m.next_proto_type = m_next_proto_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_curr_and_next_prot_type_t& m)
{
    serializer_class<npl_curr_and_next_prot_type_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_curr_and_next_prot_type_t&);

template <class Archive>
void
load(Archive& archive, npl_curr_and_next_prot_type_t& m)
{
    serializer_class<npl_curr_and_next_prot_type_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_curr_and_next_prot_type_t&);



template<>
class serializer_class<npl_dest_slice_voq_map_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dest_slice_voq_map_table_result_t& m) {
        uint64_t m_dest_slice_voq = m.dest_slice_voq;
            archive(::cereal::make_nvp("dest_slice_voq", m_dest_slice_voq));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dest_slice_voq_map_table_result_t& m) {
        uint64_t m_dest_slice_voq;
            archive(::cereal::make_nvp("dest_slice_voq", m_dest_slice_voq));
        m.dest_slice_voq = m_dest_slice_voq;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dest_slice_voq_map_table_result_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dest_slice_voq_map_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_dest_slice_voq_map_table_result_t& m)
{
    serializer_class<npl_dest_slice_voq_map_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dest_slice_voq_map_table_result_t&);



template<>
class serializer_class<npl_destination_decoding_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_destination_decoding_table_result_t& m) {
            archive(::cereal::make_nvp("check_npp_range", m.check_npp_range));
            archive(::cereal::make_nvp("lb_table_behavior", m.lb_table_behavior));
            archive(::cereal::make_nvp("resolution_table", m.resolution_table));
            archive(::cereal::make_nvp("resolution_stage", m.resolution_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_destination_decoding_table_result_t& m) {
            archive(::cereal::make_nvp("check_npp_range", m.check_npp_range));
            archive(::cereal::make_nvp("lb_table_behavior", m.lb_table_behavior));
            archive(::cereal::make_nvp("resolution_table", m.resolution_table));
            archive(::cereal::make_nvp("resolution_stage", m.resolution_stage));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_destination_decoding_table_result_t& m)
{
    serializer_class<npl_destination_decoding_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_destination_decoding_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_destination_decoding_table_result_t& m)
{
    serializer_class<npl_destination_decoding_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_destination_decoding_table_result_t&);



template<>
class serializer_class<npl_destination_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_destination_t& m) {
        uint64_t m_val = m.val;
            archive(::cereal::make_nvp("val", m_val));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_destination_t& m) {
        uint64_t m_val;
            archive(::cereal::make_nvp("val", m_val));
        m.val = m_val;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_destination_t& m)
{
    serializer_class<npl_destination_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_destination_t&);

template <class Archive>
void
load(Archive& archive, npl_destination_t& m)
{
    serializer_class<npl_destination_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_destination_t&);



template<>
class serializer_class<npl_device_mode_table_result_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_device_mode_table_result_t& m) {
        uint64_t m_dev_mode = m.dev_mode;
            archive(::cereal::make_nvp("dev_mode", m_dev_mode));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_device_mode_table_result_t& m) {
        uint64_t m_dev_mode;
            archive(::cereal::make_nvp("dev_mode", m_dev_mode));
        m.dev_mode = m_dev_mode;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_device_mode_table_result_t& m)
{
    serializer_class<npl_device_mode_table_result_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_device_mode_table_result_t&);

template <class Archive>
void
load(Archive& archive, npl_device_mode_table_result_t& m)
{
    serializer_class<npl_device_mode_table_result_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_device_mode_table_result_t&);



template<>
class serializer_class<npl_dip_index_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dip_index_t& m) {
        uint64_t m_dummy_index = m.dummy_index;
            archive(::cereal::make_nvp("dummy_index", m_dummy_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dip_index_t& m) {
        uint64_t m_dummy_index;
            archive(::cereal::make_nvp("dummy_index", m_dummy_index));
        m.dummy_index = m_dummy_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dip_index_t& m)
{
    serializer_class<npl_dip_index_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dip_index_t&);

template <class Archive>
void
load(Archive& archive, npl_dip_index_t& m)
{
    serializer_class<npl_dip_index_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dip_index_t&);



template<>
class serializer_class<npl_drop_punt_or_permit_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_drop_punt_or_permit_t& m) {
        uint64_t m_drop = m.drop;
        uint64_t m_force_punt = m.force_punt;
        uint64_t m_permit_count_enable = m.permit_count_enable;
            archive(::cereal::make_nvp("drop", m_drop));
            archive(::cereal::make_nvp("force_punt", m_force_punt));
            archive(::cereal::make_nvp("permit_count_enable", m_permit_count_enable));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_drop_punt_or_permit_t& m) {
        uint64_t m_drop;
        uint64_t m_force_punt;
        uint64_t m_permit_count_enable;
            archive(::cereal::make_nvp("drop", m_drop));
            archive(::cereal::make_nvp("force_punt", m_force_punt));
            archive(::cereal::make_nvp("permit_count_enable", m_permit_count_enable));
        m.drop = m_drop;
        m.force_punt = m_force_punt;
        m.permit_count_enable = m_permit_count_enable;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_drop_punt_or_permit_t& m)
{
    serializer_class<npl_drop_punt_or_permit_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_drop_punt_or_permit_t&);

template <class Archive>
void
load(Archive& archive, npl_drop_punt_or_permit_t& m)
{
    serializer_class<npl_drop_punt_or_permit_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_drop_punt_or_permit_t&);



template<>
class serializer_class<npl_dsp_map_info_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_dsp_map_info_t& m) {
        uint64_t m_dsp_punt_rcy = m.dsp_punt_rcy;
        uint64_t m_dsp_is_scheduled_rcy = m.dsp_is_scheduled_rcy;
            archive(::cereal::make_nvp("dsp_punt_rcy", m_dsp_punt_rcy));
            archive(::cereal::make_nvp("dsp_is_scheduled_rcy", m_dsp_is_scheduled_rcy));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_dsp_map_info_t& m) {
        uint64_t m_dsp_punt_rcy;
        uint64_t m_dsp_is_scheduled_rcy;
            archive(::cereal::make_nvp("dsp_punt_rcy", m_dsp_punt_rcy));
            archive(::cereal::make_nvp("dsp_is_scheduled_rcy", m_dsp_is_scheduled_rcy));
        m.dsp_punt_rcy = m_dsp_punt_rcy;
        m.dsp_is_scheduled_rcy = m_dsp_is_scheduled_rcy;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_dsp_map_info_t& m)
{
    serializer_class<npl_dsp_map_info_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_dsp_map_info_t&);

template <class Archive>
void
load(Archive& archive, npl_dsp_map_info_t& m)
{
    serializer_class<npl_dsp_map_info_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_dsp_map_info_t&);



template<>
class serializer_class<npl_egress_direct0_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_direct0_key_t& m) {
        uint64_t m_direct0_key = m.direct0_key;
            archive(::cereal::make_nvp("direct0_key", m_direct0_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_direct0_key_t& m) {
        uint64_t m_direct0_key;
            archive(::cereal::make_nvp("direct0_key", m_direct0_key));
        m.direct0_key = m_direct0_key;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_direct0_key_t& m)
{
    serializer_class<npl_egress_direct0_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_direct0_key_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_direct0_key_t& m)
{
    serializer_class<npl_egress_direct0_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_direct0_key_t&);



template<>
class serializer_class<npl_egress_direct1_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_direct1_key_t& m) {
        uint64_t m_direct1_key = m.direct1_key;
            archive(::cereal::make_nvp("direct1_key", m_direct1_key));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_direct1_key_t& m) {
        uint64_t m_direct1_key;
            archive(::cereal::make_nvp("direct1_key", m_direct1_key));
        m.direct1_key = m_direct1_key;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_direct1_key_t& m)
{
    serializer_class<npl_egress_direct1_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_direct1_key_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_direct1_key_t& m)
{
    serializer_class<npl_egress_direct1_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_direct1_key_t&);



template<>
class serializer_class<npl_egress_qos_result_t_anonymous_union_remark_l3_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_qos_result_t_anonymous_union_remark_l3_t& m) {
        uint64_t m_enable_egress_remark = m.enable_egress_remark;
        uint64_t m_use_in_mpls_exp = m.use_in_mpls_exp;
            archive(::cereal::make_nvp("enable_egress_remark", m_enable_egress_remark));
            archive(::cereal::make_nvp("use_in_mpls_exp", m_use_in_mpls_exp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_qos_result_t_anonymous_union_remark_l3_t& m) {
        uint64_t m_enable_egress_remark;
        uint64_t m_use_in_mpls_exp;
            archive(::cereal::make_nvp("enable_egress_remark", m_enable_egress_remark));
            archive(::cereal::make_nvp("use_in_mpls_exp", m_use_in_mpls_exp));
        m.enable_egress_remark = m_enable_egress_remark;
        m.use_in_mpls_exp = m_use_in_mpls_exp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_qos_result_t_anonymous_union_remark_l3_t& m)
{
    serializer_class<npl_egress_qos_result_t_anonymous_union_remark_l3_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_qos_result_t_anonymous_union_remark_l3_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_qos_result_t_anonymous_union_remark_l3_t& m)
{
    serializer_class<npl_egress_qos_result_t_anonymous_union_remark_l3_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_qos_result_t_anonymous_union_remark_l3_t&);



template<>
class serializer_class<npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t& m) {
            archive(::cereal::make_nvp("drop_counter", m.drop_counter));
            archive(::cereal::make_nvp("permit_ace_cntr", m.permit_ace_cntr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t& m) {
            archive(::cereal::make_nvp("drop_counter", m.drop_counter));
            archive(::cereal::make_nvp("permit_ace_cntr", m.permit_ace_cntr));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t& m)
{
    serializer_class<npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t&);

template <class Archive>
void
load(Archive& archive, npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t& m)
{
    serializer_class<npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_egress_sec_acl_result_t_anonymous_union_drop_or_permit_t&);



template<>
class serializer_class<npl_em_result_dsp_host_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_em_result_dsp_host_t& m) {
        uint64_t m_dsp_or_dspa = m.dsp_or_dspa;
        uint64_t m_host_mac = m.host_mac;
            archive(::cereal::make_nvp("dsp_or_dspa", m_dsp_or_dspa));
            archive(::cereal::make_nvp("host_mac", m_host_mac));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_em_result_dsp_host_t& m) {
        uint64_t m_dsp_or_dspa;
        uint64_t m_host_mac;
            archive(::cereal::make_nvp("dsp_or_dspa", m_dsp_or_dspa));
            archive(::cereal::make_nvp("host_mac", m_host_mac));
        m.dsp_or_dspa = m_dsp_or_dspa;
        m.host_mac = m_host_mac;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_em_result_dsp_host_t& m)
{
    serializer_class<npl_em_result_dsp_host_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_em_result_dsp_host_t&);

template <class Archive>
void
load(Archive& archive, npl_em_result_dsp_host_t& m)
{
    serializer_class<npl_em_result_dsp_host_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_em_result_dsp_host_t&);



template<>
class serializer_class<npl_encap_mpls_exp_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_encap_mpls_exp_t& m) {
        uint64_t m_valid = m.valid;
        uint64_t m_exp = m.exp;
            archive(::cereal::make_nvp("valid", m_valid));
            archive(::cereal::make_nvp("exp", m_exp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_encap_mpls_exp_t& m) {
        uint64_t m_valid;
        uint64_t m_exp;
            archive(::cereal::make_nvp("valid", m_valid));
            archive(::cereal::make_nvp("exp", m_exp));
        m.valid = m_valid;
        m.exp = m_exp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_encap_mpls_exp_t& m)
{
    serializer_class<npl_encap_mpls_exp_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_encap_mpls_exp_t&);

template <class Archive>
void
load(Archive& archive, npl_encap_mpls_exp_t& m)
{
    serializer_class<npl_encap_mpls_exp_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_encap_mpls_exp_t&);



template<>
class serializer_class<npl_ene_macro_id_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_macro_id_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_macro_id_t& m) {
            archive(::cereal::make_nvp("id", m.id));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_macro_id_t& m)
{
    serializer_class<npl_ene_macro_id_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_macro_id_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_macro_id_t& m)
{
    serializer_class<npl_ene_macro_id_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_macro_id_t&);



template<>
class serializer_class<npl_ene_no_bos_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ene_no_bos_t& m) {
        uint64_t m_exp = m.exp;
            archive(::cereal::make_nvp("exp", m_exp));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ene_no_bos_t& m) {
        uint64_t m_exp;
            archive(::cereal::make_nvp("exp", m_exp));
        m.exp = m_exp;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ene_no_bos_t& m)
{
    serializer_class<npl_ene_no_bos_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ene_no_bos_t&);

template <class Archive>
void
load(Archive& archive, npl_ene_no_bos_t& m)
{
    serializer_class<npl_ene_no_bos_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ene_no_bos_t&);



template<>
class serializer_class<npl_eth_mp_table_transmit_a_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_mp_table_transmit_a_payload_t& m) {
        uint64_t m_tx_rdi = m.tx_rdi;
        uint64_t m_unicast_da = m.unicast_da;
            archive(::cereal::make_nvp("tx_rdi", m_tx_rdi));
            archive(::cereal::make_nvp("ccm_da", m.ccm_da));
            archive(::cereal::make_nvp("unicast_da", m_unicast_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_mp_table_transmit_a_payload_t& m) {
        uint64_t m_tx_rdi;
        uint64_t m_unicast_da;
            archive(::cereal::make_nvp("tx_rdi", m_tx_rdi));
            archive(::cereal::make_nvp("ccm_da", m.ccm_da));
            archive(::cereal::make_nvp("unicast_da", m_unicast_da));
        m.tx_rdi = m_tx_rdi;
        m.unicast_da = m_unicast_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_mp_table_transmit_a_payload_t& m)
{
    serializer_class<npl_eth_mp_table_transmit_a_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_mp_table_transmit_a_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_mp_table_transmit_a_payload_t& m)
{
    serializer_class<npl_eth_mp_table_transmit_a_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_mp_table_transmit_a_payload_t&);



template<>
class serializer_class<npl_eth_mp_table_transmit_b_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_mp_table_transmit_b_payload_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_mp_table_transmit_b_payload_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_mp_table_transmit_b_payload_t& m)
{
    serializer_class<npl_eth_mp_table_transmit_b_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_mp_table_transmit_b_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_mp_table_transmit_b_payload_t& m)
{
    serializer_class<npl_eth_mp_table_transmit_b_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_mp_table_transmit_b_payload_t&);



template<>
class serializer_class<npl_eth_rmep_app_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rmep_app_t& m) {
        uint64_t m_rmep_rdi = m.rmep_rdi;
        uint64_t m_rmep_loc = m.rmep_loc;
            archive(::cereal::make_nvp("rmep_rdi", m_rmep_rdi));
            archive(::cereal::make_nvp("rmep_loc", m_rmep_loc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rmep_app_t& m) {
        uint64_t m_rmep_rdi;
        uint64_t m_rmep_loc;
            archive(::cereal::make_nvp("rmep_rdi", m_rmep_rdi));
            archive(::cereal::make_nvp("rmep_loc", m_rmep_loc));
        m.rmep_rdi = m_rmep_rdi;
        m.rmep_loc = m_rmep_loc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rmep_app_t& m)
{
    serializer_class<npl_eth_rmep_app_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rmep_app_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rmep_app_t& m)
{
    serializer_class<npl_eth_rmep_app_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rmep_app_t&);



template<>
class serializer_class<npl_eth_rmep_attributes_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rmep_attributes_t& m) {
            archive(::cereal::make_nvp("app", m.app));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rmep_attributes_t& m) {
            archive(::cereal::make_nvp("app", m.app));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rmep_attributes_t& m)
{
    serializer_class<npl_eth_rmep_attributes_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rmep_attributes_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rmep_attributes_t& m)
{
    serializer_class<npl_eth_rmep_attributes_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rmep_attributes_t&);



template<>
class serializer_class<npl_eth_rtf_prop_over_fwd0_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rtf_prop_over_fwd0_t& m) {
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rtf_prop_over_fwd0_t& m) {
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rtf_prop_over_fwd0_t& m)
{
    serializer_class<npl_eth_rtf_prop_over_fwd0_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rtf_prop_over_fwd0_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rtf_prop_over_fwd0_t& m)
{
    serializer_class<npl_eth_rtf_prop_over_fwd0_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rtf_prop_over_fwd0_t&);



template<>
class serializer_class<npl_eth_rtf_prop_over_fwd1_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_eth_rtf_prop_over_fwd1_t& m) {
        uint64_t m_acl_id = m.acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_eth_rtf_prop_over_fwd1_t& m) {
        uint64_t m_acl_id;
            archive(::cereal::make_nvp("table_index", m.table_index));
            archive(::cereal::make_nvp("acl_id", m_acl_id));
        m.acl_id = m_acl_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_eth_rtf_prop_over_fwd1_t& m)
{
    serializer_class<npl_eth_rtf_prop_over_fwd1_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_eth_rtf_prop_over_fwd1_t&);

template <class Archive>
void
load(Archive& archive, npl_eth_rtf_prop_over_fwd1_t& m)
{
    serializer_class<npl_eth_rtf_prop_over_fwd1_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_eth_rtf_prop_over_fwd1_t&);



template<>
class serializer_class<npl_ethernet_header_flags_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ethernet_header_flags_t& m) {
        uint64_t m_da_is_bc = m.da_is_bc;
        uint64_t m_sa_is_mc = m.sa_is_mc;
        uint64_t m_sa_eq_da = m.sa_eq_da;
            archive(::cereal::make_nvp("da_is_bc", m_da_is_bc));
            archive(::cereal::make_nvp("sa_is_mc", m_sa_is_mc));
            archive(::cereal::make_nvp("sa_eq_da", m_sa_eq_da));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ethernet_header_flags_t& m) {
        uint64_t m_da_is_bc;
        uint64_t m_sa_is_mc;
        uint64_t m_sa_eq_da;
            archive(::cereal::make_nvp("da_is_bc", m_da_is_bc));
            archive(::cereal::make_nvp("sa_is_mc", m_sa_is_mc));
            archive(::cereal::make_nvp("sa_eq_da", m_sa_eq_da));
        m.da_is_bc = m_da_is_bc;
        m.sa_is_mc = m_sa_is_mc;
        m.sa_eq_da = m_sa_eq_da;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ethernet_header_flags_t& m)
{
    serializer_class<npl_ethernet_header_flags_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ethernet_header_flags_t&);

template <class Archive>
void
load(Archive& archive, npl_ethernet_header_flags_t& m)
{
    serializer_class<npl_ethernet_header_flags_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ethernet_header_flags_t&);



template<>
class serializer_class<npl_ethernet_oam_em_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ethernet_oam_em_t& m) {
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
    do_load(Archive& archive, npl_ethernet_oam_em_t& m) {
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
save(Archive& archive, const npl_ethernet_oam_em_t& m)
{
    serializer_class<npl_ethernet_oam_em_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ethernet_oam_em_t&);

template <class Archive>
void
load(Archive& archive, npl_ethernet_oam_em_t& m)
{
    serializer_class<npl_ethernet_oam_em_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ethernet_oam_em_t&);



template<>
class serializer_class<npl_ethernet_traps_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ethernet_traps_t& m) {
        uint64_t m_acl_drop = m.acl_drop;
        uint64_t m_acl_force_punt = m.acl_force_punt;
        uint64_t m_vlan_membership = m.vlan_membership;
        uint64_t m_acceptable_format = m.acceptable_format;
        uint64_t m_no_service_mapping = m.no_service_mapping;
        uint64_t m_no_termination_on_l3_port = m.no_termination_on_l3_port;
        uint64_t m_no_sip_mapping = m.no_sip_mapping;
        uint64_t m_no_vni_mapping = m.no_vni_mapping;
        uint64_t m_no_vsid_mapping = m.no_vsid_mapping;
        uint64_t m_arp = m.arp;
        uint64_t m_sa_da_error = m.sa_da_error;
        uint64_t m_sa_error = m.sa_error;
        uint64_t m_da_error = m.da_error;
        uint64_t m_sa_multicast = m.sa_multicast;
        uint64_t m_dhcpv4_server = m.dhcpv4_server;
        uint64_t m_dhcpv4_client = m.dhcpv4_client;
        uint64_t m_dhcpv6_server = m.dhcpv6_server;
        uint64_t m_dhcpv6_client = m.dhcpv6_client;
        uint64_t m_ingress_stp_block = m.ingress_stp_block;
        uint64_t m_ptp_over_eth = m.ptp_over_eth;
        uint64_t m_isis_over_l2 = m.isis_over_l2;
        uint64_t m_l2cp0 = m.l2cp0;
        uint64_t m_l2cp1 = m.l2cp1;
        uint64_t m_l2cp2 = m.l2cp2;
        uint64_t m_l2cp3 = m.l2cp3;
        uint64_t m_l2cp4 = m.l2cp4;
        uint64_t m_l2cp5 = m.l2cp5;
        uint64_t m_l2cp6 = m.l2cp6;
        uint64_t m_l2cp7 = m.l2cp7;
        uint64_t m_lacp = m.lacp;
        uint64_t m_cisco_protocols = m.cisco_protocols;
        uint64_t m_macsec = m.macsec;
        uint64_t m_unknown_l3 = m.unknown_l3;
        uint64_t m_test_oam_ac_mep = m.test_oam_ac_mep;
        uint64_t m_test_oam_ac_mip = m.test_oam_ac_mip;
        uint64_t m_test_oam_cfm_link_mdl0 = m.test_oam_cfm_link_mdl0;
        uint64_t m_system_mymac = m.system_mymac;
        uint64_t m_unknown_bc = m.unknown_bc;
        uint64_t m_unknown_mc = m.unknown_mc;
        uint64_t m_unknown_uc = m.unknown_uc;
        uint64_t m_learn_punt = m.learn_punt;
        uint64_t m_bcast_pkt = m.bcast_pkt;
        uint64_t m_pfc_sample = m.pfc_sample;
        uint64_t m_hop_by_hop = m.hop_by_hop;
        uint64_t m_l2_dlp_not_found = m.l2_dlp_not_found;
        uint64_t m_same_interface = m.same_interface;
        uint64_t m_dspa_mc_trim = m.dspa_mc_trim;
        uint64_t m_egress_stp_block = m.egress_stp_block;
        uint64_t m_split_horizon = m.split_horizon;
        uint64_t m_disabled = m.disabled;
        uint64_t m_incompatible_eve_cmd = m.incompatible_eve_cmd;
        uint64_t m_padding_residue_in_second_line = m.padding_residue_in_second_line;
        uint64_t m_pfc_direct_sample = m.pfc_direct_sample;
        uint64_t m_svi_egress_dhcp = m.svi_egress_dhcp;
        uint64_t m_no_pwe_l3_dest = m.no_pwe_l3_dest;
            archive(::cereal::make_nvp("acl_drop", m_acl_drop));
            archive(::cereal::make_nvp("acl_force_punt", m_acl_force_punt));
            archive(::cereal::make_nvp("vlan_membership", m_vlan_membership));
            archive(::cereal::make_nvp("acceptable_format", m_acceptable_format));
            archive(::cereal::make_nvp("no_service_mapping", m_no_service_mapping));
            archive(::cereal::make_nvp("no_termination_on_l3_port", m_no_termination_on_l3_port));
            archive(::cereal::make_nvp("no_sip_mapping", m_no_sip_mapping));
            archive(::cereal::make_nvp("no_vni_mapping", m_no_vni_mapping));
            archive(::cereal::make_nvp("no_vsid_mapping", m_no_vsid_mapping));
            archive(::cereal::make_nvp("arp", m_arp));
            archive(::cereal::make_nvp("sa_da_error", m_sa_da_error));
            archive(::cereal::make_nvp("sa_error", m_sa_error));
            archive(::cereal::make_nvp("da_error", m_da_error));
            archive(::cereal::make_nvp("sa_multicast", m_sa_multicast));
            archive(::cereal::make_nvp("dhcpv4_server", m_dhcpv4_server));
            archive(::cereal::make_nvp("dhcpv4_client", m_dhcpv4_client));
            archive(::cereal::make_nvp("dhcpv6_server", m_dhcpv6_server));
            archive(::cereal::make_nvp("dhcpv6_client", m_dhcpv6_client));
            archive(::cereal::make_nvp("ingress_stp_block", m_ingress_stp_block));
            archive(::cereal::make_nvp("ptp_over_eth", m_ptp_over_eth));
            archive(::cereal::make_nvp("isis_over_l2", m_isis_over_l2));
            archive(::cereal::make_nvp("l2cp0", m_l2cp0));
            archive(::cereal::make_nvp("l2cp1", m_l2cp1));
            archive(::cereal::make_nvp("l2cp2", m_l2cp2));
            archive(::cereal::make_nvp("l2cp3", m_l2cp3));
            archive(::cereal::make_nvp("l2cp4", m_l2cp4));
            archive(::cereal::make_nvp("l2cp5", m_l2cp5));
            archive(::cereal::make_nvp("l2cp6", m_l2cp6));
            archive(::cereal::make_nvp("l2cp7", m_l2cp7));
            archive(::cereal::make_nvp("lacp", m_lacp));
            archive(::cereal::make_nvp("cisco_protocols", m_cisco_protocols));
            archive(::cereal::make_nvp("macsec", m_macsec));
            archive(::cereal::make_nvp("unknown_l3", m_unknown_l3));
            archive(::cereal::make_nvp("test_oam_ac_mep", m_test_oam_ac_mep));
            archive(::cereal::make_nvp("test_oam_ac_mip", m_test_oam_ac_mip));
            archive(::cereal::make_nvp("test_oam_cfm_link_mdl0", m_test_oam_cfm_link_mdl0));
            archive(::cereal::make_nvp("system_mymac", m_system_mymac));
            archive(::cereal::make_nvp("unknown_bc", m_unknown_bc));
            archive(::cereal::make_nvp("unknown_mc", m_unknown_mc));
            archive(::cereal::make_nvp("unknown_uc", m_unknown_uc));
            archive(::cereal::make_nvp("learn_punt", m_learn_punt));
            archive(::cereal::make_nvp("bcast_pkt", m_bcast_pkt));
            archive(::cereal::make_nvp("pfc_sample", m_pfc_sample));
            archive(::cereal::make_nvp("hop_by_hop", m_hop_by_hop));
            archive(::cereal::make_nvp("l2_dlp_not_found", m_l2_dlp_not_found));
            archive(::cereal::make_nvp("same_interface", m_same_interface));
            archive(::cereal::make_nvp("dspa_mc_trim", m_dspa_mc_trim));
            archive(::cereal::make_nvp("egress_stp_block", m_egress_stp_block));
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("incompatible_eve_cmd", m_incompatible_eve_cmd));
            archive(::cereal::make_nvp("padding_residue_in_second_line", m_padding_residue_in_second_line));
            archive(::cereal::make_nvp("pfc_direct_sample", m_pfc_direct_sample));
            archive(::cereal::make_nvp("svi_egress_dhcp", m_svi_egress_dhcp));
            archive(::cereal::make_nvp("no_pwe_l3_dest", m_no_pwe_l3_dest));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ethernet_traps_t& m) {
        uint64_t m_acl_drop;
        uint64_t m_acl_force_punt;
        uint64_t m_vlan_membership;
        uint64_t m_acceptable_format;
        uint64_t m_no_service_mapping;
        uint64_t m_no_termination_on_l3_port;
        uint64_t m_no_sip_mapping;
        uint64_t m_no_vni_mapping;
        uint64_t m_no_vsid_mapping;
        uint64_t m_arp;
        uint64_t m_sa_da_error;
        uint64_t m_sa_error;
        uint64_t m_da_error;
        uint64_t m_sa_multicast;
        uint64_t m_dhcpv4_server;
        uint64_t m_dhcpv4_client;
        uint64_t m_dhcpv6_server;
        uint64_t m_dhcpv6_client;
        uint64_t m_ingress_stp_block;
        uint64_t m_ptp_over_eth;
        uint64_t m_isis_over_l2;
        uint64_t m_l2cp0;
        uint64_t m_l2cp1;
        uint64_t m_l2cp2;
        uint64_t m_l2cp3;
        uint64_t m_l2cp4;
        uint64_t m_l2cp5;
        uint64_t m_l2cp6;
        uint64_t m_l2cp7;
        uint64_t m_lacp;
        uint64_t m_cisco_protocols;
        uint64_t m_macsec;
        uint64_t m_unknown_l3;
        uint64_t m_test_oam_ac_mep;
        uint64_t m_test_oam_ac_mip;
        uint64_t m_test_oam_cfm_link_mdl0;
        uint64_t m_system_mymac;
        uint64_t m_unknown_bc;
        uint64_t m_unknown_mc;
        uint64_t m_unknown_uc;
        uint64_t m_learn_punt;
        uint64_t m_bcast_pkt;
        uint64_t m_pfc_sample;
        uint64_t m_hop_by_hop;
        uint64_t m_l2_dlp_not_found;
        uint64_t m_same_interface;
        uint64_t m_dspa_mc_trim;
        uint64_t m_egress_stp_block;
        uint64_t m_split_horizon;
        uint64_t m_disabled;
        uint64_t m_incompatible_eve_cmd;
        uint64_t m_padding_residue_in_second_line;
        uint64_t m_pfc_direct_sample;
        uint64_t m_svi_egress_dhcp;
        uint64_t m_no_pwe_l3_dest;
            archive(::cereal::make_nvp("acl_drop", m_acl_drop));
            archive(::cereal::make_nvp("acl_force_punt", m_acl_force_punt));
            archive(::cereal::make_nvp("vlan_membership", m_vlan_membership));
            archive(::cereal::make_nvp("acceptable_format", m_acceptable_format));
            archive(::cereal::make_nvp("no_service_mapping", m_no_service_mapping));
            archive(::cereal::make_nvp("no_termination_on_l3_port", m_no_termination_on_l3_port));
            archive(::cereal::make_nvp("no_sip_mapping", m_no_sip_mapping));
            archive(::cereal::make_nvp("no_vni_mapping", m_no_vni_mapping));
            archive(::cereal::make_nvp("no_vsid_mapping", m_no_vsid_mapping));
            archive(::cereal::make_nvp("arp", m_arp));
            archive(::cereal::make_nvp("sa_da_error", m_sa_da_error));
            archive(::cereal::make_nvp("sa_error", m_sa_error));
            archive(::cereal::make_nvp("da_error", m_da_error));
            archive(::cereal::make_nvp("sa_multicast", m_sa_multicast));
            archive(::cereal::make_nvp("dhcpv4_server", m_dhcpv4_server));
            archive(::cereal::make_nvp("dhcpv4_client", m_dhcpv4_client));
            archive(::cereal::make_nvp("dhcpv6_server", m_dhcpv6_server));
            archive(::cereal::make_nvp("dhcpv6_client", m_dhcpv6_client));
            archive(::cereal::make_nvp("ingress_stp_block", m_ingress_stp_block));
            archive(::cereal::make_nvp("ptp_over_eth", m_ptp_over_eth));
            archive(::cereal::make_nvp("isis_over_l2", m_isis_over_l2));
            archive(::cereal::make_nvp("l2cp0", m_l2cp0));
            archive(::cereal::make_nvp("l2cp1", m_l2cp1));
            archive(::cereal::make_nvp("l2cp2", m_l2cp2));
            archive(::cereal::make_nvp("l2cp3", m_l2cp3));
            archive(::cereal::make_nvp("l2cp4", m_l2cp4));
            archive(::cereal::make_nvp("l2cp5", m_l2cp5));
            archive(::cereal::make_nvp("l2cp6", m_l2cp6));
            archive(::cereal::make_nvp("l2cp7", m_l2cp7));
            archive(::cereal::make_nvp("lacp", m_lacp));
            archive(::cereal::make_nvp("cisco_protocols", m_cisco_protocols));
            archive(::cereal::make_nvp("macsec", m_macsec));
            archive(::cereal::make_nvp("unknown_l3", m_unknown_l3));
            archive(::cereal::make_nvp("test_oam_ac_mep", m_test_oam_ac_mep));
            archive(::cereal::make_nvp("test_oam_ac_mip", m_test_oam_ac_mip));
            archive(::cereal::make_nvp("test_oam_cfm_link_mdl0", m_test_oam_cfm_link_mdl0));
            archive(::cereal::make_nvp("system_mymac", m_system_mymac));
            archive(::cereal::make_nvp("unknown_bc", m_unknown_bc));
            archive(::cereal::make_nvp("unknown_mc", m_unknown_mc));
            archive(::cereal::make_nvp("unknown_uc", m_unknown_uc));
            archive(::cereal::make_nvp("learn_punt", m_learn_punt));
            archive(::cereal::make_nvp("bcast_pkt", m_bcast_pkt));
            archive(::cereal::make_nvp("pfc_sample", m_pfc_sample));
            archive(::cereal::make_nvp("hop_by_hop", m_hop_by_hop));
            archive(::cereal::make_nvp("l2_dlp_not_found", m_l2_dlp_not_found));
            archive(::cereal::make_nvp("same_interface", m_same_interface));
            archive(::cereal::make_nvp("dspa_mc_trim", m_dspa_mc_trim));
            archive(::cereal::make_nvp("egress_stp_block", m_egress_stp_block));
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
            archive(::cereal::make_nvp("disabled", m_disabled));
            archive(::cereal::make_nvp("incompatible_eve_cmd", m_incompatible_eve_cmd));
            archive(::cereal::make_nvp("padding_residue_in_second_line", m_padding_residue_in_second_line));
            archive(::cereal::make_nvp("pfc_direct_sample", m_pfc_direct_sample));
            archive(::cereal::make_nvp("svi_egress_dhcp", m_svi_egress_dhcp));
            archive(::cereal::make_nvp("no_pwe_l3_dest", m_no_pwe_l3_dest));
        m.acl_drop = m_acl_drop;
        m.acl_force_punt = m_acl_force_punt;
        m.vlan_membership = m_vlan_membership;
        m.acceptable_format = m_acceptable_format;
        m.no_service_mapping = m_no_service_mapping;
        m.no_termination_on_l3_port = m_no_termination_on_l3_port;
        m.no_sip_mapping = m_no_sip_mapping;
        m.no_vni_mapping = m_no_vni_mapping;
        m.no_vsid_mapping = m_no_vsid_mapping;
        m.arp = m_arp;
        m.sa_da_error = m_sa_da_error;
        m.sa_error = m_sa_error;
        m.da_error = m_da_error;
        m.sa_multicast = m_sa_multicast;
        m.dhcpv4_server = m_dhcpv4_server;
        m.dhcpv4_client = m_dhcpv4_client;
        m.dhcpv6_server = m_dhcpv6_server;
        m.dhcpv6_client = m_dhcpv6_client;
        m.ingress_stp_block = m_ingress_stp_block;
        m.ptp_over_eth = m_ptp_over_eth;
        m.isis_over_l2 = m_isis_over_l2;
        m.l2cp0 = m_l2cp0;
        m.l2cp1 = m_l2cp1;
        m.l2cp2 = m_l2cp2;
        m.l2cp3 = m_l2cp3;
        m.l2cp4 = m_l2cp4;
        m.l2cp5 = m_l2cp5;
        m.l2cp6 = m_l2cp6;
        m.l2cp7 = m_l2cp7;
        m.lacp = m_lacp;
        m.cisco_protocols = m_cisco_protocols;
        m.macsec = m_macsec;
        m.unknown_l3 = m_unknown_l3;
        m.test_oam_ac_mep = m_test_oam_ac_mep;
        m.test_oam_ac_mip = m_test_oam_ac_mip;
        m.test_oam_cfm_link_mdl0 = m_test_oam_cfm_link_mdl0;
        m.system_mymac = m_system_mymac;
        m.unknown_bc = m_unknown_bc;
        m.unknown_mc = m_unknown_mc;
        m.unknown_uc = m_unknown_uc;
        m.learn_punt = m_learn_punt;
        m.bcast_pkt = m_bcast_pkt;
        m.pfc_sample = m_pfc_sample;
        m.hop_by_hop = m_hop_by_hop;
        m.l2_dlp_not_found = m_l2_dlp_not_found;
        m.same_interface = m_same_interface;
        m.dspa_mc_trim = m_dspa_mc_trim;
        m.egress_stp_block = m_egress_stp_block;
        m.split_horizon = m_split_horizon;
        m.disabled = m_disabled;
        m.incompatible_eve_cmd = m_incompatible_eve_cmd;
        m.padding_residue_in_second_line = m_padding_residue_in_second_line;
        m.pfc_direct_sample = m_pfc_direct_sample;
        m.svi_egress_dhcp = m_svi_egress_dhcp;
        m.no_pwe_l3_dest = m_no_pwe_l3_dest;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ethernet_traps_t& m)
{
    serializer_class<npl_ethernet_traps_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ethernet_traps_t&);

template <class Archive>
void
load(Archive& archive, npl_ethernet_traps_t& m)
{
    serializer_class<npl_ethernet_traps_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ethernet_traps_t&);



}

