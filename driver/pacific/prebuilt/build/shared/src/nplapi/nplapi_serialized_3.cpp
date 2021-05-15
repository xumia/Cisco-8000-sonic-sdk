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

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ibm_cmd_table_result_t&);
template <class Archive> void load(Archive&, npl_ibm_cmd_table_result_t&);

template <class Archive> void save(Archive&, const npl_ifgb_tc_lut_results_t&);
template <class Archive> void load(Archive&, npl_ifgb_tc_lut_results_t&);

template <class Archive> void save(Archive&, const npl_ingress_punt_mc_expand_encap_t&);
template <class Archive> void load(Archive&, npl_ingress_punt_mc_expand_encap_t&);

template <class Archive> void save(Archive&, const npl_ingress_qos_result_t&);
template <class Archive> void load(Archive&, npl_ingress_qos_result_t&);

template <class Archive> void save(Archive&, const npl_initial_pd_nw_rx_data_t&);
template <class Archive> void load(Archive&, npl_initial_pd_nw_rx_data_t&);

template <class Archive> void save(Archive&, const npl_ip_rx_global_counter_t&);
template <class Archive> void load(Archive&, npl_ip_rx_global_counter_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_mc_t&);
template <class Archive> void load(Archive&, npl_ip_ver_mc_t&);

template <class Archive> void save(Archive&, const npl_l3_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l3_vxlan_relay_encap_data_t&);
template <class Archive> void load(Archive&, npl_l3_vxlan_relay_encap_data_t&);

template <class Archive> void save(Archive&, const npl_local_tx_ip_mapping_t&);
template <class Archive> void load(Archive&, npl_local_tx_ip_mapping_t&);

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
        uint64_t m_pkt_size_4lsb = m.pkt_size_4lsb;
            archive(::cereal::make_nvp("dsp_is_dma", m_dsp_is_dma));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("inject_down_encap", m.inject_down_encap));
            archive(::cereal::make_nvp("pkt_size_4lsb", m_pkt_size_4lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_inject_down_select_ene_static_table_key_t& m) {
        uint64_t m_dsp_is_dma;
        uint64_t m_pkt_size_4lsb;
            archive(::cereal::make_nvp("dsp_is_dma", m_dsp_is_dma));
            archive(::cereal::make_nvp("fwd_header_type", m.fwd_header_type));
            archive(::cereal::make_nvp("inject_down_encap", m.inject_down_encap));
            archive(::cereal::make_nvp("pkt_size_4lsb", m_pkt_size_4lsb));
        m.dsp_is_dma = m_dsp_is_dma;
        m.pkt_size_4lsb = m_pkt_size_4lsb;
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
class serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t& m) {
            archive(::cereal::make_nvp("tx_npu_header_fwd_header_type", m.tx_npu_header_fwd_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t& m) {
            archive(::cereal::make_nvp("tx_npu_header_fwd_header_type", m.tx_npu_header_fwd_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t& m)
{
    serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t& m)
{
    serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_fwd_header_mapping_to_ethtype_static_table_key_t&);



template<>
class serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t& m)
{
    serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t& m)
{
    serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t&);



template<>
class serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("local_tx_ip_mapping", m.local_tx_ip_mapping));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("local_tx_ip_mapping", m.local_tx_ip_mapping));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t& m)
{
    serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t& m)
{
    serializer_class<npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_fwd_header_mapping_to_ethtype_static_table_value_t::npl_ip_fwd_header_mapping_to_ethtype_static_table_payloads_t&);



template<>
class serializer_class<npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t& m) {
        uint64_t m_global_mcid_17_downto_16_is_zero = m.global_mcid_17_downto_16_is_zero;
            archive(::cereal::make_nvp("global_mcid_17_downto_16_is_zero", m_global_mcid_17_downto_16_is_zero));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t& m) {
        uint64_t m_global_mcid_17_downto_16_is_zero;
            archive(::cereal::make_nvp("global_mcid_17_downto_16_is_zero", m_global_mcid_17_downto_16_is_zero));
        m.global_mcid_17_downto_16_is_zero = m_global_mcid_17_downto_16_is_zero;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ingress_cmp_mcid_static_table_set_value_payload_t&);



template<>
class serializer_class<npl_ip_ingress_cmp_mcid_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_key_t& m) {
        uint64_t m_global_mcid_17_downto_16 = m.global_mcid_17_downto_16;
            archive(::cereal::make_nvp("global_mcid_17_downto_16", m_global_mcid_17_downto_16));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_key_t& m) {
        uint64_t m_global_mcid_17_downto_16;
            archive(::cereal::make_nvp("global_mcid_17_downto_16", m_global_mcid_17_downto_16));
        m.global_mcid_17_downto_16 = m_global_mcid_17_downto_16;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_key_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ingress_cmp_mcid_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_key_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ingress_cmp_mcid_static_table_key_t&);



template<>
class serializer_class<npl_ip_ingress_cmp_mcid_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_value_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ingress_cmp_mcid_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_value_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ingress_cmp_mcid_static_table_value_t&);



template<>
class serializer_class<npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t& m)
{
    serializer_class<npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ingress_cmp_mcid_static_table_value_t::npl_ip_ingress_cmp_mcid_static_table_payloads_t&);



template<>
class serializer_class<npl_ip_mc_local_inject_type_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_local_inject_type_static_table_key_t& m) {
            archive(::cereal::make_nvp("current_protocol", m.current_protocol));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_local_inject_type_static_table_key_t& m) {
            archive(::cereal::make_nvp("current_protocol", m.current_protocol));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_local_inject_type_static_table_key_t& m)
{
    serializer_class<npl_ip_mc_local_inject_type_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_local_inject_type_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_local_inject_type_static_table_key_t& m)
{
    serializer_class<npl_ip_mc_local_inject_type_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_local_inject_type_static_table_key_t&);



template<>
class serializer_class<npl_ip_mc_local_inject_type_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_local_inject_type_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_local_inject_type_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_local_inject_type_static_table_value_t& m)
{
    serializer_class<npl_ip_mc_local_inject_type_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_local_inject_type_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_local_inject_type_static_table_value_t& m)
{
    serializer_class<npl_ip_mc_local_inject_type_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_local_inject_type_static_table_value_t&);



template<>
class serializer_class<npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("pd_ene_encap_data_inject_header_type", m.pd_ene_encap_data_inject_header_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("pd_ene_encap_data_inject_header_type", m.pd_ene_encap_data_inject_header_type));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t& m)
{
    serializer_class<npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t& m)
{
    serializer_class<npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_local_inject_type_static_table_value_t::npl_ip_mc_local_inject_type_static_table_payloads_t&);



template<>
class serializer_class<npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_npe_macro_id = m.npe_macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t& m) {
        uint64_t m_pl_inc;
        uint64_t m_npe_macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("npe_macro_id", m_npe_macro_id));
        m.pl_inc = m_pl_inc;
        m.npe_macro_id = m_npe_macro_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_next_macro_static_table_set_npe_next_macro_payload_t&);



template<>
class serializer_class<npl_ip_mc_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_next_macro_static_table_key_t& m) {
        uint64_t m_same_l3_int = m.same_l3_int;
            archive(::cereal::make_nvp("same_l3_int", m_same_l3_int));
            archive(::cereal::make_nvp("collapsed_mc", m.collapsed_mc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_next_macro_static_table_key_t& m) {
        uint64_t m_same_l3_int;
            archive(::cereal::make_nvp("same_l3_int", m_same_l3_int));
            archive(::cereal::make_nvp("collapsed_mc", m.collapsed_mc));
        m.same_l3_int = m_same_l3_int;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_next_macro_static_table_key_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_next_macro_static_table_key_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_ip_mc_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_next_macro_static_table_value_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_next_macro_static_table_value_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_npe_next_macro", m.set_npe_next_macro));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_npe_next_macro", m.set_npe_next_macro));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_next_macro_static_table_value_t::npl_ip_mc_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_ip_meter_profile_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_meter_profile_mapping_table_key_t& m) {
        uint64_t m_qos_id = m.qos_id;
            archive(::cereal::make_nvp("qos_id", m_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_meter_profile_mapping_table_key_t& m) {
        uint64_t m_qos_id;
            archive(::cereal::make_nvp("qos_id", m_qos_id));
        m.qos_id = m_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_meter_profile_mapping_table_key_t& m)
{
    serializer_class<npl_ip_meter_profile_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_meter_profile_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_meter_profile_mapping_table_key_t& m)
{
    serializer_class<npl_ip_meter_profile_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_meter_profile_mapping_table_key_t&);



template<>
class serializer_class<npl_ip_meter_profile_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_meter_profile_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_meter_profile_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_meter_profile_mapping_table_value_t& m)
{
    serializer_class<npl_ip_meter_profile_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_meter_profile_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_meter_profile_mapping_table_value_t& m)
{
    serializer_class<npl_ip_meter_profile_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_meter_profile_mapping_table_value_t&);



template<>
class serializer_class<npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t& m) {
        uint64_t m_slp_qos_id = m.slp_qos_id;
            archive(::cereal::make_nvp("slp_qos_id", m_slp_qos_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t& m) {
        uint64_t m_slp_qos_id;
            archive(::cereal::make_nvp("slp_qos_id", m_slp_qos_id));
        m.slp_qos_id = m_slp_qos_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t& m)
{
    serializer_class<npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t& m)
{
    serializer_class<npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_meter_profile_mapping_table_value_t::npl_ip_meter_profile_mapping_table_payloads_t&);



template<>
class serializer_class<npl_ip_prefix_destination_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_prefix_destination_table_key_t& m) {
        uint64_t m_ip_prefix_ptr = m.ip_prefix_ptr;
            archive(::cereal::make_nvp("ip_prefix_ptr", m_ip_prefix_ptr));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_prefix_destination_table_key_t& m) {
        uint64_t m_ip_prefix_ptr;
            archive(::cereal::make_nvp("ip_prefix_ptr", m_ip_prefix_ptr));
        m.ip_prefix_ptr = m_ip_prefix_ptr;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_prefix_destination_table_key_t& m)
{
    serializer_class<npl_ip_prefix_destination_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_prefix_destination_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_prefix_destination_table_key_t& m)
{
    serializer_class<npl_ip_prefix_destination_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_prefix_destination_table_key_t&);



template<>
class serializer_class<npl_ip_prefix_destination_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_prefix_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_prefix_destination_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_prefix_destination_table_value_t& m)
{
    serializer_class<npl_ip_prefix_destination_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_prefix_destination_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_prefix_destination_table_value_t& m)
{
    serializer_class<npl_ip_prefix_destination_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_prefix_destination_table_value_t&);



template<>
class serializer_class<npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("prefix_destination", m.prefix_destination));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t& m) {
            archive(::cereal::make_nvp("prefix_destination", m.prefix_destination));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t& m)
{
    serializer_class<npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t& m)
{
    serializer_class<npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_prefix_destination_table_value_t::npl_ip_prefix_destination_table_payloads_t&);



template<>
class serializer_class<npl_ip_relay_to_vni_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_relay_to_vni_table_key_t& m) {
        uint64_t m_overlay_nh = m.overlay_nh;
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_relay_to_vni_table_key_t& m) {
        uint64_t m_overlay_nh;
            archive(::cereal::make_nvp("overlay_nh", m_overlay_nh));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
        m.overlay_nh = m_overlay_nh;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_relay_to_vni_table_key_t& m)
{
    serializer_class<npl_ip_relay_to_vni_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_relay_to_vni_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_relay_to_vni_table_key_t& m)
{
    serializer_class<npl_ip_relay_to_vni_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_relay_to_vni_table_key_t&);



template<>
class serializer_class<npl_ip_relay_to_vni_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_relay_to_vni_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_relay_to_vni_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_relay_to_vni_table_value_t& m)
{
    serializer_class<npl_ip_relay_to_vni_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_relay_to_vni_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_relay_to_vni_table_value_t& m)
{
    serializer_class<npl_ip_relay_to_vni_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_relay_to_vni_table_value_t&);



template<>
class serializer_class<npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t& m) {
            archive(::cereal::make_nvp("l3_vxlan_relay_encap_data", m.l3_vxlan_relay_encap_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t& m) {
            archive(::cereal::make_nvp("l3_vxlan_relay_encap_data", m.l3_vxlan_relay_encap_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t& m)
{
    serializer_class<npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t& m)
{
    serializer_class<npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_relay_to_vni_table_value_t::npl_ip_relay_to_vni_table_payloads_t&);



template<>
class serializer_class<npl_ip_rx_global_counter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_rx_global_counter_table_key_t& m) {
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_rx_global_counter_table_key_t& m) {
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_rx_global_counter_table_key_t& m)
{
    serializer_class<npl_ip_rx_global_counter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_rx_global_counter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_rx_global_counter_table_key_t& m)
{
    serializer_class<npl_ip_rx_global_counter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_rx_global_counter_table_key_t&);



template<>
class serializer_class<npl_ip_rx_global_counter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_rx_global_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_rx_global_counter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_rx_global_counter_table_value_t& m)
{
    serializer_class<npl_ip_rx_global_counter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_rx_global_counter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_rx_global_counter_table_value_t& m)
{
    serializer_class<npl_ip_rx_global_counter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_rx_global_counter_table_value_t&);



template<>
class serializer_class<npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("global_counter", m.global_counter));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t& m) {
            archive(::cereal::make_nvp("global_counter", m.global_counter));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t& m)
{
    serializer_class<npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t& m)
{
    serializer_class<npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_rx_global_counter_table_value_t::npl_ip_rx_global_counter_table_payloads_t&);



template<>
class serializer_class<npl_ip_ver_mc_static_table_set_value_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ver_mc_static_table_set_value_payload_t& m) {
        uint64_t m_v4_offset_zero = m.v4_offset_zero;
            archive(::cereal::make_nvp("v4_offset_zero", m_v4_offset_zero));
            archive(::cereal::make_nvp("ip_ver_mc", m.ip_ver_mc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ver_mc_static_table_set_value_payload_t& m) {
        uint64_t m_v4_offset_zero;
            archive(::cereal::make_nvp("v4_offset_zero", m_v4_offset_zero));
            archive(::cereal::make_nvp("ip_ver_mc", m.ip_ver_mc));
        m.v4_offset_zero = m_v4_offset_zero;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ver_mc_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_set_value_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ver_mc_static_table_set_value_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ver_mc_static_table_set_value_payload_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_set_value_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ver_mc_static_table_set_value_payload_t&);



template<>
class serializer_class<npl_ip_ver_mc_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ver_mc_static_table_key_t& m) {
        uint64_t m_is_v6 = m.is_v6;
        uint64_t m_v6_sip_127_120 = m.v6_sip_127_120;
        uint64_t m_v4_sip_31_28 = m.v4_sip_31_28;
        uint64_t m_v4_frag_offset = m.v4_frag_offset;
            archive(::cereal::make_nvp("is_v6", m_is_v6));
            archive(::cereal::make_nvp("v6_sip_127_120", m_v6_sip_127_120));
            archive(::cereal::make_nvp("v4_sip_31_28", m_v4_sip_31_28));
            archive(::cereal::make_nvp("v4_frag_offset", m_v4_frag_offset));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ver_mc_static_table_key_t& m) {
        uint64_t m_is_v6;
        uint64_t m_v6_sip_127_120;
        uint64_t m_v4_sip_31_28;
        uint64_t m_v4_frag_offset;
            archive(::cereal::make_nvp("is_v6", m_is_v6));
            archive(::cereal::make_nvp("v6_sip_127_120", m_v6_sip_127_120));
            archive(::cereal::make_nvp("v4_sip_31_28", m_v4_sip_31_28));
            archive(::cereal::make_nvp("v4_frag_offset", m_v4_frag_offset));
        m.is_v6 = m_is_v6;
        m.v6_sip_127_120 = m_v6_sip_127_120;
        m.v4_sip_31_28 = m_v4_sip_31_28;
        m.v4_frag_offset = m_v4_frag_offset;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ver_mc_static_table_key_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ver_mc_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ver_mc_static_table_key_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ver_mc_static_table_key_t&);



template<>
class serializer_class<npl_ip_ver_mc_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ver_mc_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ver_mc_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ver_mc_static_table_value_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ver_mc_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ver_mc_static_table_value_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ver_mc_static_table_value_t&);



template<>
class serializer_class<npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_value", m.set_value));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t& m)
{
    serializer_class<npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_ver_mc_static_table_value_t::npl_ip_ver_mc_static_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t& m) {
        uint64_t m_dummy_bits = m.dummy_bits;
        uint64_t m_is_valid = m.is_valid;
        uint64_t m_acl_l4_protocol = m.acl_l4_protocol;
        uint64_t m_protocol_type = m.protocol_type;
            archive(::cereal::make_nvp("dummy_bits", m_dummy_bits));
            archive(::cereal::make_nvp("is_valid", m_is_valid));
            archive(::cereal::make_nvp("acl_l4_protocol", m_acl_l4_protocol));
            archive(::cereal::make_nvp("protocol_type", m_protocol_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t& m) {
        uint64_t m_dummy_bits;
        uint64_t m_is_valid;
        uint64_t m_acl_l4_protocol;
        uint64_t m_protocol_type;
            archive(::cereal::make_nvp("dummy_bits", m_dummy_bits));
            archive(::cereal::make_nvp("is_valid", m_is_valid));
            archive(::cereal::make_nvp("acl_l4_protocol", m_acl_l4_protocol));
            archive(::cereal::make_nvp("protocol_type", m_protocol_type));
        m.dummy_bits = m_dummy_bits;
        m.is_valid = m_is_valid;
        m.acl_l4_protocol = m_acl_l4_protocol;
        m.protocol_type = m_protocol_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_update_payload_t&);



template<>
class serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& m) {
        uint64_t m_protocol = m.protocol;
            archive(::cereal::make_nvp("protocol", m_protocol));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& m) {
        uint64_t m_protocol;
            archive(::cereal::make_nvp("protocol", m_protocol));
        m.protocol = m_protocol;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_key_t&);



template<>
class serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t&);



template<>
class serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t& m) {
            archive(::cereal::make_nvp("update", m.update));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t& m)
{
    serializer_class<npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_acl_map_protocol_type_to_protocol_number_table_value_t::npl_ipv4_acl_map_protocol_type_to_protocol_number_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_acl_sport_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_acl_sport_static_table_key_t& m) {
        uint64_t m_acl_is_valid = m.acl_is_valid;
        uint64_t m_acl_l4_protocol = m.acl_l4_protocol;
            archive(::cereal::make_nvp("acl_is_valid", m_acl_is_valid));
            archive(::cereal::make_nvp("acl_l4_protocol", m_acl_l4_protocol));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_acl_sport_static_table_key_t& m) {
        uint64_t m_acl_is_valid;
        uint64_t m_acl_l4_protocol;
            archive(::cereal::make_nvp("acl_is_valid", m_acl_is_valid));
            archive(::cereal::make_nvp("acl_l4_protocol", m_acl_l4_protocol));
        m.acl_is_valid = m_acl_is_valid;
        m.acl_l4_protocol = m_acl_l4_protocol;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_acl_sport_static_table_key_t& m)
{
    serializer_class<npl_ipv4_acl_sport_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_acl_sport_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_acl_sport_static_table_key_t& m)
{
    serializer_class<npl_ipv4_acl_sport_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_acl_sport_static_table_key_t&);



template<>
class serializer_class<npl_ipv4_acl_sport_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_acl_sport_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_acl_sport_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_acl_sport_static_table_value_t& m)
{
    serializer_class<npl_ipv4_acl_sport_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_acl_sport_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_acl_sport_static_table_value_t& m)
{
    serializer_class<npl_ipv4_acl_sport_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_acl_sport_static_table_value_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t& m) {
        uint64_t m_my_dip_index = m.my_dip_index;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t& m) {
        uint64_t m_my_dip_index;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
        m.my_dip_index = m_my_dip_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_key_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt0_attributes", m.term_tt0_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt0_attributes", m.term_tt0_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_index_tt0_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t& m) {
        uint64_t m_sip = m.sip;
        uint64_t m_my_dip_index = m.my_dip_index;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t& m) {
        uint64_t m_sip;
        uint64_t m_my_dip_index;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
        m.sip = m_sip;
        m.my_dip_index = m_my_dip_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_key_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt0_attributes", m.term_tt0_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt0_attributes", m.term_tt0_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt0_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t& m) {
        uint64_t m_sip = m.sip;
        uint64_t m_my_dip_index = m.my_dip_index;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t& m) {
        uint64_t m_sip;
        uint64_t m_my_dip_index;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("my_dip_index", m_my_dip_index));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
        m.sip = m_sip;
        m.my_dip_index = m_my_dip_index;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_key_t&);



}

