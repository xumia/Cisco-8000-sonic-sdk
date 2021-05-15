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

template <class Archive> void save(Archive&, const npl_destination_t&);
template <class Archive> void load(Archive&, npl_destination_t&);

template <class Archive> void save(Archive&, const npl_ip_em_result_t&);
template <class Archive> void load(Archive&, npl_ip_em_result_t&);

template <class Archive> void save(Archive&, const npl_ip_fi_core_tcam_table_next_header_info_payload_t&);
template <class Archive> void load(Archive&, npl_ip_fi_core_tcam_table_next_header_info_payload_t&);

template <class Archive> void save(Archive&, const npl_ip_mc_result_em_payload_t&);
template <class Archive> void load(Archive&, npl_ip_mc_result_em_payload_t&);

template <class Archive> void save(Archive&, const npl_ip_rtf_iteration_properties_t&);
template <class Archive> void load(Archive&, npl_ip_rtf_iteration_properties_t&);

template <class Archive> void save(Archive&, const npl_ip_rx_global_counter_t&);
template <class Archive> void load(Archive&, npl_ip_rx_global_counter_t&);

template <class Archive> void save(Archive&, const npl_ip_sgt_em_result_t&);
template <class Archive> void load(Archive&, npl_ip_sgt_em_result_t&);

template <class Archive> void save(Archive&, const npl_ip_sgt_result_t&);
template <class Archive> void load(Archive&, npl_ip_sgt_result_t&);

template <class Archive> void save(Archive&, const npl_ip_ver_mc_t&);
template <class Archive> void load(Archive&, npl_ip_ver_mc_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_eth_init_rtf_stages_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_eth_init_rtf_stages_t&);

template <class Archive> void save(Archive&, const npl_ipv4_ipv6_init_rtf_stage_t&);
template <class Archive> void load(Archive&, npl_ipv4_ipv6_init_rtf_stage_t&);

template <class Archive> void save(Archive&, const npl_l2_dlp_attributes_t&);
template <class Archive> void load(Archive&, npl_l2_dlp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_ip_fragment_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_ip_fragment_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_next_macro_pack_fields_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_next_macro_pack_fields_t&);

template <class Archive> void save(Archive&, const npl_l2_lpts_payload_t&);
template <class Archive> void load(Archive&, npl_l2_lpts_payload_t&);

template <class Archive> void save(Archive&, const npl_l3_lp_attributes_t&);
template <class Archive> void load(Archive&, npl_l3_lp_attributes_t&);

template <class Archive> void save(Archive&, const npl_l3_relay_id_t&);
template <class Archive> void load(Archive&, npl_l3_relay_id_t&);

template <class Archive> void save(Archive&, const npl_l3_vxlan_relay_encap_data_t&);
template <class Archive> void load(Archive&, npl_l3_vxlan_relay_encap_data_t&);

template <class Archive> void save(Archive&, const npl_l4_ports_header_t&);
template <class Archive> void load(Archive&, npl_l4_ports_header_t&);

template <class Archive> void save(Archive&, const npl_local_tx_ip_mapping_t&);
template <class Archive> void load(Archive&, npl_local_tx_ip_mapping_t&);

template <class Archive> void save(Archive&, const npl_lp_rtf_conf_set_t&);
template <class Archive> void load(Archive&, npl_lp_rtf_conf_set_t&);

template <class Archive> void save(Archive&, const npl_lpm_payload_t&);
template <class Archive> void load(Archive&, npl_lpm_payload_t&);

template <class Archive> void save(Archive&, const npl_lpts_cntr_and_lookup_index_t&);
template <class Archive> void load(Archive&, npl_lpts_cntr_and_lookup_index_t&);

template <class Archive> void save(Archive&, const npl_lpts_object_groups_t&);
template <class Archive> void load(Archive&, npl_lpts_object_groups_t&);

template <class Archive> void save(Archive&, const npl_lpts_tcam_first_result_encap_data_msb_t&);
template <class Archive> void load(Archive&, npl_lpts_tcam_first_result_encap_data_msb_t&);

template <class Archive> void save(Archive&, const npl_mac_addr_t&);
template <class Archive> void load(Archive&, npl_mac_addr_t&);

template <class Archive> void save(Archive&, const npl_og_em_result_t&);
template <class Archive> void load(Archive&, npl_og_em_result_t&);

template <class Archive> void save(Archive&, const npl_og_lpm_compression_code_t&);
template <class Archive> void load(Archive&, npl_og_lpm_compression_code_t&);

template <class Archive> void save(Archive&, const npl_og_pcl_id_t&);
template <class Archive> void load(Archive&, npl_og_pcl_id_t&);

template <class Archive> void save(Archive&, const npl_punt_encap_data_lsb_t&);
template <class Archive> void load(Archive&, npl_punt_encap_data_lsb_t&);

template <class Archive> void save(Archive&, const npl_rtf_step_t&);
template <class Archive> void load(Archive&, npl_rtf_step_t&);

template<>
class serializer_class<npl_ip_fi_core_tcam_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid = m.ethertype_or_tpid;
        uint64_t m_is_ipv6_header = m.is_ipv6_header;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
            archive(::cereal::make_nvp("is_ipv6_header", m_is_ipv6_header));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_fi_core_tcam_table_key_t& m) {
        uint64_t m_ethertype_or_tpid;
        uint64_t m_is_ipv6_header;
            archive(::cereal::make_nvp("ethertype_or_tpid", m_ethertype_or_tpid));
            archive(::cereal::make_nvp("is_ipv6_header", m_is_ipv6_header));
        m.ethertype_or_tpid = m_ethertype_or_tpid;
        m.is_ipv6_header = m_is_ipv6_header;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_fi_core_tcam_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_fi_core_tcam_table_key_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_fi_core_tcam_table_key_t&);



template<>
class serializer_class<npl_ip_fi_core_tcam_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_fi_core_tcam_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_fi_core_tcam_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_fi_core_tcam_table_value_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_fi_core_tcam_table_value_t&);



template<>
class serializer_class<npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t& m) {
            archive(::cereal::make_nvp("next_header_info", m.next_header_info));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t& m)
{
    serializer_class<npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_fi_core_tcam_table_value_t::npl_ip_fi_core_tcam_table_payloads_t&);



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
class serializer_class<npl_ip_inactivity_check_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_inactivity_check_table_key_t& m) {
        uint64_t m_ip_address_msb = m.ip_address_msb;
        uint64_t m_vrf_id = m.vrf_id;
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("ip_address_msb", m_ip_address_msb));
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_inactivity_check_table_key_t& m) {
        uint64_t m_ip_address_msb;
        uint64_t m_vrf_id;
            archive(::cereal::make_nvp("ip_version", m.ip_version));
            archive(::cereal::make_nvp("ip_address_msb", m_ip_address_msb));
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
        m.ip_address_msb = m_ip_address_msb;
        m.vrf_id = m_vrf_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_inactivity_check_table_key_t& m)
{
    serializer_class<npl_ip_inactivity_check_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_inactivity_check_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_inactivity_check_table_key_t& m)
{
    serializer_class<npl_ip_inactivity_check_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_inactivity_check_table_key_t&);



template<>
class serializer_class<npl_ip_inactivity_check_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_inactivity_check_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_inactivity_check_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_inactivity_check_table_value_t& m)
{
    serializer_class<npl_ip_inactivity_check_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_inactivity_check_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_inactivity_check_table_value_t& m)
{
    serializer_class<npl_ip_inactivity_check_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_inactivity_check_table_value_t&);



template<>
class serializer_class<npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t& m) {
        uint64_t m_ip_inactivity_punt = m.ip_inactivity_punt;
            archive(::cereal::make_nvp("ip_inactivity_punt", m_ip_inactivity_punt));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t& m) {
        uint64_t m_ip_inactivity_punt;
            archive(::cereal::make_nvp("ip_inactivity_punt", m_ip_inactivity_punt));
        m.ip_inactivity_punt = m_ip_inactivity_punt;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t& m)
{
    serializer_class<npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t& m)
{
    serializer_class<npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_inactivity_check_table_value_t::npl_ip_inactivity_check_table_payloads_t&);



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
class serializer_class<npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_mpls_next_macro_static_table_ip_mc_mpls_next_macro_action_payload_t&);



template<>
class serializer_class<npl_ip_mc_mpls_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_key_t& m) {
        uint64_t m_ipv4_msb = m.ipv4_msb;
        uint64_t m_ipv6_msb = m.ipv6_msb;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("ipv4_msb", m_ipv4_msb));
            archive(::cereal::make_nvp("ipv6_msb", m_ipv6_msb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_key_t& m) {
        uint64_t m_ipv4_msb;
        uint64_t m_ipv6_msb;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("ipv4_msb", m_ipv4_msb));
            archive(::cereal::make_nvp("ipv6_msb", m_ipv6_msb));
        m.ipv4_msb = m_ipv4_msb;
        m.ipv6_msb = m_ipv6_msb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_key_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_mpls_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_key_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_mpls_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_ip_mc_mpls_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_value_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_mpls_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_value_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_mpls_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_mc_mpls_next_macro_action", m.ip_mc_mpls_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_mc_mpls_next_macro_action", m.ip_mc_mpls_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_mc_mpls_next_macro_static_table_value_t::npl_ip_mc_mpls_next_macro_static_table_payloads_t&);



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
class serializer_class<npl_ip_proto_type_mux_static_table_set_values_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_proto_type_mux_static_table_set_values_payload_t& m) {
        uint64_t m_is_gre_v4 = m.is_gre_v4;
        uint64_t m_is_gre_v6 = m.is_gre_v6;
        uint64_t m_is_udp = m.is_udp;
        uint64_t m_is_hop_by_hop = m.is_hop_by_hop;
            archive(::cereal::make_nvp("is_gre_v4", m_is_gre_v4));
            archive(::cereal::make_nvp("is_gre_v6", m_is_gre_v6));
            archive(::cereal::make_nvp("is_udp", m_is_udp));
            archive(::cereal::make_nvp("is_hop_by_hop", m_is_hop_by_hop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_proto_type_mux_static_table_set_values_payload_t& m) {
        uint64_t m_is_gre_v4;
        uint64_t m_is_gre_v6;
        uint64_t m_is_udp;
        uint64_t m_is_hop_by_hop;
            archive(::cereal::make_nvp("is_gre_v4", m_is_gre_v4));
            archive(::cereal::make_nvp("is_gre_v6", m_is_gre_v6));
            archive(::cereal::make_nvp("is_udp", m_is_udp));
            archive(::cereal::make_nvp("is_hop_by_hop", m_is_hop_by_hop));
        m.is_gre_v4 = m_is_gre_v4;
        m.is_gre_v6 = m_is_gre_v6;
        m.is_udp = m_is_udp;
        m.is_hop_by_hop = m_is_hop_by_hop;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_proto_type_mux_static_table_set_values_payload_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_set_values_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_proto_type_mux_static_table_set_values_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_proto_type_mux_static_table_set_values_payload_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_set_values_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_proto_type_mux_static_table_set_values_payload_t&);



template<>
class serializer_class<npl_ip_proto_type_mux_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_proto_type_mux_static_table_key_t& m) {
        uint64_t m_ip_version = m.ip_version;
        uint64_t m_ipv4_proto = m.ipv4_proto;
        uint64_t m_ipv6_proto = m.ipv6_proto;
            archive(::cereal::make_nvp("ip_version", m_ip_version));
            archive(::cereal::make_nvp("ipv4_proto", m_ipv4_proto));
            archive(::cereal::make_nvp("ipv6_proto", m_ipv6_proto));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_proto_type_mux_static_table_key_t& m) {
        uint64_t m_ip_version;
        uint64_t m_ipv4_proto;
        uint64_t m_ipv6_proto;
            archive(::cereal::make_nvp("ip_version", m_ip_version));
            archive(::cereal::make_nvp("ipv4_proto", m_ipv4_proto));
            archive(::cereal::make_nvp("ipv6_proto", m_ipv6_proto));
        m.ip_version = m_ip_version;
        m.ipv4_proto = m_ipv4_proto;
        m.ipv6_proto = m_ipv6_proto;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_proto_type_mux_static_table_key_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_proto_type_mux_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_proto_type_mux_static_table_key_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_proto_type_mux_static_table_key_t&);



template<>
class serializer_class<npl_ip_proto_type_mux_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_proto_type_mux_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_proto_type_mux_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_proto_type_mux_static_table_value_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_proto_type_mux_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_proto_type_mux_static_table_value_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_proto_type_mux_static_table_value_t&);



template<>
class serializer_class<npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_values", m.set_values));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("set_values", m.set_values));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t& m)
{
    serializer_class<npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ip_proto_type_mux_static_table_value_t::npl_ip_proto_type_mux_static_table_payloads_t&);



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
class serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t& m) {
        uint64_t m_dip = m.dip;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t& m) {
        uint64_t m_dip;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("tunnel_type", m.tunnel_type));
        m.dip = m_dip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_dip_tt0_table_key_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt0_attributes", m.term_tt0_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt0_attributes", m.term_tt0_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_dip_tt0_table_value_t::npl_ipv4_ip_tunnel_termination_dip_tt0_table_payloads_t&);



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



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t&);



template<>
class serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt1_attributes", m.term_tt1_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t& m) {
            archive(::cereal::make_nvp("term_tt1_attributes", m.term_tt1_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t& m)
{
    serializer_class<npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_value_t::npl_ipv4_ip_tunnel_termination_sip_dip_index_tt1_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_lpm_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_lpm_table_key_t& m) {
        uint64_t m_ipv4_ip_address_address = m.ipv4_ip_address_address;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ipv4_ip_address_address", m_ipv4_ip_address_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_lpm_table_key_t& m) {
        uint64_t m_ipv4_ip_address_address;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ipv4_ip_address_address", m_ipv4_ip_address_address));
        m.ipv4_ip_address_address = m_ipv4_ip_address_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_lpm_table_key_t& m)
{
    serializer_class<npl_ipv4_lpm_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_lpm_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_lpm_table_key_t& m)
{
    serializer_class<npl_ipv4_lpm_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_lpm_table_key_t&);



template<>
class serializer_class<npl_ipv4_lpm_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_lpm_table_value_t& m)
{
    serializer_class<npl_ipv4_lpm_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_lpm_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_lpm_table_value_t& m)
{
    serializer_class<npl_ipv4_lpm_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_lpm_table_value_t&);



template<>
class serializer_class<npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_payload", m.lpm_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_payload", m.lpm_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_lpm_table_value_t::npl_ipv4_lpm_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t& m) {
            archive(::cereal::make_nvp("lpts_first_result_encap_data_msb", m.lpts_first_result_encap_data_msb));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("lpts_cntr_and_second_lookup_index", m.lpts_cntr_and_second_lookup_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t& m) {
            archive(::cereal::make_nvp("lpts_first_result_encap_data_msb", m.lpts_first_result_encap_data_msb));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("lpts_cntr_and_second_lookup_index", m.lpts_cntr_and_second_lookup_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t& m)
{
    serializer_class<npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t& m)
{
    serializer_class<npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_lpts_table_lpts_first_lookup_result_payload_t&);



template<>
class serializer_class<npl_ipv4_lpts_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_lpts_table_key_t& m) {
        uint64_t m_fragmented = m.fragmented;
        uint64_t m_is_mc = m.is_mc;
        uint64_t m_app_id = m.app_id;
        uint64_t m_established = m.established;
        uint64_t m_ttl_255 = m.ttl_255;
        uint64_t m_l4_protocol = m.l4_protocol;
        uint64_t m_v4_frag = m.v4_frag;
        uint64_t m_ip_length = m.ip_length;
        uint64_t m_sip = m.sip;
            archive(::cereal::make_nvp("fragmented", m_fragmented));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("app_id", m_app_id));
            archive(::cereal::make_nvp("established", m_established));
            archive(::cereal::make_nvp("ttl_255", m_ttl_255));
            archive(::cereal::make_nvp("og_codes", m.og_codes));
            archive(::cereal::make_nvp("l4_protocol", m_l4_protocol));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("v4_frag", m_v4_frag));
            archive(::cereal::make_nvp("ip_length", m_ip_length));
            archive(::cereal::make_nvp("sip", m_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_lpts_table_key_t& m) {
        uint64_t m_fragmented;
        uint64_t m_is_mc;
        uint64_t m_app_id;
        uint64_t m_established;
        uint64_t m_ttl_255;
        uint64_t m_l4_protocol;
        uint64_t m_v4_frag;
        uint64_t m_ip_length;
        uint64_t m_sip;
            archive(::cereal::make_nvp("fragmented", m_fragmented));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("app_id", m_app_id));
            archive(::cereal::make_nvp("established", m_established));
            archive(::cereal::make_nvp("ttl_255", m_ttl_255));
            archive(::cereal::make_nvp("og_codes", m.og_codes));
            archive(::cereal::make_nvp("l4_protocol", m_l4_protocol));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("v4_frag", m_v4_frag));
            archive(::cereal::make_nvp("ip_length", m_ip_length));
            archive(::cereal::make_nvp("sip", m_sip));
        m.fragmented = m_fragmented;
        m.is_mc = m_is_mc;
        m.app_id = m_app_id;
        m.established = m_established;
        m.ttl_255 = m_ttl_255;
        m.l4_protocol = m_l4_protocol;
        m.v4_frag = m_v4_frag;
        m.ip_length = m_ip_length;
        m.sip = m_sip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_lpts_table_key_t& m)
{
    serializer_class<npl_ipv4_lpts_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_lpts_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_lpts_table_key_t& m)
{
    serializer_class<npl_ipv4_lpts_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_lpts_table_key_t&);



template<>
class serializer_class<npl_ipv4_lpts_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_lpts_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_lpts_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_lpts_table_value_t& m)
{
    serializer_class<npl_ipv4_lpts_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_lpts_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_lpts_table_value_t& m)
{
    serializer_class<npl_ipv4_lpts_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_lpts_table_value_t&);



template<>
class serializer_class<npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpts_first_lookup_result", m.lpts_first_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpts_first_lookup_result", m.lpts_first_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t& m)
{
    serializer_class<npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t& m)
{
    serializer_class<npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_lpts_table_value_t::npl_ipv4_lpts_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_og_pcl_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_og_pcl_em_table_key_t& m) {
        uint64_t m_ip_address_31_20 = m.ip_address_31_20;
        uint64_t m_ip_address_19_0 = m.ip_address_19_0;
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address_31_20", m_ip_address_31_20));
            archive(::cereal::make_nvp("ip_address_19_0", m_ip_address_19_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_og_pcl_em_table_key_t& m) {
        uint64_t m_ip_address_31_20;
        uint64_t m_ip_address_19_0;
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address_31_20", m_ip_address_31_20));
            archive(::cereal::make_nvp("ip_address_19_0", m_ip_address_19_0));
        m.ip_address_31_20 = m_ip_address_31_20;
        m.ip_address_19_0 = m_ip_address_19_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_og_pcl_em_table_key_t& m)
{
    serializer_class<npl_ipv4_og_pcl_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_og_pcl_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_og_pcl_em_table_key_t& m)
{
    serializer_class<npl_ipv4_og_pcl_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_og_pcl_em_table_key_t&);



template<>
class serializer_class<npl_ipv4_og_pcl_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_og_pcl_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_og_pcl_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_og_pcl_em_table_value_t& m)
{
    serializer_class<npl_ipv4_og_pcl_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_og_pcl_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_og_pcl_em_table_value_t& m)
{
    serializer_class<npl_ipv4_og_pcl_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_og_pcl_em_table_value_t&);



template<>
class serializer_class<npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("og_em_lookup_result", m.og_em_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("og_em_lookup_result", m.og_em_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t& m)
{
    serializer_class<npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t& m)
{
    serializer_class<npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_og_pcl_em_table_value_t::npl_ipv4_og_pcl_em_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_og_pcl_lpm_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_og_pcl_lpm_table_key_t& m) {
        uint64_t m_ip_address = m.ip_address;
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address", m_ip_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_og_pcl_lpm_table_key_t& m) {
        uint64_t m_ip_address;
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address", m_ip_address));
        m.ip_address = m_ip_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_og_pcl_lpm_table_key_t& m)
{
    serializer_class<npl_ipv4_og_pcl_lpm_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_og_pcl_lpm_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_og_pcl_lpm_table_key_t& m)
{
    serializer_class<npl_ipv4_og_pcl_lpm_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_og_pcl_lpm_table_key_t&);



template<>
class serializer_class<npl_ipv4_og_pcl_lpm_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_og_pcl_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_og_pcl_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_og_pcl_lpm_table_value_t& m)
{
    serializer_class<npl_ipv4_og_pcl_lpm_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_og_pcl_lpm_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_og_pcl_lpm_table_value_t& m)
{
    serializer_class<npl_ipv4_og_pcl_lpm_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_og_pcl_lpm_table_value_t&);



template<>
class serializer_class<npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_code", m.lpm_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_code", m.lpm_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_og_pcl_lpm_table_value_t::npl_ipv4_og_pcl_lpm_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_rtf_conf_set_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_rtf_conf_set_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_rtf_conf_set_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_rtf_conf_set_mapping_table_key_t& m)
{
    serializer_class<npl_ipv4_rtf_conf_set_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_rtf_conf_set_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_rtf_conf_set_mapping_table_key_t& m)
{
    serializer_class<npl_ipv4_rtf_conf_set_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_rtf_conf_set_mapping_table_key_t&);



template<>
class serializer_class<npl_ipv4_rtf_conf_set_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_rtf_conf_set_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_rtf_conf_set_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_rtf_conf_set_mapping_table_value_t& m)
{
    serializer_class<npl_ipv4_rtf_conf_set_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_rtf_conf_set_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_rtf_conf_set_mapping_table_value_t& m)
{
    serializer_class<npl_ipv4_rtf_conf_set_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_rtf_conf_set_mapping_table_value_t&);



template<>
class serializer_class<npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ipv4_rtf_iteration_prop", m.ipv4_rtf_iteration_prop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ipv4_rtf_iteration_prop", m.ipv4_rtf_iteration_prop));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t& m)
{
    serializer_class<npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t& m)
{
    serializer_class<npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_rtf_conf_set_mapping_table_value_t::npl_ipv4_rtf_conf_set_mapping_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_sgt_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_sgt_em_table_key_t& m) {
        uint64_t m_vrf_id = m.vrf_id;
        uint64_t m_ip_address_31_20 = m.ip_address_31_20;
        uint64_t m_ip_address_19_0 = m.ip_address_19_0;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address_31_20", m_ip_address_31_20));
            archive(::cereal::make_nvp("ip_address_19_0", m_ip_address_19_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_sgt_em_table_key_t& m) {
        uint64_t m_vrf_id;
        uint64_t m_ip_address_31_20;
        uint64_t m_ip_address_19_0;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address_31_20", m_ip_address_31_20));
            archive(::cereal::make_nvp("ip_address_19_0", m_ip_address_19_0));
        m.vrf_id = m_vrf_id;
        m.ip_address_31_20 = m_ip_address_31_20;
        m.ip_address_19_0 = m_ip_address_19_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_sgt_em_table_key_t& m)
{
    serializer_class<npl_ipv4_sgt_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_sgt_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_sgt_em_table_key_t& m)
{
    serializer_class<npl_ipv4_sgt_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_sgt_em_table_key_t&);



template<>
class serializer_class<npl_ipv4_sgt_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_sgt_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_sgt_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_sgt_em_table_value_t& m)
{
    serializer_class<npl_ipv4_sgt_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_sgt_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_sgt_em_table_value_t& m)
{
    serializer_class<npl_ipv4_sgt_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_sgt_em_table_value_t&);



template<>
class serializer_class<npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_sgt_em_result", m.ip_sgt_em_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_sgt_em_result", m.ip_sgt_em_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t& m)
{
    serializer_class<npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t& m)
{
    serializer_class<npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_sgt_em_table_value_t::npl_ipv4_sgt_em_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_sgt_lpm_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_sgt_lpm_table_key_t& m) {
        uint64_t m_vrf_id = m.vrf_id;
        uint64_t m_ip_address = m.ip_address;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address", m_ip_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_sgt_lpm_table_key_t& m) {
        uint64_t m_vrf_id;
        uint64_t m_ip_address;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address", m_ip_address));
        m.vrf_id = m_vrf_id;
        m.ip_address = m_ip_address;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_sgt_lpm_table_key_t& m)
{
    serializer_class<npl_ipv4_sgt_lpm_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_sgt_lpm_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_sgt_lpm_table_key_t& m)
{
    serializer_class<npl_ipv4_sgt_lpm_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_sgt_lpm_table_key_t&);



template<>
class serializer_class<npl_ipv4_sgt_lpm_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_sgt_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_sgt_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_sgt_lpm_table_value_t& m)
{
    serializer_class<npl_ipv4_sgt_lpm_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_sgt_lpm_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_sgt_lpm_table_value_t& m)
{
    serializer_class<npl_ipv4_sgt_lpm_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_sgt_lpm_table_value_t&);



template<>
class serializer_class<npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_data", m.sgt_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_data", m.sgt_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_sgt_lpm_table_value_t::npl_ipv4_sgt_lpm_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_vrf_dip_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_vrf_dip_em_table_key_t& m) {
        uint64_t m_ip_address_31_20 = m.ip_address_31_20;
        uint64_t m_ip_address_19_0 = m.ip_address_19_0;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ip_address_31_20", m_ip_address_31_20));
            archive(::cereal::make_nvp("ip_address_19_0", m_ip_address_19_0));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_vrf_dip_em_table_key_t& m) {
        uint64_t m_ip_address_31_20;
        uint64_t m_ip_address_19_0;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ip_address_31_20", m_ip_address_31_20));
            archive(::cereal::make_nvp("ip_address_19_0", m_ip_address_19_0));
        m.ip_address_31_20 = m_ip_address_31_20;
        m.ip_address_19_0 = m_ip_address_19_0;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_vrf_dip_em_table_key_t& m)
{
    serializer_class<npl_ipv4_vrf_dip_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_vrf_dip_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_vrf_dip_em_table_key_t& m)
{
    serializer_class<npl_ipv4_vrf_dip_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_vrf_dip_em_table_key_t&);



template<>
class serializer_class<npl_ipv4_vrf_dip_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_vrf_dip_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_vrf_dip_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_vrf_dip_em_table_value_t& m)
{
    serializer_class<npl_ipv4_vrf_dip_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_vrf_dip_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_vrf_dip_em_table_value_t& m)
{
    serializer_class<npl_ipv4_vrf_dip_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_vrf_dip_em_table_value_t&);



template<>
class serializer_class<npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("em_lookup_result", m.em_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("em_lookup_result", m.em_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t& m)
{
    serializer_class<npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t& m)
{
    serializer_class<npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_vrf_dip_em_table_value_t::npl_ipv4_vrf_dip_em_table_payloads_t&);



template<>
class serializer_class<npl_ipv4_vrf_s_g_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_vrf_s_g_table_key_t& m) {
        uint64_t m_dip_19_0_ = m.dip_19_0_;
        uint64_t m_sip = m.sip;
        uint64_t m_dip_27_20_ = m.dip_27_20_;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("dip_19_0_", m_dip_19_0_));
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("dip_27_20_", m_dip_27_20_));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_vrf_s_g_table_key_t& m) {
        uint64_t m_dip_19_0_;
        uint64_t m_sip;
        uint64_t m_dip_27_20_;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("dip_19_0_", m_dip_19_0_));
            archive(::cereal::make_nvp("sip", m_sip));
            archive(::cereal::make_nvp("dip_27_20_", m_dip_27_20_));
        m.dip_19_0_ = m_dip_19_0_;
        m.sip = m_sip;
        m.dip_27_20_ = m_dip_27_20_;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_vrf_s_g_table_key_t& m)
{
    serializer_class<npl_ipv4_vrf_s_g_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_vrf_s_g_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_vrf_s_g_table_key_t& m)
{
    serializer_class<npl_ipv4_vrf_s_g_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_vrf_s_g_table_key_t&);



template<>
class serializer_class<npl_ipv4_vrf_s_g_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_vrf_s_g_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_vrf_s_g_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_vrf_s_g_table_value_t& m)
{
    serializer_class<npl_ipv4_vrf_s_g_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_vrf_s_g_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_vrf_s_g_table_value_t& m)
{
    serializer_class<npl_ipv4_vrf_s_g_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_vrf_s_g_table_value_t&);



template<>
class serializer_class<npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t& m) {
            archive(::cereal::make_nvp("vrf_s_g_hw_ip_mc_result", m.vrf_s_g_hw_ip_mc_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t& m) {
            archive(::cereal::make_nvp("vrf_s_g_hw_ip_mc_result", m.vrf_s_g_hw_ip_mc_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t& m)
{
    serializer_class<npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t& m)
{
    serializer_class<npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv4_vrf_s_g_table_value_t::npl_ipv4_vrf_s_g_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_acl_sport_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_acl_sport_static_table_key_t& m) {
        uint64_t m_acl_is_valid = m.acl_is_valid;
        uint64_t m_acl_l4_protocol = m.acl_l4_protocol;
            archive(::cereal::make_nvp("acl_is_valid", m_acl_is_valid));
            archive(::cereal::make_nvp("acl_l4_protocol", m_acl_l4_protocol));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_acl_sport_static_table_key_t& m) {
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
save(Archive& archive, const npl_ipv6_acl_sport_static_table_key_t& m)
{
    serializer_class<npl_ipv6_acl_sport_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_acl_sport_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_acl_sport_static_table_key_t& m)
{
    serializer_class<npl_ipv6_acl_sport_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_acl_sport_static_table_key_t&);



template<>
class serializer_class<npl_ipv6_acl_sport_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_acl_sport_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_acl_sport_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_acl_sport_static_table_value_t& m)
{
    serializer_class<npl_ipv6_acl_sport_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_acl_sport_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_acl_sport_static_table_value_t& m)
{
    serializer_class<npl_ipv6_acl_sport_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_acl_sport_static_table_value_t&);



template<>
class serializer_class<npl_ipv6_first_fragment_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_first_fragment_static_table_key_t& m) {
        uint64_t m_acl_on_outer = m.acl_on_outer;
        uint64_t m_acl_changed_destination = m.acl_changed_destination;
        uint64_t m_saved_not_first_fragment = m.saved_not_first_fragment;
        uint64_t m_packet_not_first_fragment = m.packet_not_first_fragment;
            archive(::cereal::make_nvp("acl_on_outer", m_acl_on_outer));
            archive(::cereal::make_nvp("acl_changed_destination", m_acl_changed_destination));
            archive(::cereal::make_nvp("saved_not_first_fragment", m_saved_not_first_fragment));
            archive(::cereal::make_nvp("packet_not_first_fragment", m_packet_not_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_first_fragment_static_table_key_t& m) {
        uint64_t m_acl_on_outer;
        uint64_t m_acl_changed_destination;
        uint64_t m_saved_not_first_fragment;
        uint64_t m_packet_not_first_fragment;
            archive(::cereal::make_nvp("acl_on_outer", m_acl_on_outer));
            archive(::cereal::make_nvp("acl_changed_destination", m_acl_changed_destination));
            archive(::cereal::make_nvp("saved_not_first_fragment", m_saved_not_first_fragment));
            archive(::cereal::make_nvp("packet_not_first_fragment", m_packet_not_first_fragment));
        m.acl_on_outer = m_acl_on_outer;
        m.acl_changed_destination = m_acl_changed_destination;
        m.saved_not_first_fragment = m_saved_not_first_fragment;
        m.packet_not_first_fragment = m_packet_not_first_fragment;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_first_fragment_static_table_key_t& m)
{
    serializer_class<npl_ipv6_first_fragment_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_first_fragment_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_first_fragment_static_table_key_t& m)
{
    serializer_class<npl_ipv6_first_fragment_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_first_fragment_static_table_key_t&);



template<>
class serializer_class<npl_ipv6_first_fragment_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_first_fragment_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_first_fragment_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_first_fragment_static_table_value_t& m)
{
    serializer_class<npl_ipv6_first_fragment_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_first_fragment_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_first_fragment_static_table_value_t& m)
{
    serializer_class<npl_ipv6_first_fragment_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_first_fragment_static_table_value_t&);



template<>
class serializer_class<npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_first_fragment", m.ip_first_fragment));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t& m)
{
    serializer_class<npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t& m)
{
    serializer_class<npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_first_fragment_static_table_value_t::npl_ipv6_first_fragment_static_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_lpm_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_lpm_table_key_t& m) {
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ipv6_ip_address_address", m.ipv6_ip_address_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_lpm_table_key_t& m) {
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ipv6_ip_address_address", m.ipv6_ip_address_address));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_lpm_table_key_t& m)
{
    serializer_class<npl_ipv6_lpm_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_lpm_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_lpm_table_key_t& m)
{
    serializer_class<npl_ipv6_lpm_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_lpm_table_key_t&);



template<>
class serializer_class<npl_ipv6_lpm_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_lpm_table_value_t& m)
{
    serializer_class<npl_ipv6_lpm_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_lpm_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_lpm_table_value_t& m)
{
    serializer_class<npl_ipv6_lpm_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_lpm_table_value_t&);



template<>
class serializer_class<npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_payload", m.lpm_payload));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_payload", m.lpm_payload));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_lpm_table_value_t::npl_ipv6_lpm_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t& m) {
            archive(::cereal::make_nvp("lpts_first_result_encap_data_msb", m.lpts_first_result_encap_data_msb));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("lpts_cntr_and_second_lookup_index", m.lpts_cntr_and_second_lookup_index));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t& m) {
            archive(::cereal::make_nvp("lpts_first_result_encap_data_msb", m.lpts_first_result_encap_data_msb));
            archive(::cereal::make_nvp("punt_encap_data_lsb", m.punt_encap_data_lsb));
            archive(::cereal::make_nvp("lpts_cntr_and_second_lookup_index", m.lpts_cntr_and_second_lookup_index));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t& m)
{
    serializer_class<npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t& m)
{
    serializer_class<npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_lpts_table_lpts_first_lookup_result_payload_t&);



template<>
class serializer_class<npl_ipv6_lpts_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_lpts_table_key_t& m) {
        uint64_t m_src_port = m.src_port;
        uint64_t m_is_mc = m.is_mc;
        uint64_t m_app_id = m.app_id;
        uint64_t m_established = m.established;
        uint64_t m_ttl_255 = m.ttl_255;
        uint64_t m_l4_protocol = m.l4_protocol;
        uint64_t m_dst_port = m.dst_port;
        uint64_t m_ip_length = m.ip_length;
        uint64_t m_pad = m.pad;
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("sip", m.sip));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("app_id", m_app_id));
            archive(::cereal::make_nvp("established", m_established));
            archive(::cereal::make_nvp("ttl_255", m_ttl_255));
            archive(::cereal::make_nvp("og_codes", m.og_codes));
            archive(::cereal::make_nvp("l4_protocol", m_l4_protocol));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("ip_length", m_ip_length));
            archive(::cereal::make_nvp("pad", m_pad));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_lpts_table_key_t& m) {
        uint64_t m_src_port;
        uint64_t m_is_mc;
        uint64_t m_app_id;
        uint64_t m_established;
        uint64_t m_ttl_255;
        uint64_t m_l4_protocol;
        uint64_t m_dst_port;
        uint64_t m_ip_length;
        uint64_t m_pad;
            archive(::cereal::make_nvp("src_port", m_src_port));
            archive(::cereal::make_nvp("sip", m.sip));
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("is_mc", m_is_mc));
            archive(::cereal::make_nvp("app_id", m_app_id));
            archive(::cereal::make_nvp("established", m_established));
            archive(::cereal::make_nvp("ttl_255", m_ttl_255));
            archive(::cereal::make_nvp("og_codes", m.og_codes));
            archive(::cereal::make_nvp("l4_protocol", m_l4_protocol));
            archive(::cereal::make_nvp("dst_port", m_dst_port));
            archive(::cereal::make_nvp("ip_length", m_ip_length));
            archive(::cereal::make_nvp("pad", m_pad));
        m.src_port = m_src_port;
        m.is_mc = m_is_mc;
        m.app_id = m_app_id;
        m.established = m_established;
        m.ttl_255 = m_ttl_255;
        m.l4_protocol = m_l4_protocol;
        m.dst_port = m_dst_port;
        m.ip_length = m_ip_length;
        m.pad = m_pad;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_lpts_table_key_t& m)
{
    serializer_class<npl_ipv6_lpts_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_lpts_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_lpts_table_key_t& m)
{
    serializer_class<npl_ipv6_lpts_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_lpts_table_key_t&);



template<>
class serializer_class<npl_ipv6_lpts_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_lpts_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_lpts_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_lpts_table_value_t& m)
{
    serializer_class<npl_ipv6_lpts_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_lpts_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_lpts_table_value_t& m)
{
    serializer_class<npl_ipv6_lpts_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_lpts_table_value_t&);



template<>
class serializer_class<npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpts_first_lookup_result", m.lpts_first_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpts_first_lookup_result", m.lpts_first_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t& m)
{
    serializer_class<npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t& m)
{
    serializer_class<npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_lpts_table_value_t::npl_ipv6_lpts_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_og_pcl_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_og_pcl_em_table_key_t& m) {
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_og_pcl_em_table_key_t& m) {
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_og_pcl_em_table_key_t& m)
{
    serializer_class<npl_ipv6_og_pcl_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_og_pcl_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_og_pcl_em_table_key_t& m)
{
    serializer_class<npl_ipv6_og_pcl_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_og_pcl_em_table_key_t&);



template<>
class serializer_class<npl_ipv6_og_pcl_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_og_pcl_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_og_pcl_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_og_pcl_em_table_value_t& m)
{
    serializer_class<npl_ipv6_og_pcl_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_og_pcl_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_og_pcl_em_table_value_t& m)
{
    serializer_class<npl_ipv6_og_pcl_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_og_pcl_em_table_value_t&);



template<>
class serializer_class<npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("og_em_lookup_result", m.og_em_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("og_em_lookup_result", m.og_em_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t& m)
{
    serializer_class<npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t& m)
{
    serializer_class<npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_og_pcl_em_table_value_t::npl_ipv6_og_pcl_em_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_og_pcl_lpm_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_og_pcl_lpm_table_key_t& m) {
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_og_pcl_lpm_table_key_t& m) {
            archive(::cereal::make_nvp("pcl_id", m.pcl_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_og_pcl_lpm_table_key_t& m)
{
    serializer_class<npl_ipv6_og_pcl_lpm_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_og_pcl_lpm_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_og_pcl_lpm_table_key_t& m)
{
    serializer_class<npl_ipv6_og_pcl_lpm_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_og_pcl_lpm_table_key_t&);



template<>
class serializer_class<npl_ipv6_og_pcl_lpm_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_og_pcl_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_og_pcl_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_og_pcl_lpm_table_value_t& m)
{
    serializer_class<npl_ipv6_og_pcl_lpm_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_og_pcl_lpm_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_og_pcl_lpm_table_value_t& m)
{
    serializer_class<npl_ipv6_og_pcl_lpm_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_og_pcl_lpm_table_value_t&);



template<>
class serializer_class<npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_code", m.lpm_code));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("lpm_code", m.lpm_code));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_og_pcl_lpm_table_value_t::npl_ipv6_og_pcl_lpm_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_rtf_conf_set_mapping_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_rtf_conf_set_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_rtf_conf_set_mapping_table_key_t& m) {
            archive(::cereal::make_nvp("lp_rtf_conf_set", m.lp_rtf_conf_set));
            archive(::cereal::make_nvp("rtf_step", m.rtf_step));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_rtf_conf_set_mapping_table_key_t& m)
{
    serializer_class<npl_ipv6_rtf_conf_set_mapping_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_rtf_conf_set_mapping_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_rtf_conf_set_mapping_table_key_t& m)
{
    serializer_class<npl_ipv6_rtf_conf_set_mapping_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_rtf_conf_set_mapping_table_key_t&);



template<>
class serializer_class<npl_ipv6_rtf_conf_set_mapping_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_rtf_conf_set_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_rtf_conf_set_mapping_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_rtf_conf_set_mapping_table_value_t& m)
{
    serializer_class<npl_ipv6_rtf_conf_set_mapping_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_rtf_conf_set_mapping_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_rtf_conf_set_mapping_table_value_t& m)
{
    serializer_class<npl_ipv6_rtf_conf_set_mapping_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_rtf_conf_set_mapping_table_value_t&);



template<>
class serializer_class<npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ipv6_rtf_iteration_prop", m.ipv6_rtf_iteration_prop));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t& m) {
            archive(::cereal::make_nvp("ipv6_rtf_iteration_prop", m.ipv6_rtf_iteration_prop));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t& m)
{
    serializer_class<npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t& m)
{
    serializer_class<npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_rtf_conf_set_mapping_table_value_t::npl_ipv6_rtf_conf_set_mapping_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_sgt_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sgt_em_table_key_t& m) {
        uint64_t m_vrf_id = m.vrf_id;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sgt_em_table_key_t& m) {
        uint64_t m_vrf_id;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
        m.vrf_id = m_vrf_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sgt_em_table_key_t& m)
{
    serializer_class<npl_ipv6_sgt_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sgt_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sgt_em_table_key_t& m)
{
    serializer_class<npl_ipv6_sgt_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sgt_em_table_key_t&);



template<>
class serializer_class<npl_ipv6_sgt_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sgt_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sgt_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sgt_em_table_value_t& m)
{
    serializer_class<npl_ipv6_sgt_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sgt_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sgt_em_table_value_t& m)
{
    serializer_class<npl_ipv6_sgt_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sgt_em_table_value_t&);



template<>
class serializer_class<npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_sgt_em_result", m.ip_sgt_em_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("ip_sgt_em_result", m.ip_sgt_em_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t& m)
{
    serializer_class<npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t& m)
{
    serializer_class<npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sgt_em_table_value_t::npl_ipv6_sgt_em_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_sgt_lpm_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sgt_lpm_table_key_t& m) {
        uint64_t m_vrf_id = m.vrf_id;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sgt_lpm_table_key_t& m) {
        uint64_t m_vrf_id;
            archive(::cereal::make_nvp("vrf_id", m_vrf_id));
            archive(::cereal::make_nvp("ip_address", m.ip_address));
        m.vrf_id = m_vrf_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sgt_lpm_table_key_t& m)
{
    serializer_class<npl_ipv6_sgt_lpm_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sgt_lpm_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sgt_lpm_table_key_t& m)
{
    serializer_class<npl_ipv6_sgt_lpm_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sgt_lpm_table_key_t&);



template<>
class serializer_class<npl_ipv6_sgt_lpm_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sgt_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sgt_lpm_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sgt_lpm_table_value_t& m)
{
    serializer_class<npl_ipv6_sgt_lpm_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sgt_lpm_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sgt_lpm_table_value_t& m)
{
    serializer_class<npl_ipv6_sgt_lpm_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sgt_lpm_table_value_t&);



template<>
class serializer_class<npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_data", m.sgt_data));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t& m) {
            archive(::cereal::make_nvp("sgt_data", m.sgt_data));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t& m)
{
    serializer_class<npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sgt_lpm_table_value_t::npl_ipv6_sgt_lpm_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_sip_compression_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sip_compression_table_key_t& m) {
            archive(::cereal::make_nvp("ipv6_sip", m.ipv6_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sip_compression_table_key_t& m) {
            archive(::cereal::make_nvp("ipv6_sip", m.ipv6_sip));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sip_compression_table_key_t& m)
{
    serializer_class<npl_ipv6_sip_compression_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sip_compression_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sip_compression_table_key_t& m)
{
    serializer_class<npl_ipv6_sip_compression_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sip_compression_table_key_t&);



template<>
class serializer_class<npl_ipv6_sip_compression_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sip_compression_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sip_compression_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sip_compression_table_value_t& m)
{
    serializer_class<npl_ipv6_sip_compression_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sip_compression_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sip_compression_table_value_t& m)
{
    serializer_class<npl_ipv6_sip_compression_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sip_compression_table_value_t&);



template<>
class serializer_class<npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t& m) {
        uint64_t m_compressed_sip = m.compressed_sip;
            archive(::cereal::make_nvp("compressed_sip", m_compressed_sip));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t& m) {
        uint64_t m_compressed_sip;
            archive(::cereal::make_nvp("compressed_sip", m_compressed_sip));
        m.compressed_sip = m_compressed_sip;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t& m)
{
    serializer_class<npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t& m)
{
    serializer_class<npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_sip_compression_table_value_t::npl_ipv6_sip_compression_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_vrf_dip_em_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_vrf_dip_em_table_key_t& m) {
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ipv6_ip_address_address", m.ipv6_ip_address_address));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_vrf_dip_em_table_key_t& m) {
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("ipv6_ip_address_address", m.ipv6_ip_address_address));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_vrf_dip_em_table_key_t& m)
{
    serializer_class<npl_ipv6_vrf_dip_em_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_vrf_dip_em_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_vrf_dip_em_table_key_t& m)
{
    serializer_class<npl_ipv6_vrf_dip_em_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_vrf_dip_em_table_key_t&);



template<>
class serializer_class<npl_ipv6_vrf_dip_em_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_vrf_dip_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_vrf_dip_em_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_vrf_dip_em_table_value_t& m)
{
    serializer_class<npl_ipv6_vrf_dip_em_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_vrf_dip_em_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_vrf_dip_em_table_value_t& m)
{
    serializer_class<npl_ipv6_vrf_dip_em_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_vrf_dip_em_table_value_t&);



template<>
class serializer_class<npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("em_lookup_result", m.em_lookup_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t& m) {
            archive(::cereal::make_nvp("em_lookup_result", m.em_lookup_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t& m)
{
    serializer_class<npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t& m)
{
    serializer_class<npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_vrf_dip_em_table_value_t::npl_ipv6_vrf_dip_em_table_payloads_t&);



template<>
class serializer_class<npl_ipv6_vrf_s_g_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_vrf_s_g_table_key_t& m) {
        uint64_t m_compressed_sip = m.compressed_sip;
        uint64_t m_dip_32_lsb = m.dip_32_lsb;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("compressed_sip", m_compressed_sip));
            archive(::cereal::make_nvp("dip_32_lsb", m_dip_32_lsb));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_vrf_s_g_table_key_t& m) {
        uint64_t m_compressed_sip;
        uint64_t m_dip_32_lsb;
            archive(::cereal::make_nvp("l3_relay_id", m.l3_relay_id));
            archive(::cereal::make_nvp("compressed_sip", m_compressed_sip));
            archive(::cereal::make_nvp("dip_32_lsb", m_dip_32_lsb));
        m.compressed_sip = m_compressed_sip;
        m.dip_32_lsb = m_dip_32_lsb;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_vrf_s_g_table_key_t& m)
{
    serializer_class<npl_ipv6_vrf_s_g_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_vrf_s_g_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_vrf_s_g_table_key_t& m)
{
    serializer_class<npl_ipv6_vrf_s_g_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_vrf_s_g_table_key_t&);



template<>
class serializer_class<npl_ipv6_vrf_s_g_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_vrf_s_g_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_vrf_s_g_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_vrf_s_g_table_value_t& m)
{
    serializer_class<npl_ipv6_vrf_s_g_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_vrf_s_g_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_vrf_s_g_table_value_t& m)
{
    serializer_class<npl_ipv6_vrf_s_g_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_vrf_s_g_table_value_t&);



template<>
class serializer_class<npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t& m) {
            archive(::cereal::make_nvp("vrf_s_g_hw_ip_mc_result", m.vrf_s_g_hw_ip_mc_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t& m) {
            archive(::cereal::make_nvp("vrf_s_g_hw_ip_mc_result", m.vrf_s_g_hw_ip_mc_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t& m)
{
    serializer_class<npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t& m)
{
    serializer_class<npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_ipv6_vrf_s_g_table_value_t::npl_ipv6_vrf_s_g_table_payloads_t&);



template<>
class serializer_class<npl_l2_dlp_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_dlp_table_key_t& m) {
        uint64_t m_l2_dlp_id_key_id = m.l2_dlp_id_key_id;
            archive(::cereal::make_nvp("l2_dlp_id_key_id", m_l2_dlp_id_key_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_dlp_table_key_t& m) {
        uint64_t m_l2_dlp_id_key_id;
            archive(::cereal::make_nvp("l2_dlp_id_key_id", m_l2_dlp_id_key_id));
        m.l2_dlp_id_key_id = m_l2_dlp_id_key_id;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_dlp_table_key_t& m)
{
    serializer_class<npl_l2_dlp_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_dlp_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_dlp_table_key_t& m)
{
    serializer_class<npl_l2_dlp_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_dlp_table_key_t&);



template<>
class serializer_class<npl_l2_dlp_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_dlp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_dlp_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_dlp_table_value_t& m)
{
    serializer_class<npl_l2_dlp_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_dlp_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_dlp_table_value_t& m)
{
    serializer_class<npl_l2_dlp_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_dlp_table_value_t&);



template<>
class serializer_class<npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_dlp_attributes", m.l2_dlp_attributes));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_dlp_attributes", m.l2_dlp_attributes));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t& m)
{
    serializer_class<npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t& m)
{
    serializer_class<npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_dlp_table_value_t::npl_l2_dlp_table_payloads_t&);



template<>
class serializer_class<npl_l2_lp_profile_filter_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lp_profile_filter_table_key_t& m) {
        uint64_t m_slp_profile = m.slp_profile;
        uint64_t m_lp_profile = m.lp_profile;
            archive(::cereal::make_nvp("slp_profile", m_slp_profile));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lp_profile_filter_table_key_t& m) {
        uint64_t m_slp_profile;
        uint64_t m_lp_profile;
            archive(::cereal::make_nvp("slp_profile", m_slp_profile));
            archive(::cereal::make_nvp("lp_profile", m_lp_profile));
        m.slp_profile = m_slp_profile;
        m.lp_profile = m_lp_profile;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lp_profile_filter_table_key_t& m)
{
    serializer_class<npl_l2_lp_profile_filter_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lp_profile_filter_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lp_profile_filter_table_key_t& m)
{
    serializer_class<npl_l2_lp_profile_filter_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lp_profile_filter_table_key_t&);



template<>
class serializer_class<npl_l2_lp_profile_filter_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lp_profile_filter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lp_profile_filter_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lp_profile_filter_table_value_t& m)
{
    serializer_class<npl_l2_lp_profile_filter_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lp_profile_filter_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lp_profile_filter_table_value_t& m)
{
    serializer_class<npl_l2_lp_profile_filter_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lp_profile_filter_table_value_t&);



template<>
class serializer_class<npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t& m) {
        uint64_t m_split_horizon = m.split_horizon;
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t& m) {
        uint64_t m_split_horizon;
            archive(::cereal::make_nvp("split_horizon", m_split_horizon));
        m.split_horizon = m_split_horizon;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t& m)
{
    serializer_class<npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t& m)
{
    serializer_class<npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lp_profile_filter_table_value_t::npl_l2_lp_profile_filter_table_payloads_t&);



template<>
class serializer_class<npl_l2_lpts_ctrl_fields_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ctrl_fields_static_table_key_t& m) {
        uint64_t m_mac_terminated = m.mac_terminated;
        uint64_t m_is_tagged = m.is_tagged;
        uint64_t m_is_svi = m.is_svi;
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ctrl_fields_static_table_key_t& m) {
        uint64_t m_mac_terminated;
        uint64_t m_is_tagged;
        uint64_t m_is_svi;
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
        m.mac_terminated = m_mac_terminated;
        m.is_tagged = m_is_tagged;
        m.is_svi = m_is_svi;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ctrl_fields_static_table_key_t& m)
{
    serializer_class<npl_l2_lpts_ctrl_fields_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ctrl_fields_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ctrl_fields_static_table_key_t& m)
{
    serializer_class<npl_l2_lpts_ctrl_fields_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ctrl_fields_static_table_key_t&);



template<>
class serializer_class<npl_l2_lpts_ctrl_fields_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ctrl_fields_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ctrl_fields_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ctrl_fields_static_table_value_t& m)
{
    serializer_class<npl_l2_lpts_ctrl_fields_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ctrl_fields_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ctrl_fields_static_table_value_t& m)
{
    serializer_class<npl_l2_lpts_ctrl_fields_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ctrl_fields_static_table_value_t&);



template<>
class serializer_class<npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t& m) {
        uint64_t m_ctrl_fields = m.ctrl_fields;
            archive(::cereal::make_nvp("ctrl_fields", m_ctrl_fields));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t& m) {
        uint64_t m_ctrl_fields;
            archive(::cereal::make_nvp("ctrl_fields", m_ctrl_fields));
        m.ctrl_fields = m_ctrl_fields;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ctrl_fields_static_table_value_t::npl_l2_lpts_ctrl_fields_static_table_payloads_t&);



template<>
class serializer_class<npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t& m) {
            archive(::cereal::make_nvp("l2_lpts_trap_vector", m.l2_lpts_trap_vector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t& m) {
            archive(::cereal::make_nvp("l2_lpts_trap_vector", m.l2_lpts_trap_vector));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv4_table_l2_lpts_result_payload_t&);



template<>
class serializer_class<npl_l2_lpts_ipv4_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv4_table_key_t& m) {
        uint64_t m_dip = m.dip;
        uint64_t m_ttl = m.ttl;
        uint64_t m_protocol = m.protocol;
        uint64_t m_npp_attributes = m.npp_attributes;
        uint64_t m_bd_attributes = m.bd_attributes;
        uint64_t m_l2_slp_attributes = m.l2_slp_attributes;
        uint64_t m_mac_terminated = m.mac_terminated;
        uint64_t m_is_tagged = m.is_tagged;
        uint64_t m_is_svi = m.is_svi;
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("ttl", m_ttl));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m_bd_attributes));
            archive(::cereal::make_nvp("l2_slp_attributes", m_l2_slp_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv4_table_key_t& m) {
        uint64_t m_dip;
        uint64_t m_ttl;
        uint64_t m_protocol;
        uint64_t m_npp_attributes;
        uint64_t m_bd_attributes;
        uint64_t m_l2_slp_attributes;
        uint64_t m_mac_terminated;
        uint64_t m_is_tagged;
        uint64_t m_is_svi;
            archive(::cereal::make_nvp("dip", m_dip));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("ttl", m_ttl));
            archive(::cereal::make_nvp("protocol", m_protocol));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m_bd_attributes));
            archive(::cereal::make_nvp("l2_slp_attributes", m_l2_slp_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
        m.dip = m_dip;
        m.ttl = m_ttl;
        m.protocol = m_protocol;
        m.npp_attributes = m_npp_attributes;
        m.bd_attributes = m_bd_attributes;
        m.l2_slp_attributes = m_l2_slp_attributes;
        m.mac_terminated = m_mac_terminated;
        m.is_tagged = m_is_tagged;
        m.is_svi = m_is_svi;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv4_table_key_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv4_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv4_table_key_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv4_table_key_t&);



template<>
class serializer_class<npl_l2_lpts_ipv4_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv4_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv4_table_value_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv4_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv4_table_value_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv4_table_value_t&);



template<>
class serializer_class<npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_result", m.l2_lpts_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_result", m.l2_lpts_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv4_table_value_t::npl_l2_lpts_ipv4_table_payloads_t&);



template<>
class serializer_class<npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t& m) {
            archive(::cereal::make_nvp("l2_lpts_trap_vector", m.l2_lpts_trap_vector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t& m) {
            archive(::cereal::make_nvp("l2_lpts_trap_vector", m.l2_lpts_trap_vector));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv6_table_l2_lpts_result_payload_t&);



template<>
class serializer_class<npl_l2_lpts_ipv6_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv6_table_key_t& m) {
        uint64_t m_dip_32_msb = m.dip_32_msb;
        uint64_t m_dip_32_lsb = m.dip_32_lsb;
        uint64_t m_next_header = m.next_header;
        uint64_t m_hop_limit = m.hop_limit;
        uint64_t m_npp_attributes = m.npp_attributes;
        uint64_t m_bd_attributes = m.bd_attributes;
        uint64_t m_l2_slp_attributes = m.l2_slp_attributes;
        uint64_t m_mac_terminated = m.mac_terminated;
        uint64_t m_is_tagged = m.is_tagged;
        uint64_t m_is_svi = m.is_svi;
            archive(::cereal::make_nvp("dip_32_msb", m_dip_32_msb));
            archive(::cereal::make_nvp("dip_32_lsb", m_dip_32_lsb));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("next_header", m_next_header));
            archive(::cereal::make_nvp("hop_limit", m_hop_limit));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m_bd_attributes));
            archive(::cereal::make_nvp("l2_slp_attributes", m_l2_slp_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv6_table_key_t& m) {
        uint64_t m_dip_32_msb;
        uint64_t m_dip_32_lsb;
        uint64_t m_next_header;
        uint64_t m_hop_limit;
        uint64_t m_npp_attributes;
        uint64_t m_bd_attributes;
        uint64_t m_l2_slp_attributes;
        uint64_t m_mac_terminated;
        uint64_t m_is_tagged;
        uint64_t m_is_svi;
            archive(::cereal::make_nvp("dip_32_msb", m_dip_32_msb));
            archive(::cereal::make_nvp("dip_32_lsb", m_dip_32_lsb));
            archive(::cereal::make_nvp("l4_ports", m.l4_ports));
            archive(::cereal::make_nvp("next_header", m_next_header));
            archive(::cereal::make_nvp("hop_limit", m_hop_limit));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m_bd_attributes));
            archive(::cereal::make_nvp("l2_slp_attributes", m_l2_slp_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
            archive(::cereal::make_nvp("ip_not_first_fragment", m.ip_not_first_fragment));
        m.dip_32_msb = m_dip_32_msb;
        m.dip_32_lsb = m_dip_32_lsb;
        m.next_header = m_next_header;
        m.hop_limit = m_hop_limit;
        m.npp_attributes = m_npp_attributes;
        m.bd_attributes = m_bd_attributes;
        m.l2_slp_attributes = m_l2_slp_attributes;
        m.mac_terminated = m_mac_terminated;
        m.is_tagged = m_is_tagged;
        m.is_svi = m_is_svi;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv6_table_key_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv6_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv6_table_key_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv6_table_key_t&);



template<>
class serializer_class<npl_l2_lpts_ipv6_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv6_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv6_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv6_table_value_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv6_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv6_table_value_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv6_table_value_t&);



template<>
class serializer_class<npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_result", m.l2_lpts_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_result", m.l2_lpts_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_ipv6_table_value_t::npl_l2_lpts_ipv6_table_payloads_t&);



template<>
class serializer_class<npl_l2_lpts_mac_table_l2_lpts_result_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_mac_table_l2_lpts_result_payload_t& m) {
            archive(::cereal::make_nvp("l2_lpts_trap_vector", m.l2_lpts_trap_vector));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_mac_table_l2_lpts_result_payload_t& m) {
            archive(::cereal::make_nvp("l2_lpts_trap_vector", m.l2_lpts_trap_vector));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_mac_table_l2_lpts_result_payload_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_l2_lpts_result_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_mac_table_l2_lpts_result_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_mac_table_l2_lpts_result_payload_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_l2_lpts_result_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_mac_table_l2_lpts_result_payload_t&);



template<>
class serializer_class<npl_l2_lpts_mac_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_mac_table_key_t& m) {
        uint64_t m_ether_type = m.ether_type;
        uint64_t m_npp_attributes = m.npp_attributes;
        uint64_t m_bd_attributes = m.bd_attributes;
        uint64_t m_l2_slp_attributes = m.l2_slp_attributes;
        uint64_t m_mac_terminated = m.mac_terminated;
        uint64_t m_is_tagged = m.is_tagged;
        uint64_t m_is_svi = m.is_svi;
            archive(::cereal::make_nvp("mac_da", m.mac_da));
            archive(::cereal::make_nvp("ether_type", m_ether_type));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m_bd_attributes));
            archive(::cereal::make_nvp("l2_slp_attributes", m_l2_slp_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_mac_table_key_t& m) {
        uint64_t m_ether_type;
        uint64_t m_npp_attributes;
        uint64_t m_bd_attributes;
        uint64_t m_l2_slp_attributes;
        uint64_t m_mac_terminated;
        uint64_t m_is_tagged;
        uint64_t m_is_svi;
            archive(::cereal::make_nvp("mac_da", m.mac_da));
            archive(::cereal::make_nvp("ether_type", m_ether_type));
            archive(::cereal::make_nvp("npp_attributes", m_npp_attributes));
            archive(::cereal::make_nvp("bd_attributes", m_bd_attributes));
            archive(::cereal::make_nvp("l2_slp_attributes", m_l2_slp_attributes));
            archive(::cereal::make_nvp("mac_lp_type", m.mac_lp_type));
            archive(::cereal::make_nvp("mac_terminated", m_mac_terminated));
            archive(::cereal::make_nvp("is_tagged", m_is_tagged));
            archive(::cereal::make_nvp("is_svi", m_is_svi));
        m.ether_type = m_ether_type;
        m.npp_attributes = m_npp_attributes;
        m.bd_attributes = m_bd_attributes;
        m.l2_slp_attributes = m_l2_slp_attributes;
        m.mac_terminated = m_mac_terminated;
        m.is_tagged = m_is_tagged;
        m.is_svi = m_is_svi;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_mac_table_key_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_mac_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_mac_table_key_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_mac_table_key_t&);



template<>
class serializer_class<npl_l2_lpts_mac_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_mac_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_mac_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_mac_table_value_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_mac_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_mac_table_value_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_mac_table_value_t&);



template<>
class serializer_class<npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_result", m.l2_lpts_result));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_result", m.l2_lpts_result));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_mac_table_value_t::npl_l2_lpts_mac_table_payloads_t&);



template<>
class serializer_class<npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_next_macro_static_table_l2_lpts_next_macro_action_payload_t&);



template<>
class serializer_class<npl_l2_lpts_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_next_macro_static_table_key_t& m) {
        uint64_t m_v4_mc = m.v4_mc;
        uint64_t m_v6_mc = m.v6_mc;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("ctrl_fields", m.ctrl_fields));
            archive(::cereal::make_nvp("v4_mc", m_v4_mc));
            archive(::cereal::make_nvp("v6_mc", m_v6_mc));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_next_macro_static_table_key_t& m) {
        uint64_t m_v4_mc;
        uint64_t m_v6_mc;
            archive(::cereal::make_nvp("type", m.type));
            archive(::cereal::make_nvp("ctrl_fields", m.ctrl_fields));
            archive(::cereal::make_nvp("v4_mc", m_v4_mc));
            archive(::cereal::make_nvp("v6_mc", m_v6_mc));
        m.v4_mc = m_v4_mc;
        m.v6_mc = m_v6_mc;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_l2_lpts_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_next_macro_action", m.l2_lpts_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_next_macro_action", m.l2_lpts_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_next_macro_static_table_value_t::npl_l2_lpts_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_l2_lpts_protocol_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_protocol_table_key_t& m) {
        uint64_t m_dst_udp_port = m.dst_udp_port;
        uint64_t m_mac_da_use_l2_lpts = m.mac_da_use_l2_lpts;
            archive(::cereal::make_nvp("next_protocol_type", m.next_protocol_type));
            archive(::cereal::make_nvp("next_header_1_type", m.next_header_1_type));
            archive(::cereal::make_nvp("dst_udp_port", m_dst_udp_port));
            archive(::cereal::make_nvp("mac_da_use_l2_lpts", m_mac_da_use_l2_lpts));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_protocol_table_key_t& m) {
        uint64_t m_dst_udp_port;
        uint64_t m_mac_da_use_l2_lpts;
            archive(::cereal::make_nvp("next_protocol_type", m.next_protocol_type));
            archive(::cereal::make_nvp("next_header_1_type", m.next_header_1_type));
            archive(::cereal::make_nvp("dst_udp_port", m_dst_udp_port));
            archive(::cereal::make_nvp("mac_da_use_l2_lpts", m_mac_da_use_l2_lpts));
        m.dst_udp_port = m_dst_udp_port;
        m.mac_da_use_l2_lpts = m_mac_da_use_l2_lpts;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_protocol_table_key_t& m)
{
    serializer_class<npl_l2_lpts_protocol_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_protocol_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_protocol_table_key_t& m)
{
    serializer_class<npl_l2_lpts_protocol_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_protocol_table_key_t&);



template<>
class serializer_class<npl_l2_lpts_protocol_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_protocol_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_protocol_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_protocol_table_value_t& m)
{
    serializer_class<npl_l2_lpts_protocol_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_protocol_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_protocol_table_value_t& m)
{
    serializer_class<npl_l2_lpts_protocol_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_protocol_table_value_t&);



template<>
class serializer_class<npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t& m) {
        uint64_t m_use_l2_lpts = m.use_l2_lpts;
            archive(::cereal::make_nvp("use_l2_lpts", m_use_l2_lpts));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t& m) {
        uint64_t m_use_l2_lpts;
            archive(::cereal::make_nvp("use_l2_lpts", m_use_l2_lpts));
        m.use_l2_lpts = m_use_l2_lpts;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_protocol_table_value_t::npl_l2_lpts_protocol_table_payloads_t&);



template<>
class serializer_class<npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t& m) {
        uint64_t m_skip_p2p_trap = m.skip_p2p_trap;
            archive(::cereal::make_nvp("skip_p2p_trap", m_skip_p2p_trap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t& m) {
        uint64_t m_skip_p2p_trap;
            archive(::cereal::make_nvp("skip_p2p_trap", m_skip_p2p_trap));
        m.skip_p2p_trap = m_skip_p2p_trap;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_skip_p2p_static_table_l2_lpts_set_skip_p2p_trap_payload_t&);



template<>
class serializer_class<npl_l2_lpts_skip_p2p_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_key_t& m) {
        uint64_t m_mac_lp_type_and_term = m.mac_lp_type_and_term;
        uint64_t m_is_p2p = m.is_p2p;
            archive(::cereal::make_nvp("mac_lp_type_and_term", m_mac_lp_type_and_term));
            archive(::cereal::make_nvp("is_p2p", m_is_p2p));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_key_t& m) {
        uint64_t m_mac_lp_type_and_term;
        uint64_t m_is_p2p;
            archive(::cereal::make_nvp("mac_lp_type_and_term", m_mac_lp_type_and_term));
            archive(::cereal::make_nvp("is_p2p", m_is_p2p));
        m.mac_lp_type_and_term = m_mac_lp_type_and_term;
        m.is_p2p = m_is_p2p;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_key_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_skip_p2p_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_key_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_skip_p2p_static_table_key_t&);



template<>
class serializer_class<npl_l2_lpts_skip_p2p_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_value_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_skip_p2p_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_value_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_skip_p2p_static_table_value_t&);



template<>
class serializer_class<npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_set_skip_p2p_trap", m.l2_lpts_set_skip_p2p_trap));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_lpts_set_skip_p2p_trap", m.l2_lpts_set_skip_p2p_trap));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t& m)
{
    serializer_class<npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_lpts_skip_p2p_static_table_value_t::npl_l2_lpts_skip_p2p_static_table_payloads_t&);



template<>
class serializer_class<npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_termination_next_macro_static_table_l2_termination_next_macro_action_payload_t&);



template<>
class serializer_class<npl_l2_termination_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_termination_next_macro_static_table_key_t& m) {
        uint64_t m_next_hdr_type = m.next_hdr_type;
            archive(::cereal::make_nvp("next_hdr_type", m_next_hdr_type));
            archive(::cereal::make_nvp("ipv4_ipv6_eth_init_rtf_stage", m.ipv4_ipv6_eth_init_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_termination_next_macro_static_table_key_t& m) {
        uint64_t m_next_hdr_type;
            archive(::cereal::make_nvp("next_hdr_type", m_next_hdr_type));
            archive(::cereal::make_nvp("ipv4_ipv6_eth_init_rtf_stage", m.ipv4_ipv6_eth_init_rtf_stage));
        m.next_hdr_type = m_next_hdr_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_termination_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_termination_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_termination_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_l2_termination_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_termination_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_termination_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_termination_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_termination_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_termination_next_macro_action", m.l2_termination_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_termination_next_macro_action", m.l2_termination_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_termination_next_macro_static_table_value_t::npl_l2_termination_next_macro_static_table_payloads_t&);



template<>
class serializer_class<npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t& m) {
        uint64_t m_pl_inc = m.pl_inc;
        uint64_t m_macro_id = m.macro_id;
            archive(::cereal::make_nvp("pl_inc", m_pl_inc));
            archive(::cereal::make_nvp("macro_id", m_macro_id));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t& m) {
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
save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_tunnel_term_next_macro_static_table_l2_termination_next_macro_action_payload_t&);



template<>
class serializer_class<npl_l2_tunnel_term_next_macro_static_table_key_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_key_t& m) {
        uint64_t m_overlay_or_pwe_lp_type = m.overlay_or_pwe_lp_type;
            archive(::cereal::make_nvp("overlay_or_pwe_lp_type", m_overlay_or_pwe_lp_type));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_key_t& m) {
        uint64_t m_overlay_or_pwe_lp_type;
            archive(::cereal::make_nvp("overlay_or_pwe_lp_type", m_overlay_or_pwe_lp_type));
            archive(::cereal::make_nvp("ipv4_ipv6_init_rtf_stage", m.ipv4_ipv6_init_rtf_stage));
        m.overlay_or_pwe_lp_type = m_overlay_or_pwe_lp_type;
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_key_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_tunnel_term_next_macro_static_table_key_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_key_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_key_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_tunnel_term_next_macro_static_table_key_t&);



template<>
class serializer_class<npl_l2_tunnel_term_next_macro_static_table_value_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_value_t& m) {
            archive(::cereal::make_nvp("action", m.action));
            archive(::cereal::make_nvp("payloads", m.payloads));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_value_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_tunnel_term_next_macro_static_table_value_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_value_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_value_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_tunnel_term_next_macro_static_table_value_t&);



template<>
class serializer_class<npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t> {
public:
    template <class Archive>
    static void
    do_save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_termination_next_macro_action", m.l2_termination_next_macro_action));
    }
    template <class Archive>
    static void
    do_load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t& m) {
            archive(::cereal::make_nvp("l2_termination_next_macro_action", m.l2_termination_next_macro_action));
    }
};
template <class Archive>
void
save(Archive& archive, const npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t>::do_save(archive, m);
}
template void save<cereal_output_archive_class>(cereal_output_archive_class&, const npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t&);

template <class Archive>
void
load(Archive& archive, npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t& m)
{
    serializer_class<npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t>::do_load(archive, m);
}
template void load<cereal_input_archive_class>(cereal_input_archive_class&, npl_l2_tunnel_term_next_macro_static_table_value_t::npl_l2_tunnel_term_next_macro_static_table_payloads_t&);



}

